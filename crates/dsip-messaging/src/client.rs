//! Client-side rules: voicemail offer, conversation convergence, receipts and activity, seq gaps.
//!
//! Spec: M§13.2 (when a caller may offer voicemail — [`voicemail_offer`]), M§7.2 and M§7.5
//! (duplicate direct conversations and successor groups converge on the lowest ULID —
//! [`select_direct`], [`check_successor`], [`select_successor`]), M§10.2–M§10.5 (identity-level
//! receipts, first-by-seq collapse, monotone read watermarks, privacy routing — [`Client`]),
//! M§11.2 (activity opt-in and refresh bound — [`Client`]), M§6.5 (holding handshake items across
//! a seq gap and re-joining on timeout — [`GapTracker`]), M§5.4 and M§8.5 (what a device keeps
//! durably across a restart — [`Resume`]).
//!
//! Impl: an unregistered `endpoint.*` rejection offers voicemail by category fallback, an
//! unregistered condition in any other category does not; delivered receipts are decided after a
//! whole sync batch; the gap timer starts when the first item is held; delivery state commits atomically with each
//! item and redelivery is recognised by seq (spec-gaps 41, 42, 44).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use dsip_core::registry::REASONS;
use dsip_core::ulid::Ulid;

use crate::checks::{accept, reject, ULID_TOLERANCE_S};

/// The profile a usable mailbox entry must advertise.
///
/// Spec: M§4.2.
pub const MESSAGING_PROFILE: &str = "messaging/1.0";

/// Choose a mailbox from what an identity advertises.
///
/// Spec: M§4.2, §8.1 — DID document entries are authoritative and hints serve only identities with
/// no document entry; an entry is usable when it satisfies the service schema and advertises
/// `messaging/1.0`; order is by `priority` (absent = 0), stable within a priority; the selection is
/// the first usable entry that accepts a connection, and devices sync every usable one.
pub fn select_mailbox(inp: &Value) -> Value {
    let list = |k: &str| -> Vec<Value> { inp[k].as_array().cloned().unwrap_or_default() };
    let (doc, hints) = (list("document_entries"), list("hint_entries"));
    let source = if !doc.is_empty() {
        json!("did-document")
    } else if !hints.is_empty() {
        json!("hint")
    } else {
        Value::Null
    };
    let entries = if doc.is_empty() { hints } else { doc }; // §8.1 rule 6: no falling back past a document
    let (mut usable, mut discarded): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    for e in entries {
        let advertises = e["profiles"].as_array().is_some_and(|p| p.iter().any(|x| x == MESSAGING_PROFILE));
        if crate::schemas::schema_ok("mailbox-service", &e) && advertises {
            usable.push(e);
        } else {
            discarded.push(e["uri"].clone());
        }
    }
    usable.sort_by_key(|e| e["priority"].as_i64().unwrap_or(0)); // stable
    let order: Vec<Value> = usable.iter().map(|e| e["mailbox"].clone()).collect();
    let reachable = inp["reachable"].as_array();
    let selected = order
        .iter()
        .find(|m| reachable.is_none_or(|r| r.contains(m)))
        .cloned()
        .unwrap_or(Value::Null);
    json!({"source": source, "selected": selected, "order": order, "sync_targets": order, "discarded": discarded})
}

/// Whether an established conversation's mailbox may move to `candidate`.
///
/// Spec: M§4.2, M§15.4 — never on a hint alone.
pub fn mailbox_switch(inp: &Value) -> Value {
    let (established, candidate) = (&inp["established"], &inp["candidate"]);
    if candidate["mailbox"] == established["mailbox"] {
        json!({"switch": false, "reason": "unchanged"})
    } else if candidate["source"] != "did-document" {
        json!({"switch": false, "reason": "hint-sourced"})
    } else {
        json!({"switch": true, "reason": "did-document"})
    }
}

/// Rejection reasons after which a caller may offer voicemail.
///
/// Spec: M§13.2.
pub const VOICEMAIL_REJECT_REASONS: &[&str] = &["user.no-answer", "user.declined", "endpoint.busy", "endpoint.unavailable"];
/// Member-identity count above which delivered receipts are not sent.
///
/// Spec: M§10.2.
pub const DELIVERED_MAX_GROUP: i64 = 32;
/// Maximum targets in one receipt.
///
/// Spec: M§10.2.
pub const RECEIPT_MAX_TARGETS: usize = 256;
/// Minimum interval between read watermarks for one conversation, seconds.
///
/// Spec: M§10.3.
pub const READ_MIN_INTERVAL_S: i64 = 5;
/// Minimum interval between `active` refreshes of one activity, seconds.
///
/// Spec: M§11.2.
pub const ACTIVITY_REFRESH_S: i64 = 5;
/// How long a held item may wait for a seq gap to fill before the device re-joins, seconds.
///
/// Spec: M§6.5 (`gap_timeout`, RECOMMENDED 300 s).
pub const GAP_TIMEOUT_S: i64 = 300;

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Whether the caller's client may offer to record a voicemail after an attempt outcome.
///
/// Spec: M§13.2.
pub fn voicemail_offer(inp: &Value) -> Value {
    let vm = &inp["voicemail"];
    if !vm.is_object() || !inp["can_send"].as_bool().unwrap_or(false) {
        return json!({"offer": false});
    }
    let reason = inp["outcome"]["reason"].as_str().unwrap_or("");
    let ok = match inp["outcome"]["type"].as_str() {
        Some("reject") => {
            let registered = REASONS.iter().any(|(t, _)| *t == reason);
            VOICEMAIL_REJECT_REASONS.contains(&reason)
                || (!registered && reason.split('.').next() == Some("endpoint"))
        }
        Some("cancel") => reason == "session.timeout",
        _ => false,
    };
    if !ok {
        return json!({"offer": false});
    }
    match vm.get("max_duration_s") {
        Some(d) => json!({"offer": true, "max_duration_s": d}),
        None => json!({"offer": true}),
    }
}

/// Converge duplicate direct conversations on the lowest conversation ULID.
///
/// Spec: M§7.2 — candidates failing the §20.6 ULID/`issued_at` consistency check cannot win.
pub fn select_direct(candidates: &[Value]) -> Value {
    let mut kept: Vec<String> = vec![];
    let mut discarded: Vec<String> = vec![];
    for c in candidates {
        let conv = s(&c["conversation"]);
        let consistent = Ulid::parse(&conv)
            .is_some_and(|u| (u.timestamp_s() - c["issued_at"].as_i64().unwrap_or(0)).abs() <= ULID_TOLERANCE_S);
        if consistent { kept.push(conv) } else { discarded.push(conv) }
    }
    json!({"winner": kept.into_iter().min(), "discarded": discarded})
}

/// Accept a successor group only from a predecessor member re-adding predecessor members.
///
/// Spec: M§7.5 — otherwise the group is a new conversation subject to first contact.
pub fn check_successor(inp: &Value) -> Value {
    let set = |k: &str| -> BTreeSet<String> { inp[k].as_array().into_iter().flatten().map(s).collect() };
    let pred = set("predecessor_roster");
    if pred.contains(&s(&inp["creator"])) && set("roster").is_subset(&pred) {
        accept()
    } else {
        reject("successor-invalid", None)
    }
}

/// Converge concurrent successor groups on the lowest `group_id`, compared as the decoded ULID.
///
/// Spec: M§7.5, M§6.3 (`group_id` is the UTF-8 bytes of a ULID; the wire form is base64url).
pub fn select_successor(candidates: &[Value]) -> Value {
    let mut kept: Vec<(String, String)> = vec![];
    let mut discarded: Vec<String> = vec![];
    for c in candidates {
        let g = s(c);
        let ulid = dsip_core::b64::decode(&g)
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|u| Ulid::parse(u).is_some());
        match ulid {
            Some(u) => kept.push((u, g)),
            None => discarded.push(g),
        }
    }
    json!({"winner": kept.into_iter().min().map(|(_, g)| g), "discarded": discarded})
}

struct Content {
    sender: String,
    seq: i64,
    kind: String,
}

/// One device's view of one conversation, and what it sends.
///
/// Spec: M§10.2–M§10.5, M§11.2, M§8.5.
pub struct Client {
    now: i64,
    me: String,
    policy: Value,
    members: i64,
    content: BTreeMap<String, Content>,
    timeline: Vec<String>,
    delivered: BTreeMap<String, BTreeMap<String, Value>>,
    played: BTreeMap<String, BTreeMap<String, Value>>,
    read_seq: BTreeMap<String, i64>,
    read_through: BTreeMap<String, String>,
    sent_delivered: BTreeSet<String>,
    sent_played: BTreeSet<String>,
    last_read_sent: Option<i64>,
    pending_read: bool,
    last_activity: BTreeMap<String, i64>,
}

impl Client {
    /// A client from a vector `context`: `now`, `me`, `policy`, `member_identities`.
    pub fn new(ctx: &Value) -> Client {
        Client {
            now: ctx["now"].as_i64().unwrap_or(0),
            me: s(&ctx["me"]),
            policy: ctx["policy"].clone(),
            members: ctx["member_identities"].as_i64().unwrap_or(2),
            content: BTreeMap::new(),
            timeline: vec![],
            delivered: BTreeMap::new(),
            played: BTreeMap::new(),
            read_seq: BTreeMap::new(),
            read_through: BTreeMap::new(),
            sent_delivered: BTreeSet::new(),
            sent_played: BTreeSet::new(),
            last_read_sent: None,
            pending_read: false,
            last_activity: BTreeMap::new(),
        }
    }

    fn policy(&self, k: &str) -> bool {
        self.policy[k].as_bool().unwrap_or(false)
    }

    /// Apply one event (`sync`, `read`, `play`, `activity`, `advance`) and return what the device sends.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|m| m.iter().next()) else { return vec![] };
        match name.as_str() {
            "sync" => self.sync(e),
            "read" => self.read(e),
            "play" => self.play(e),
            "activity" => self.activity(e),
            "advance" => self.advance(e.as_i64().unwrap_or(0)),
            _ => vec![],
        }
    }

    fn sync(&mut self, e: &Value) -> Vec<Value> {
        let mut fresh = vec![];
        for it in e["items"].as_array().into_iter().flatten() {
            let o = &it["object"];
            match o["object"].as_str() {
                Some("content") => {
                    let id = s(&o["id"]);
                    if self.content.contains_key(&id) {
                        continue; // M§8.5: duplicates collapse silently
                    }
                    let seq = it["seq"].as_i64().unwrap_or(0);
                    self.content.insert(id.clone(), Content { sender: s(&o["sender"]), seq, kind: s(&o["kind"]) });
                    self.timeline.push(id.clone());
                    fresh.push(id);
                }
                Some("receipt") => self.receipt(o),
                _ => {}
            }
        }
        let mut out = vec![];
        if self.policy("delivered") && self.members <= DELIVERED_MAX_GROUP {
            // M§10.2: decided after the whole batch, so a sibling's receipt in it suppresses ours
            let targets: Vec<String> = fresh
                .into_iter()
                .filter(|i| {
                    self.content[i].sender != self.me
                        && !self.delivered.get(i).is_some_and(|m| m.contains_key(&self.me))
                        && !self.sent_delivered.contains(i)
                })
                .collect();
            for chunk in targets.chunks(RECEIPT_MAX_TARGETS) {
                out.push(json!({"send": {"to": "conversation", "receipt": "delivered", "targets": chunk}}));
            }
            self.sent_delivered.extend(targets);
        }
        out
    }

    fn receipt(&mut self, o: &Value) {
        let who = s(&o["sender"]);
        match o["kind"].as_str() {
            Some(kind @ ("delivered" | "played")) => {
                for t in o["targets"].as_array().into_iter().flatten().map(s) {
                    let Some(c) = self.content.get(&t) else { continue };
                    if c.sender == who || (kind == "played" && !matches!(c.kind.as_str(), "audio" | "video")) {
                        continue;
                    }
                    let book = if kind == "delivered" { &mut self.delivered } else { &mut self.played };
                    book.entry(t).or_default().entry(who.clone()).or_insert_with(|| o["sent_at"].clone());
                }
            }
            Some("read") => {
                let through = s(&o["through"]);
                if let Some(c) = self.content.get(&through) {
                    if c.seq > self.read_seq.get(&who).copied().unwrap_or(0) {
                        // M§10.3: monotone
                        self.read_seq.insert(who.clone(), c.seq);
                        self.read_through.insert(who, through);
                    }
                }
            }
            _ => {}
        }
    }

    fn read_send(&mut self) -> Vec<Value> {
        self.last_read_sent = Some(self.now);
        self.pending_read = false;
        let to = if self.policy("read") { "conversation" } else { "personal" }; // M§10.5
        vec![json!({"send": {"to": to, "receipt": "read", "through": self.read_through[&self.me]}})]
    }

    fn read(&mut self, e: &Value) -> Vec<Value> {
        let through = s(&e["through"]);
        let Some(seq) = self.content.get(&through).map(|c| c.seq) else { return vec![] };
        if seq <= self.read_seq.get(&self.me).copied().unwrap_or(0) {
            return vec![];
        }
        self.read_seq.insert(self.me.clone(), seq);
        self.read_through.insert(self.me.clone(), through);
        if self.last_read_sent.is_some_and(|t| self.now - t < READ_MIN_INTERVAL_S) {
            self.pending_read = true;
            return vec![];
        }
        self.read_send()
    }

    fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        if self.pending_read && self.last_read_sent.is_some_and(|t| self.now - t >= READ_MIN_INTERVAL_S) {
            return self.read_send();
        }
        vec![]
    }

    fn play(&mut self, e: &Value) -> Vec<Value> {
        let id = s(&e["id"]);
        let media = self.content.get(&id).is_some_and(|c| matches!(c.kind.as_str(), "audio" | "video"));
        let already = self.played.get(&id).is_some_and(|m| m.contains_key(&self.me)) || self.sent_played.contains(&id);
        if !media || !self.policy("played") || already {
            return vec![];
        }
        self.sent_played.insert(id.clone());
        vec![json!({"send": {"to": "conversation", "receipt": "played", "targets": [id]}})]
    }

    fn activity(&mut self, e: &Value) -> Vec<Value> {
        if !self.policy("activity") {
            return vec![]; // M§11.2: same opt-in as read receipts
        }
        let a = s(&e["activity"]);
        let state = s(&e["state"]);
        if state == "active" {
            if self.last_activity.get(&a).is_some_and(|t| self.now - t < ACTIVITY_REFRESH_S) {
                return vec![];
            }
            self.last_activity.insert(a.clone(), self.now);
        } else {
            self.last_activity.remove(&a);
        }
        vec![json!({"send": {"to": "conversation", "activity": a, "state": state}})]
    }

    /// Snapshot compared by the vectors: timeline, collapsed receipts, read watermarks.
    pub fn snapshot(&self) -> Value {
        let book = |b: &BTreeMap<String, BTreeMap<String, Value>>| -> Value {
            let m: serde_json::Map<String, Value> =
                b.iter().filter(|(_, m)| !m.is_empty()).map(|(i, m)| (i.clone(), json!(m))).collect();
            Value::Object(m)
        };
        json!({"timeline": self.timeline, "delivered": book(&self.delivered), "played": book(&self.played),
               "read_through": self.read_through})
    }
}

/// Seq-gap handling for one group on one device.
///
/// Spec: M§6.5 — handshake items beyond a gap, and anything after a held item, wait for the gap;
/// a gap not filled within [`GAP_TIMEOUT_S`] of the first held item triggers a re-join (M§6.8).
pub struct GapTracker {
    now: i64,
    contiguous: i64,
    seen: BTreeSet<i64>,
    held: Vec<i64>,
    gap_since: Option<i64>,
}

impl GapTracker {
    /// A tracker from a vector `context`: `now`, `contiguous`.
    pub fn new(ctx: &Value) -> GapTracker {
        GapTracker {
            now: ctx["now"].as_i64().unwrap_or(0),
            contiguous: ctx["contiguous"].as_i64().unwrap_or(0),
            seen: BTreeSet::new(),
            held: vec![],
            gap_since: None,
        }
    }

    /// Apply one event (`item`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(n) = ev.get("advance").and_then(Value::as_i64) {
            self.now += n;
            if !self.held.is_empty() && self.gap_since.is_some_and(|t| self.now - t >= GAP_TIMEOUT_S) {
                let out = vec![json!({"rejoin": {"held": self.held}})];
                self.contiguous = self.held.iter().chain(self.seen.iter()).copied().max().unwrap_or(self.contiguous);
                self.seen.clear();
                self.held.clear();
                self.gap_since = None;
                return out;
            }
            return vec![];
        }
        let it = &ev["item"];
        let seq = it["seq"].as_i64().unwrap_or(0);
        if seq <= self.contiguous || self.seen.contains(&seq) {
            return vec![json!({"duplicate": seq})];
        }
        self.seen.insert(seq);
        let mut out = vec![];
        let blocked = it["class"] == "handshake" && seq > self.contiguous + 1;
        if blocked || self.held.first().is_some_and(|h| seq > *h) {
            self.held.push(seq);
            self.held.sort_unstable();
            self.gap_since.get_or_insert(self.now);
            out.push(json!({"hold": seq}));
        } else {
            out.push(json!({"process": seq}));
        }
        while self.seen.remove(&(self.contiguous + 1)) {
            self.contiguous += 1;
        }
        while self.held.first().is_some_and(|h| *h <= self.contiguous) {
            out.push(json!({"process": self.held.remove(0)}));
        }
        if self.held.is_empty() {
            self.gap_since = None;
        }
        out
    }

    /// Snapshot compared by the vectors.
    pub fn snapshot(&self) -> Value {
        json!({"contiguous": self.contiguous, "held": self.held})
    }
}

/// The deposit classes the hub sequences.
///
/// Spec: M§6.5 rule 4.
pub const SEQUENCED_CLASSES: [&str; 2] = ["handshake", "application"];

/// A device's durable delivery state: the ack cursor, per-group seq positions and joined groups.
///
/// Spec: M§5.4 — `ack_through` covers only items the device has durably processed; M§8.5 — duplicates
/// collapse silently; M§5.4 — on `mailbox.cursor-invalid` the device re-syncs from `null`.
///
/// Impl (spec-gap 44): each item is processed and committed together with this state, or not at all,
/// so a crash rolls an item back with its MLS state and it is redelivered. A redelivered sequenced
/// item is recognised by its hub `seq` ([`GapTracker`]'s contiguous position plus the seqs seen past
/// a gap), never by decrypting it, since MLS consumed its secret the first time; a welcome is a
/// duplicate for a group already joined; unsequenced `group-info` is state and is processed again.
/// Holding across a gap is [`GapTracker`]'s job and is not modelled here.
#[derive(Debug, Clone, Default)]
pub struct Resume {
    cursor: Option<String>,
    groups: BTreeMap<String, (i64, BTreeSet<i64>)>,
    joined: BTreeSet<String>,
}

impl Resume {
    /// Durable state from a vector `context` or a previous [`Resume::snapshot`]: `cursor`, `groups`, `joined`.
    pub fn new(ctx: &Value) -> Resume {
        let groups = ctx["groups"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(g, p)| {
                let seen = p["seen"].as_array().into_iter().flatten().filter_map(Value::as_i64).collect();
                (g.clone(), (p["contiguous"].as_i64().unwrap_or(0), seen))
            })
            .collect();
        Resume {
            cursor: ctx["cursor"].as_str().map(String::from),
            groups,
            joined: ctx["joined"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
        }
    }

    /// Whether an `items[]` element was already durably processed.
    pub fn is_duplicate(&self, item: &Value) -> bool {
        let class = item["class"].as_str().unwrap_or("");
        let group = item["group"].as_str().unwrap_or("");
        if SEQUENCED_CLASSES.contains(&class) {
            let seq = item["seq"].as_i64().unwrap_or(0);
            return self.groups.get(group).is_some_and(|(contiguous, seen)| seq <= *contiguous || seen.contains(&seq));
        }
        class == "welcome" && self.joined.contains(group)
    }

    /// Record an item as committed; `duplicate` items only advance the cursor, so they are acknowledged.
    pub fn commit(&mut self, item: &Value, duplicate: bool) {
        self.cursor = item["cursor"].as_str().map(String::from);
        if duplicate {
            return;
        }
        let class = item["class"].as_str().unwrap_or("");
        let group = item["group"].as_str().unwrap_or("").to_string();
        if SEQUENCED_CLASSES.contains(&class) {
            let (contiguous, seen) = self.groups.entry(group).or_default();
            seen.insert(item["seq"].as_i64().unwrap_or(0));
            while seen.remove(&(*contiguous + 1)) {
                *contiguous += 1;
            }
        } else if class == "welcome" {
            self.joined.insert(group);
        }
    }

    /// Forget the cursor after `mailbox.cursor-invalid`; seq positions and joined groups are kept.
    pub fn cursor_invalid(&mut self) {
        self.cursor = None;
    }

    /// The `sync` fields this state allows: `since`, and `ack_through` never ahead of the last commit.
    pub fn sync_fields(&self) -> Value {
        match &self.cursor {
            Some(c) => json!({"since": c, "ack_through": c}),
            None => json!({"since": null}),
        }
    }

    /// Apply one trace event (`items` with optional `crash_at`, `sync`, `restart`, `cursor_invalid`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(e) = ev.get("items") {
            let mut out = vec![];
            for item in e["items"].as_array().into_iter().flatten() {
                let cursor = item["cursor"].clone();
                if e.get("crash_at") == Some(&cursor) {
                    out.push(json!({"crash": cursor})); // processed in memory, never committed
                    break;
                }
                let dup = self.is_duplicate(item);
                out.push(json!({ if dup { "duplicate" } else { "process" }: cursor }));
                self.commit(item, dup);
            }
            return out;
        }
        if ev.get("restart").is_some() {
            *self = Resume::new(&self.snapshot()); // only durable state survives
        } else if ev.get("cursor_invalid").is_some() {
            self.cursor_invalid();
        }
        vec![json!({"sync": self.sync_fields()})]
    }

    /// The durable state, as the vectors compare it and as a device stores it.
    pub fn snapshot(&self) -> Value {
        let groups: serde_json::Map<String, Value> = self
            .groups
            .iter()
            .map(|(g, (contiguous, seen))| (g.clone(), json!({"contiguous": contiguous, "seen": seen})))
            .collect();
        json!({"cursor": self.cursor, "groups": groups, "joined": self.joined})
    }
}
