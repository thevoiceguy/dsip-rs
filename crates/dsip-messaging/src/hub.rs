//! The hub: per-group ordering authority and fan-out.
//!
//! Spec: M§6.5 (authenticate depositors, first valid commit per epoch wins, application messages
//! for the current or previous epoch, per-group `seq`, per-mailbox fan-out in `seq` order with
//! retry before later items), M§6.8 (external joins), M§7.3 (membership rules), M§9.3
//! (idempotent re-deposit), M§11.2 (ephemeral activity is forwarded, never sequenced), M§7.4 (a commit with `moves_to`
//! is the group's last here: later deposits are refused `mailbox.unknown-group` while the queues drain; spec-gap 60),
//! M§4.4 (`mls_retention_s` bounds what is kept for a member that acknowledges nothing; spec-gap 119), and a group that
//! comes back to a hub it left (spec-gap 128).
//!
//! Impl: MLS is abstracted — a deposit event carries the epoch, a digest of the MLS bytes, and for
//! a commit its adds, removes, validity and whether it is external. Refusals without a
//! profile-specific token use `policy.blocked` (spec-gap 34 records the hub model).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checks::{check_external_join, check_roster_change};

/// Hub state for one group.
#[derive(Serialize, Deserialize)]
pub struct Hub {
    now: i64,
    kind: String,
    owner: Option<String>,
    epoch: i64,
    next_seq: i64,
    roster: BTreeMap<String, BTreeSet<String>>,
    digests: HashMap<String, i64>,
    seq_class: HashMap<i64, String>,
    pending: BTreeMap<String, Vec<i64>>,
    group_info: bool,
    #[serde(default)]
    moved_to: Option<String>,
    /// Unacknowledged welcomes per added identity, by the seq of the commit that added it (spec-gap 66).
    #[serde(default)]
    welcomes: BTreeMap<String, Vec<i64>>,
    /// Identities a commit brought in whose welcome is not yet acknowledged: their mailbox has no registration for
    /// the group and would refuse a sequenced item (M§6.6), so their queue is held (spec-gap 66). A member that
    /// gained a device is not among them (spec-gap 87).
    #[serde(default)]
    unregistered: BTreeSet<String>,
    /// How long a member identity may acknowledge nothing before its queues are dropped, seconds (spec-gap 119).
    #[serde(default = "default_retention")]
    retention: i64,
    /// Per member identity with something queued: when its queues last went from empty to not, or saw a head
    /// acknowledged (spec-gap 119).
    #[serde(default)]
    waiting: BTreeMap<String, i64>,
}

/// The retention bound a hub uses when its context names none.
///
/// Spec: M§4.4 (`mls_retention_s`, RECOMMENDED 2,592,000 s), M§6.5 (it bounds a hub's queues; v0.13, spec-gap 119).
pub const MLS_RETENTION_S: i64 = 2_592_000;

fn default_retention() -> i64 {
    MLS_RETENTION_S
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

impl Hub {
    /// A hub from a vector `context`: `now`, `kind`, `owner`, `epoch`, `next_seq`, `roster`.
    pub fn new(ctx: &Value) -> Hub {
        let roster = ctx["roster"]
            .as_object()
            .map(|m| m.iter().map(|(i, d)| (i.clone(), d.as_array().into_iter().flatten().map(s).collect())).collect())
            .unwrap_or_default();
        Hub {
            now: ctx["now"].as_i64().unwrap_or(0),
            kind: ctx["kind"].as_str().unwrap_or("direct").to_string(),
            owner: ctx["owner"].as_str().map(String::from),
            epoch: ctx["epoch"].as_i64().unwrap_or(0),
            next_seq: ctx["next_seq"].as_i64().unwrap_or(1),
            roster,
            digests: HashMap::new(),
            seq_class: HashMap::new(),
            pending: BTreeMap::new(),
            group_info: false,
            moved_to: None,
            welcomes: BTreeMap::new(),
            unregistered: BTreeSet::new(),
            retention: ctx["mls_retention_s"].as_i64().unwrap_or(MLS_RETENTION_S),
            waiting: BTreeMap::new(),
        }
    }

    /// The hub's clock, seconds.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Time passes: a member identity whose clock has reached the retention bound has every queue it has here dropped,
    /// welcome included, and its welcome hold lifted; it stays in the roster.
    ///
    /// Spec: M§6.5 "How long a queue is kept" (v0.13, spec-gap 119): the clock runs while anything is queued for the
    /// identity and restarts at every acknowledgement of a head; a returning device re-joins by external commit (M§6.8).
    fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        let due: Vec<String> = self.waiting.iter().filter(|(_, t)| self.now - **t >= self.retention).map(|(i, _)| i.clone()).collect();
        let mut out = vec![];
        for i in due {
            let pending = self.pending.remove(&i).unwrap_or_default();
            let welcomes = self.welcomes.remove(&i).unwrap_or_default();
            self.unregistered.remove(&i);
            self.waiting.remove(&i);
            out.push(json!({"dropped": {"identity": i, "pending": pending, "welcomes": welcomes}}));
        }
        out
    }

    fn start_clock(&mut self, ident: &str) {
        let now = self.now;
        self.waiting.entry(ident.to_string()).or_insert(now);
    }

    /// Apply one event (`deposit`, `ack`, `advance`, `restart`) and return what the hub emits.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(n) = ev.get("advance").and_then(Value::as_i64) {
            return self.advance(n);
        }
        if let Some(a) = ev.get("ack") {
            return self.ack(&s(&a["identity"]), a["seq"].as_i64().unwrap_or(0), a["class"].as_str().unwrap_or(""));
        }
        if ev.get("restart").is_some() {
            if let Some(h) = Hub::from_full_state(&self.full_state()) {
                *self = h;
            }
            return self.resend_heads();
        }
        self.deposit(&ev["deposit"])
    }

    /// Everything a hub keeps across a restart: epoch, roster, sequence counter, digests, fan-out queues.
    ///
    /// Spec: M§6.5, M§9.3. Impl (spec-gap 59): all hub state is durable; a restart loses nothing.
    pub fn full_state(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// A hub restored from [`Hub::full_state`]; `None` if the value is not one.
    ///
    /// An identity with something queued but no clock, as in a state saved before the retention clock existed (or
    /// re-saved by a hub that loaded one), gets a clock started at the hub's clock; otherwise a queue held then would
    /// never be dropped (spec-gap 119). A state this hub saved always has the clocks already.
    pub fn from_full_state(v: &Value) -> Option<Hub> {
        let mut h: Hub = serde_json::from_value(v.clone()).ok()?;
        let queued: Vec<String> =
            h.pending.iter().chain(h.welcomes.iter()).filter(|(_, q)| !q.is_empty()).map(|(i, _)| i.clone()).collect();
        for i in queued {
            h.start_clock(&i);
        }
        Some(h)
    }

    /// The head of every unacknowledged fan-out queue, to be sent again.
    ///
    /// Spec: M§6.5 rule 5 (retry before later items). Impl (spec-gap 59): a restarted hub, or one whose retry timer
    /// fires, re-sends each queue's head; the member mailbox acknowledges a redelivery as a duplicate.
    pub fn resend_heads(&self) -> Vec<Value> {
        let items = self
            .pending
            .iter()
            .filter(|(i, _)| !self.unregistered.contains(*i))
            .filter_map(|(i, q)| q.first().map(|seq| json!({"fanout": {"to": i, "seq": seq, "class": self.seq_class[seq]}})));
        let welcomes = self
            .welcomes
            .iter()
            .filter_map(|(i, q)| q.first().map(|seq| json!({"fanout": {"to": i, "seq": seq, "class": "welcome"}})));
        items.chain(welcomes).collect()
    }

    fn error(d: &Value, reason: &str) -> Vec<Value> {
        vec![json!({"error": {"to": d["device"], "in_reply_to": d["id"], "reason": reason}})]
    }

    fn deposit(&mut self, d: &Value) -> Vec<Value> {
        let class = s(&d["class"]);
        let ident = s(&d["identity"]);
        if self.moved_to.is_some() && class == "group-info" && d.get("handover_seq").is_some() {
            return self.returned(d);
        }
        if self.moved_to.is_some() {
            // M§7.4: after ordering the commit that moved the group, the old hub refuses further deposits for it
            return Self::error(d, "mailbox.unknown-group");
        }
        if !matches!(class.as_str(), "handshake" | "application" | "ephemeral" | "group-info") {
            return Self::error(d, "mailbox.unsupported-class");
        }
        if class == "group-info" {
            // M§6.5 rule 6 / M§6.8: the hub keeps the latest GroupInfo so a returning device can
            // external-join, and forwards it to the members' mailboxes. Never sequenced.
            if !self.roster.contains_key(&ident) {
                return Self::error(d, "policy.blocked");
            }
            self.group_info = true;
            let mut out = vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"]}})];
            out.extend(self.roster.keys().map(|i| json!({"fanout": {"to": i, "class": "group-info"}})));
            return out;
        }
        if class == "ephemeral" {
            // M§11.2: never sequenced or stored; dropped once expired
            if d["expires_at"].as_i64().unwrap_or(0) < self.now {
                return vec![];
            }
            if !self.roster.contains_key(&ident) {
                return Self::error(d, "policy.blocked");
            }
            return self
                .roster
                .keys()
                .filter(|i| **i != ident)
                .map(|i| json!({"forward": {"to": i, "class": "ephemeral"}}))
                .collect();
        }
        let digest = s(&d["digest"]);
        if let Some(seq) = self.digests.get(&digest) {
            // M§9.3: same MLS bytes → original seq, no second fan-out
            return vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": seq, "duplicate": true}})];
        }
        let commit = d.get("commit");
        let external = commit.is_some_and(|c| c["external"].as_bool().unwrap_or(false));
        if external {
            // M§6.8 (spec-gap 62): the same check every member makes
            let c = commit.cloned().unwrap_or(Value::Null);
            let v = check_external_join(&json!({"kind": self.kind, "owner": self.owner, "roster": self.roster.keys().collect::<Vec<_>>(),
                "joiner": {"identity": ident, "device": d["device"]}, "adds": c["adds"], "removes": c["removes"]}));
            if v["verdict"] != "accept" {
                return Self::error(d, "policy.blocked");
            }
        } else if !self.roster.contains_key(&ident) {
            return Self::error(d, "policy.blocked"); // M§6.5 rule 1
        }
        let e = d["epoch"].as_i64().unwrap_or(i64::MIN);
        let targets: Vec<String> = self.roster.keys().cloned().collect();
        if class == "application" {
            if e != self.epoch && e != self.epoch - 1 {
                return Self::error(d, "mailbox.stale-epoch"); // M§6.5 rule 3
            }
            return self.sequence(d, &targets);
        }
        if e != self.epoch {
            // M§6.5 rule 2
            let conflict = commit.is_some() && e == self.epoch - 1;
            return Self::error(d, if conflict { "mailbox.commit-conflict" } else { "mailbox.stale-epoch" });
        }
        let Some(commit) = commit else {
            return self.sequence(d, &targets); // standalone proposal: sequenced, epoch unchanged
        };
        if !commit["valid"].as_bool().unwrap_or(true) {
            return Self::error(d, "policy.blocked");
        }
        let roster: Vec<Value> = self.roster.iter().flat_map(|(i, devs)| devs.iter().map(move |dev| json!({"identity": i, "device": dev}))).collect();
        let v = check_roster_change(&json!({"committer": ident, "roster": roster, "adds": commit["adds"], "removes": commit["removes"]}));
        if v["verdict"] != "accept" {
            return Self::error(d, "policy.blocked"); // M§7.3: the rule every member checks too (spec-gap 126)
        }
        let adds: Vec<&Value> = commit["adds"].as_array().into_iter().flatten().collect();
        let removes: Vec<&Value> = commit["removes"].as_array().into_iter().flatten().collect();
        let mut out = self.sequence(d, &targets);
        let before = self.roster.clone();
        for r in &removes {
            let x = s(&r["identity"]);
            if let Some(devs) = self.roster.get_mut(&x) {
                devs.remove(&s(&r["device"]));
                if devs.is_empty() {
                    self.roster.remove(&x);
                }
            }
        }
        for a in &adds {
            self.roster.entry(s(&a["identity"])).or_default().insert(s(&a["device"]));
        }
        self.epoch += 1;
        if let Some(to) = commit["moves_to"].as_str() {
            self.moved_to = Some(to.to_string()); // M§7.4: everything after this commit goes to the new hub
        }
        if !external {
            // an external joiner joined by its own commit; welcomes go only to identities others added — every identity
            // that gained a device, including a member adding its own new device (spec-gap 50)
            let gained: BTreeSet<String> = adds
                .iter()
                .filter(|a| !before.get(&s(&a["identity"])).is_some_and(|devs| devs.contains(&s(&a["device"]))))
                .map(|a| s(&a["identity"]))
                .collect();
            // spec-gap 87: only an identity the commit brought in has no registration to receive sequenced items with
            self.unregistered.extend(gained.iter().filter(|i| !before.contains_key(*i)).cloned());
            let seq = self.digests[&s(&d["digest"])];
            for i in gained {
                self.start_clock(&i); // spec-gap 119
                // spec-gap 66: a welcome is queued and retried like any fan-out, in its own queue — a member adding its
                // own device needs both the commit (for its other devices) and the welcome (for the new one)
                let q = self.welcomes.entry(i.clone()).or_default();
                q.push(seq);
                if q.len() == 1 {
                    out.push(json!({"fanout": {"to": i, "seq": seq, "class": "welcome"}}));
                }
            }
        }
        out
    }

    /// The group comes back to this hub, which it left: `view` is the epoch and roster of the GroupInfo the daemon read
    /// (it names this hub); numbering goes on from `handover_seq` + 1, never reusing a seq this hub gave, and what was
    /// ordered before the group left keeps draining.
    ///
    /// Spec: M§7.4, M§12.2. Impl (spec-gap 128): the spec has the old hub refuse every later deposit and never says a
    /// group may come back; a member's handover `group-info` that names this hub again returns it.
    fn returned(&mut self, d: &Value) -> Vec<Value> {
        let roster: BTreeMap<String, BTreeSet<String>> = d["view"]["roster"].as_object().into_iter().flatten()
            .map(|(i, devs)| (i.clone(), devs.as_array().into_iter().flatten().map(s).collect())).collect();
        if !roster.contains_key(&s(&d["identity"])) {
            return Self::error(d, "policy.blocked");
        }
        let Some(handover) = d["handover_seq"].as_i64().filter(|h| *h >= self.next_seq) else {
            return Self::error(d, "policy.blocked"); // M§12.2: (group, seq) is unique
        };
        self.moved_to = None;
        self.epoch = d["view"]["epoch"].as_i64().unwrap_or(self.epoch);
        self.roster = roster;
        self.next_seq = handover + 1;
        self.group_info = true;
        let mut out = vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"]}})];
        out.extend(self.roster.keys().map(|i| json!({"fanout": {"to": i, "class": "group-info"}})));
        out
    }

    fn sequence(&mut self, d: &Value, targets: &[String]) -> Vec<Value> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let class = s(&d["class"]);
        self.digests.insert(s(&d["digest"]), seq);
        self.seq_class.insert(seq, class.clone());
        let mut out = vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": seq}})];
        for i in targets {
            // M§6.5 rule 5: per-mailbox seq order; an unacknowledged item blocks later ones
            self.start_clock(i); // spec-gap 119
            let held = self.unregistered.contains(i);
            let q = self.pending.entry(i.clone()).or_default();
            q.push(seq);
            // spec-gap 66: nothing reaches a mailbox the commit brought in before it acknowledges its welcome — until then
            // it has no registration for the group and would refuse the item (M§6.6); a member that gained a device is
            // registered and gets the commit at once (spec-gap 87)
            if q.len() == 1 && !held {
                out.push(json!({"fanout": {"to": i, "seq": seq, "class": class}}));
            }
        }
        out
    }

    fn ack(&mut self, ident: &str, seq: i64, class: &str) -> Vec<Value> {
        let welcome = class == "welcome";
        // the hold behind an unacknowledged welcome applies here too: the queue moves, nothing is sent (spec-gap 87)
        let held = !welcome && self.unregistered.contains(ident);
        let next = {
            let queue = if welcome { &mut self.welcomes } else { &mut self.pending };
            let Some(q) = queue.get_mut(ident) else { return vec![] };
            if q.first() != Some(&seq) {
                return vec![];
            }
            q.remove(0);
            q.first().copied()
        };
        // spec-gap 119: progress restarts the clock; nothing left queued stops it
        let queued = self.pending.get(ident).is_some_and(|q| !q.is_empty()) || self.welcomes.get(ident).is_some_and(|q| !q.is_empty());
        if queued {
            self.waiting.insert(ident.to_string(), self.now);
        } else {
            self.waiting.remove(ident);
        }
        if held {
            return vec![];
        }
        if let Some(next) = next {
            let class = if welcome { "welcome".to_string() } else { self.seq_class[&next].clone() };
            return vec![json!({"fanout": {"to": ident, "seq": next, "class": class}})];
        }
        if welcome && self.unregistered.remove(ident) {
            // the group is registered now: whatever waited behind the welcome goes (a member that gained a device
            // waited for nothing: its head went out with the commit, spec-gap 87)
            if let Some(next) = self.pending.get(ident).and_then(|q| q.first()) {
                return vec![json!({"fanout": {"to": ident, "seq": next, "class": self.seq_class[next]}})];
            }
        }
        vec![]
    }

    /// Every seq still queued for some member mailbox, welcomes included: the payloads a host must keep for retries.
    pub fn queued_seqs(&self) -> BTreeSet<i64> {
        self.pending.values().chain(self.welcomes.values()).flatten().copied().collect()
    }

    /// Snapshot compared by the vectors: epoch, next seq, roster, non-empty pending queues.
    pub fn snapshot(&self) -> Value {
        let roster: serde_json::Map<String, Value> =
            self.roster.iter().map(|(i, d)| (i.clone(), json!(d.iter().collect::<Vec<_>>()))).collect();
        let pending: serde_json::Map<String, Value> =
            self.pending.iter().filter(|(_, q)| !q.is_empty()).map(|(i, q)| (i.clone(), json!(q))).collect();
        let welcomes: serde_json::Map<String, Value> =
            self.welcomes.iter().filter(|(_, q)| !q.is_empty()).map(|(i, q)| (i.clone(), json!(q))).collect();
        json!({"epoch": self.epoch, "next_seq": self.next_seq, "roster": roster, "pending": pending,
               "group_info": self.group_info, "moved_to": self.moved_to, "welcomes": welcomes})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_saved_before_the_retention_clock_starts_one_on_restore() {
        let ctx = json!({"now": 1000, "kind": "direct", "epoch": 1, "mls_retention_s": 100,
            "roster": {"a": ["da"], "b": ["db"]}});
        let mut h = Hub::new(&ctx);
        h.step(&json!({"deposit": {"id": "x", "device": "da", "identity": "a", "class": "application", "epoch": 1, "digest": "d1"}}));
        let mut old = h.full_state();
        old.as_object_mut().unwrap().remove("waiting");
        let mut resaved = h.full_state();
        resaved["waiting"] = json!({});
        assert_eq!(Hub::from_full_state(&resaved).unwrap().waiting, h.waiting);
        let mut r = Hub::from_full_state(&old).unwrap();
        assert!(r.step(&json!({"advance": 99})).is_empty());
        let out = r.step(&json!({"advance": 1}));
        assert!(out.iter().any(|e| e["dropped"]["identity"] == "b"), "{out:?}");
    }
}
