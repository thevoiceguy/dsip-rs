//! `dsip-recording` — the rules of the DSIP Recording Profile (draft `recording/0.1`,
//! `v0.10/dsip-recording-profile-v0.10-draft.md`, cited `C§n`). Pure: no network, no media.
//!
//! Spec: sections owned by this crate — C§4 (a counterparty's consent: render, hold until
//! acceptance, decline with `policy.recording-declined` — [`Consent`]), C§5 (a recorded
//! conversation; a recorder is receive-only — [`conversation`]), C§6 (the recording party's checks
//! on its recorder leg — [`recording_session`]).
//!
//! Impl (spec-gap 107): an unregistered recording state is read as `on`; acceptance is per session
//! and per recorder. Every rule is pinned by `impl/vectors/recording/`; the Python reference is
//! `impl/tools/dsipvec/recording.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::{json, Value};

/// The reason a party declines to be recorded (C§7).
pub const DECLINED: &str = "policy.recording-declined";

/// The capability that marks a recorder device (C§1).
pub const RECORD: &str = "dsip.record";

/// A counterparty's standing answer to a recording declaration (C§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptPolicy {
    /// Ask the user.
    Ask,
    /// Accept every recorder.
    Always,
    /// Decline every recording (also what `policy.recording: forbidden` means, C§2).
    Never,
}

/// One counterparty's client in one call: what it renders, whether it holds its media, and when it
/// declines.
///
/// Spec: C§4.
#[derive(Debug, Clone)]
pub struct Consent {
    callee: bool,
    policy: AcceptPolicy,
    disclosure: Option<Value>,
    pending: bool,
    accepted: BTreeSet<String>,
    answered: bool,
    ended: Option<&'static str>,
}

impl Consent {
    /// A client on the `callee` side or the caller's, with its standing policy.
    pub fn new(callee: bool, policy: AcceptPolicy) -> Consent {
        Consent { callee, policy, disclosure: None, pending: false, accepted: BTreeSet::new(), answered: false, ended: None }
    }

    /// Whether outbound media must be held (C§4).
    pub fn hold_media(&self) -> bool {
        self.pending && self.ended.is_none()
    }

    /// Whether an acceptance is awaited.
    pub fn pending(&self) -> bool {
        self.pending
    }

    /// The other side's current declaration, if it is not off.
    pub fn disclosure(&self) -> Option<&Value> {
        self.disclosure.as_ref()
    }

    fn decline(&mut self) -> Vec<Value> {
        let t = if self.callee && !self.answered { "reject" } else { "bye" };
        self.ended = Some(DECLINED);
        self.pending = false;
        vec![json!({"send": {"type": t, "reason": DECLINED}})]
    }

    /// A received `invite`, `answer` or `update` with its `recording` member (or none).
    pub fn received(&mut self, msg_type: &str, recording: Option<&Value>) -> Vec<Value> {
        if self.ended.is_some() {
            return vec![];
        }
        if msg_type == "answer" {
            self.answered = true;
        }
        let state = recording.and_then(|r| r["state"].as_str()).unwrap_or("off");
        if state == "off" {
            let Some(prev) = self.disclosure.take() else { return vec![] };
            self.pending = false;
            return vec![json!({"render": {"state": "off", "recorder": prev["recorder"]}})];
        }
        let r = recording.expect("a state other than off came from a declaration");
        let recorder = r["recorder"].as_str().unwrap_or("").to_string();
        let mut decl = json!({"state": state, "recorder": recorder});
        if let Some(p) = r.get("purpose") {
            decl["purpose"] = p.clone();
        }
        let mut out = vec![];
        if self.disclosure.as_ref() != Some(&decl) {
            out.push(json!({"render": decl.clone()}));
            self.disclosure = Some(decl);
        }
        if state == "paused" || self.accepted.contains(&recorder) {
            self.pending = false;
        } else {
            // C§4: an unregistered state is read as on
            match self.policy {
                AcceptPolicy::Always => {
                    out.push(json!({"accepted": {"recorder": recorder, "by": "policy"}}));
                    self.accepted.insert(recorder);
                }
                AcceptPolicy::Never => out.extend(self.decline()),
                AcceptPolicy::Ask => self.pending = true,
            }
        }
        out
    }

    /// The user accepts the current disclosure.
    pub fn accept(&mut self) -> Vec<Value> {
        if !self.pending {
            return vec![];
        }
        let rec = self.disclosure.as_ref().and_then(|d| d["recorder"].as_str()).unwrap_or("").to_string();
        self.pending = false;
        self.accepted.insert(rec.clone());
        vec![json!({"accepted": {"recorder": rec, "by": "user"}})]
    }

    /// The user declines (at any time while something is disclosed).
    pub fn decline_now(&mut self) -> Vec<Value> {
        if self.ended.is_none() && self.disclosure.is_some() {
            self.decline()
        } else {
            vec![]
        }
    }

    /// The callee's user tries to answer.
    pub fn answer(&mut self) -> Vec<Value> {
        if self.ended.is_some() || !self.callee {
            return vec![];
        }
        if self.pending {
            return vec![json!({"blocked": "awaiting-acceptance"})];
        }
        self.answered = true;
        vec![json!({"send": {"type": "answer"}})]
    }

    /// The README's snapshot.
    pub fn snapshot(&self) -> Value {
        json!({"disclosure": self.disclosure, "pending": self.pending, "hold_media": self.hold_media(),
               "accepted": self.accepted.iter().collect::<Vec<_>>(), "ended": self.ended})
    }
}

fn has_record(leaf: &Value) -> bool {
    leaf["capabilities"].as_array().is_some_and(|c| c.iter().any(|x| x == RECORD))
}

/// Is the conversation recorded, may this member send, and is a sender's content rendered.
///
/// Spec: C§5.
pub fn conversation(i: &Value) -> Value {
    let leaves = i["leaves"].as_array().cloned().unwrap_or_default();
    let mut rec: Vec<Value> = leaves.iter().filter(|l| has_record(l)).map(|l| json!({"device": l["device"], "subject": l["subject"]})).collect();
    rec.sort_by(|a, b| a["device"].as_str().cmp(&b["device"].as_str()));
    let accepted: BTreeSet<&str> = i["accepted"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let may_send = rec.iter().all(|r| r["device"].as_str().is_some_and(|d| accepted.contains(d)));
    let mut out = json!({"recorded": !rec.is_empty(), "recorders": rec, "may_send": may_send});
    if let Some(s) = i.get("sender") {
        let leaf = leaves.iter().find(|l| &l["device"] == s);
        out["render_sender"] = json!(leaf.is_some_and(|l| !has_record(l)));
    }
    out
}

/// The recording party's checks before it streams to its recorder: `{"ok": true}` or `{"refused": token}`.
///
/// Spec: C§6.
pub fn recording_session(i: &Value) -> Value {
    let (d, r, o) = (&i["declared"], &i["recorder"], &i["offer"]);
    let refused = |t: &str| json!({"refused": t});
    if d["state"].as_str().unwrap_or("off") == "off" {
        return refused("not-declared");
    }
    if r["identity"] != d["recorder"] {
        return refused("recorder-mismatch");
    }
    if !has_record(r) {
        return refused("missing-capability");
    }
    let rs = &o["recording_session"];
    if rs["of"] != d["session"] {
        return refused("wrong-session");
    }
    let media = o["media"].as_array().cloned().unwrap_or_default();
    let who: BTreeSet<&str> = rs["participants"].as_array().into_iter().flatten().filter_map(|p| p["identity"].as_str()).collect();
    let mut seen = BTreeSet::new();
    let streams = rs["streams"].as_array().cloned().unwrap_or_default();
    if streams.is_empty() {
        return refused("bad-stream-map");
    }
    for s in &streams {
        let ok = s["media"].as_u64().is_some_and(|m| (m as usize) < media.len() && seen.insert(m))
            && s["participant"].as_str().is_some_and(|p| who.contains(p));
        if !ok {
            return refused("bad-stream-map");
        }
    }
    if streams.iter().any(|s| media[s["media"].as_u64().unwrap_or(0) as usize]["direction"] != "sendonly") {
        return refused("direction");
    }
    json!({"ok": true})
}

/// The devices to add for an identity from its KeyPackage directory's answer: `{"add": [device…]}` or
/// `{"refused": "no-key-packages" | "recorder-only"}`.
///
/// Spec: C§5 (a recorder never stands in for the person; never the personal group), M§5.5, M§7.2 (every device).
pub fn add_devices(i: &Value) -> Value {
    let mut seen = BTreeSet::new();
    let mut cands: Vec<&Value> = vec![];
    for k in i["key_packages"].as_array().into_iter().flatten() {
        let Some(device) = k["device"].as_str() else { continue };
        if k["identity"] != i["target"] || Some(device) == i["self_device"].as_str() || !seen.insert(device.to_string()) {
            continue;
        }
        cands.push(k);
    }
    if i["purpose"] == "personal" {
        cands.retain(|k| !has_record(k));
    }
    if cands.is_empty() {
        return json!({"refused": "no-key-packages"});
    }
    if cands.iter().all(|k| has_record(k)) && i["target"] != i["self_identity"] {
        return json!({"refused": "recorder-only"});
    }
    json!({"add": cands.iter().map(|k| k["device"].clone()).collect::<Vec<_>>()})
}

/// Run one `recording` vector.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    match i["check"].as_str() {
        Some("conversation") => conversation(i),
        Some("recording-session") => recording_session(i),
        Some("add-devices") => add_devices(i),
        Some(_) => json!({"error": "unknown check"}),
        None => {
            let c = &v["context"];
            let policy = match c["accept"].as_str() {
                Some("always") => AcceptPolicy::Always,
                Some("never") => AcceptPolicy::Never,
                _ => AcceptPolicy::Ask,
            };
            let mut m = Consent::new(c["role"] == "callee", policy);
            Value::Array(
                i["steps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|st| {
                        let ev = &st["event"];
                        let emit = if let Some(r) = ev.get("received") {
                            m.received(r["type"].as_str().unwrap_or(""), r.get("recording"))
                        } else {
                            match ev["local"].as_str() {
                                Some("accept") => m.accept(),
                                Some("decline") => m.decline_now(),
                                Some("answer") => m.answer(),
                                _ => vec![],
                            }
                        };
                        let mut s = m.snapshot();
                        s["emit"] = Value::Array(emit);
                        s
                    })
                    .collect(),
            )
        }
    }
}
