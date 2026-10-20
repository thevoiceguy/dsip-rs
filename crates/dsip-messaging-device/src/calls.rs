//! What a device records of its calls: the `call-event` in its personal group, the call log of every device of the
//! identity, and the `call-record` for its identity's record-keeper.
//!
//! Spec: M§13.3 (call events, spec-gap 63; the pinned `call_event_decision`), C§9 (call records, v0.13, spec-gaps
//! 121 and 123; the pinned `call-record-outcome` order).

use std::collections::BTreeMap;

use dsip_messaging::checks::check_object;
use serde_json::{json, Value};

/// This identity's call log: one call event per session, whichever device reported it, the first kept (spec-gap 63),
/// in the order they were recorded — the order the pinned `peer_timeline` keeps for calls at the same time.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CallLog(Vec<Value>);

impl CallLog {
    /// A log saved by session (dsip-msg's format); its order is the sessions'.
    pub fn from_map(map: BTreeMap<String, Value>) -> CallLog {
        CallLog(map.into_values().collect())
    }

    /// The log by session (dsip-msg's format).
    pub fn to_map(&self) -> BTreeMap<String, Value> {
        self.0.iter().map(|e| (e["session"].as_str().unwrap_or("").to_string(), e.clone())).collect()
    }

    /// Record a call event, sent or received, live or from the archive; `false` when its session is already logged.
    pub fn record(&mut self, event: &Value) -> bool {
        if self.get(event["session"].as_str().unwrap_or("")).is_some() {
            return false;
        }
        self.0.push(event.clone());
        true
    }

    /// The call event logged for `session`.
    pub fn get(&self, session: &str) -> Option<&Value> {
        self.0.iter().find(|e| e["session"] == session)
    }

    /// Every call event logged, in order.
    pub fn events(&self) -> &[Value] {
        &self.0
    }

    /// The call events with `peer`, in order, as the pinned `peer_timeline` takes them (M§13.3: interleaved by peer
    /// identity).
    pub fn with_peer(&self, peer: &str) -> Vec<Value> {
        self.0.iter().filter(|e| e["peer"] == peer).cloned().collect()
    }
}

/// How one inbound leg ended, as the host saw it.
pub struct Ended<'a> {
    /// The call's session id.
    pub session: &'a str,
    /// The caller.
    pub peer: &'a str,
    /// Whether this device alerted.
    pub alerted: bool,
    /// Whether this device answered.
    pub answered_here: bool,
    /// Who ended it (`local`, `remote`, …).
    pub ended_by: &'a str,
    /// The reason token, or empty.
    pub reason: &'a str,
}

/// The `call-event` to send to the personal group for an inbound leg, or `None` when the pinned decision sends
/// nothing (the call was answered elsewhere, or never alerted here).
pub fn call_event(leg: &Ended, now: i64) -> Option<Value> {
    let d = dsip_messaging::client::call_event_decision(&json!({"alerted": leg.alerted, "answered_here": leg.answered_here,
        "ended_by": leg.ended_by, "reason": leg.reason}));
    (d["send"] == json!(true)).then(|| json!({"object": "call-event", "session": leg.session, "peer": leg.peer, "direction": "inbound",
        "outcome": d["outcome"], "at": now}))
}

/// One leg's `call-record` (C§9) from `leg` = `{session, direction, peer, relay?, invited_at, answered, answered_at?,
/// ended_by, reason?, media?, evidence?}`: `answered_at` exactly when the outcome is `answered`; `ended_at` is now, never
/// before the invite or answer. `Err` is the check code of a record the record-keeper would drop: it is never sent.
pub fn call_record(leg: &Value, device: &str, now: i64) -> Result<Value, String> {
    let outcome = dsip_recording::call_record_outcome(&json!({"direction": leg["direction"], "answered": leg["answered"] == json!(true),
        "ended_by": leg["ended_by"], "reason": leg["reason"]}));
    let mut rec = json!({"object": "call-record", "session": leg["session"], "device": device, "direction": leg["direction"],
        "peer": leg["peer"], "invited_at": leg["invited_at"], "outcome": outcome, "ended_by": leg["ended_by"]});
    let mut last = leg["invited_at"].as_i64().unwrap_or(0);
    if outcome == "answered" {
        rec["answered_at"] = leg["answered_at"].clone();
        last = last.max(leg["answered_at"].as_i64().unwrap_or(0));
    }
    // C§9: the times never decrease; an invite or answer stamped by a peer's clock ahead of ours ends no earlier
    rec["ended_at"] = json!(now.max(last));
    for k in ["relay", "reason"] {
        if leg[k].as_str().is_some_and(|v| !v.is_empty()) {
            rec[k] = leg[k].clone();
        }
    }
    for k in ["media", "evidence"] {
        if leg[k].as_array().is_some_and(|a| !a.is_empty()) {
            rec[k] = leg[k].clone();
        }
    }
    let v = check_object(&rec, &json!({"conversation_kind": "direct", "leaf_device": device}));
    if v["verdict"] != "accept" {
        return Err(v["code"].as_str().unwrap_or("invalid").to_string());
    }
    Ok(rec)
}
