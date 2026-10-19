//! Whether a conversation is recorded, by which recorders, and whether this member may send.
//!
//! Spec: C§5 (recorder leaves carry `dsip.record`; content waits until every recorder is accepted; a recorder of
//! this member's own identity is its own organisation's and needs no acceptance from it).

use std::collections::BTreeSet;

use dsip_messaging::mls_wire::LeafIdentity;
use serde_json::{json, Value};

/// `dsip_recording::conversation` over a group's authenticated leaves, given the recorder devices this member has
/// accepted, plus `pending`: the recorders not accepted yet.
pub fn state(leaves: &[LeafIdentity], me: &str, accepted: &BTreeSet<String>) -> Value {
    let leaves_json: Vec<Value> = leaves.iter().map(|w| json!({"device": w.device, "subject": w.identity, "capabilities": w.capabilities})).collect();
    let ok: Vec<&str> = leaves.iter().filter(|w| w.is_recorder())
        .filter(|w| w.identity == me || accepted.contains(&w.device)).map(|w| w.device.as_str()).collect();
    let mut out = dsip_recording::conversation(&json!({"leaves": leaves_json, "accepted": ok}));
    let pending: Vec<Value> = out["recorders"].as_array().into_iter().flatten()
        .filter(|r| !r["device"].as_str().is_some_and(|d| ok.contains(&d))).cloned().collect();
    out["pending"] = json!(pending);
    out
}
