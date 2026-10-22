//! The subscriber's side of the Presence Profile: several devices' records combined into one identity's presence.
//!
//! Spec: P§4 (the combining rule: valid records and the authority's assertion as candidates, ranked `dnd` > `busy` >
//! `available` > `away` > `offline`, ties broken deterministically: a record before the assertion, a registered state
//! before an unknown one, code-point order), P§5 (an unknown state ranks and shows as
//! `available`, its token kept).

use serde_json::{json, Value};

use dsip_core::registry::{effective_presence_state, PRESENCE_STATES};

/// The identity's presence as P§4 combines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combined {
    /// The effective state: a `dsip-presence-state` registered value.
    pub state: String,
    /// The token that won, shown raw when unknown (P§5).
    pub token: String,
    /// `record`, `assertion` or `none`: where the winner came from. A client renders an assertion as the authority's
    /// claim (§9.3).
    pub source: &'static str,
}

/// P§4 rank of an effective state, highest first.
fn rank(state: &str) -> u8 {
    match state {
        "dnd" => 4,
        "busy" => 3,
        "available" => 2,
        "away" => 1,
        _ => 0,
    }
}

/// Combine the records a subscriber holds (each `{state, expires_at, device?}`) with the body's assertion at `now`.
///
/// Spec: P§4, P§5.
pub fn combine(records: &[Value], asserted: Option<&str>, now: i64) -> Combined {
    let mut candidates: Vec<(String, &'static str)> = records
        .iter()
        .filter(|r| r["expires_at"].as_i64().is_some_and(|e| e > now))
        .filter_map(|r| r["state"].as_str().map(|s| (s.to_string(), "record")))
        .collect();
    if asserted == Some("available") {
        candidates.push(("available".into(), "assertion"));
    }
    // highest rank, then a record before the assertion, a registered token before an unknown one, code-point order
    let best = candidates.into_iter().min_by(|(a, sa), (b, sb)| {
        let key = |t: &str, s: &str| {
            (std::cmp::Reverse(rank(effective_presence_state(t))), s != "record", !PRESENCE_STATES.contains(&t), t.to_string())
        };
        key(a, sa).cmp(&key(b, sb))
    });
    match best {
        None => Combined { state: "offline".into(), token: "offline".into(), source: "none" },
        Some((token, source)) => Combined { state: effective_presence_state(&token).into(), token, source },
    }
}

/// Run a `presence` vector (`input.check` `aggregate`).
///
/// Spec: P§4.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    match i["check"].as_str() {
        Some("aggregate") => {
            let records = i["records"].as_array().cloned().unwrap_or_default();
            let c = combine(&records, i["asserted"].as_str(), v["context"]["now"].as_i64().unwrap_or(0));
            json!({"state": c.state, "token": c.token, "source": c.source})
        }
        other => json!({"error": format!("unknown presence check {other:?}")}),
    }
}
