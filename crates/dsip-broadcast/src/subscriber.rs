//! The subscriber: seq ordering, terminal state, local lapse.
//!
//! Spec: §9.3 — receivers discard lower-than-seen `seq`; a `terminated` notify
//! is final; renewal is a fresh `subscribe` before `expires_in` lapses.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dsip_core::registry::resolve_reason;

/// One subscription as seen by the subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sub {
    /// Target.
    pub target: String,
    /// Events.
    pub events: Vec<String>,
    /// `pending` | `active` | `terminated` | `rejected` | `lapsed`.
    pub state: String,
    /// Highest seq seen.
    pub seq: u64,
    /// Local expiry.
    pub expires_at: i64,
}

/// The subscriber.
pub struct Subscriber {
    /// Clock.
    pub now: i64,
    /// Subscriptions by id.
    pub subs: BTreeMap<String, Sub>,
}

impl Subscriber {
    /// Create at clock `start`.
    pub fn new(start: i64) -> Subscriber {
        Subscriber { now: start, subs: BTreeMap::new() }
    }

    /// Drive a trace event; returns README-shaped emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let mut out = vec![];
        if let Some(a) = ev.get("advance").and_then(Value::as_i64) {
            self.now += a;
            for (sid, s) in self.subs.iter_mut() {
                if s.state == "active" && s.expires_at <= self.now {
                    s.state = "lapsed".into();
                    out.push(json!({"ui": "subscription_lapsed", "subscription": sid}));
                }
            }
        } else if ev.get("local").and_then(Value::as_str) == Some("subscribe") {
            let id = ev["id"].as_str().unwrap_or("").to_string();
            let events: Vec<String> = ev["events"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
            let expires_in = ev["expires_in"].as_i64().unwrap_or(0);
            self.subs.insert(
                id.clone(),
                Sub { target: ev["target"].as_str().unwrap_or("").into(), events: events.clone(), state: "pending".into(), seq: 0, expires_at: self.now + expires_in },
            );
            out.push(json!({"send": {"type": "subscribe", "to": ev["to"], "id": id, "target": ev["target"], "events": events, "expires_in": expires_in}}));
        } else if let Some(m) = ev.get("recv") {
            out.extend(self.recv(m));
        }
        out
    }

    /// A verified `notify` or `reject` arrived.
    pub fn recv(&mut self, m: &Value) -> Vec<Value> {
        let t = m["type"].as_str().unwrap_or("");
        if t == "reject" {
            let Some(s) = m["session"].as_str().and_then(|sid| self.subs.get_mut(sid)) else {
                return vec![json!({"drop": "unknown-subscription"})];
            };
            s.state = "rejected".into();
            let reason = resolve_reason(m["reason"].as_str().unwrap_or(""), "reject").effective;
            return vec![json!({"ui": "subscription_rejected", "reason": reason})];
        }
        if t != "notify" {
            return vec![json!({"drop": "not-subscription"})];
        }
        let Some(s) = m["subscription"].as_str().and_then(|sid| self.subs.get_mut(sid)) else {
            return vec![json!({"drop": "unknown-subscription"})];
        };
        if s.state == "terminated" || s.state == "rejected" {
            return vec![json!({"drop": "terminated-subscription"})];
        }
        let seq = m["seq"].as_u64().unwrap_or(0);
        if seq <= s.seq {
            return vec![json!({"drop": "stale-seq"})]; // §9.3: discard lower-than-seen seq
        }
        s.seq = seq;
        if m["state"] == "terminated" {
            s.state = "terminated".into();
            return vec![json!({"ui": "subscription_terminated", "reason": m.get("reason").cloned().unwrap_or(Value::Null)})];
        }
        s.state = "active".into();
        vec![json!({"ui": "notify", "event": m["body"]["event"], "state": m["body"]["state"]})]
    }

    /// README snapshot.
    pub fn snapshot(&self) -> Value {
        let m: serde_json::Map<String, Value> =
            self.subs.iter().map(|(k, s)| (k.clone(), json!({"target": s.target, "state": s.state, "seq": s.seq}))).collect();
        Value::Object(m)
    }
}
