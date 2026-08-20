//! Forking relay: per-leg attempt tracking and attempt-outcome signaling.
//!
//! Spec: §12.7 rule 3 (track delivered legs; deliver `cancel` per-leg to every
//! leg that has not terminated) and rule 6 (when the final outstanding leg
//! terminates without an answer, forward the most informative `reject`:
//! `user.declined` > `user.no-answer` > `endpoint.busy` > `endpoint.unavailable`).
//!
//! This is the data model `dsip-relay` uses; it has no I/O so the vector
//! suite can drive it directly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::event::Emission;
use crate::message::Message;

/// §12.7 rule 6 preference order. Other tokens rank after these, first-seen first.
pub const REASON_RANK: &[&str] = &["user.declined", "user.no-answer", "endpoint.busy", "endpoint.unavailable"];

/// Per-leg state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum LegState {
    Delivered,
    Answered,
    Rejected,
    Expired,
    Cancelled,
}

impl LegState {
    fn terminated(self) -> bool {
        self != LegState::Delivered
    }
}

/// One forked invite attempt.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Session id.
    pub session: String,
    /// Initiator device DID.
    pub initiator: String,
    /// Addressed identity.
    pub identity: String,
    /// Leg → state (ordered for deterministic output).
    pub legs: BTreeMap<String, LegState>,
    /// Leg → reject reason (insertion order matters for ties).
    pub reasons: Vec<(String, String)>,
    /// `None` | `answered` | `rejected` | `cancelled`.
    pub outcome: Option<&'static str>,
}

impl Attempt {
    /// README snapshot shape.
    pub fn snapshot(&self) -> Value {
        json!({ "legs": self.legs, "outcome": self.outcome })
    }
}

/// Relay-side events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelayEvent {
    /// Clock advance (no relay timers in this model; kept for trace symmetry).
    Advance {
        /// Seconds.
        advance: i64,
    },
    /// A message from a leg or the initiator.
    Recv {
        /// The message.
        recv: Message,
    },
    /// A relay-internal action.
    Relay(RelayAction),
}

/// Relay-internal actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "relay", rename_all = "snake_case")]
pub enum RelayAction {
    /// Fork an invite to the listed device legs.
    Invite {
        /// Session id.
        session: String,
        /// Initiator device.
        from: String,
        /// Addressed identity.
        to: String,
        /// Device legs.
        legs: Vec<String>,
    },
    /// The relay's own delivery expiry for a leg.
    LegExpired {
        /// Session id.
        session: String,
        /// Leg device.
        leg: String,
    },
}

/// The relay's attempt tracker.
pub struct Relay {
    /// Clock.
    pub now: i64,
    attempts: BTreeMap<String, Attempt>,
    out: Vec<Emission>,
}

impl Relay {
    /// Create a relay tracker.
    pub fn new(start: i64) -> Relay {
        Relay { now: start, attempts: BTreeMap::new(), out: vec![] }
    }

    /// Snapshot of named attempts.
    pub fn snapshot(&self, ids: impl IntoIterator<Item = String>) -> Value {
        let mut m = serde_json::Map::new();
        for id in ids {
            m.insert(id.clone(), self.attempts.get(&id).map(Attempt::snapshot).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    /// Drive one event.
    pub fn step(&mut self, ev: &RelayEvent) -> Vec<Emission> {
        self.out.clear();
        match ev {
            RelayEvent::Advance { advance } => self.now += advance,
            RelayEvent::Relay(a) => self.action(a),
            RelayEvent::Recv { recv } => self.recv(recv),
        }
        std::mem::take(&mut self.out)
    }

    fn action(&mut self, a: &RelayAction) {
        match a {
            RelayAction::Invite { session, from, to, legs } => {
                let mut att = Attempt {
                    session: session.clone(),
                    initiator: from.clone(),
                    identity: to.clone(),
                    legs: BTreeMap::new(),
                    reasons: vec![],
                    outcome: None,
                };
                for leg in legs {
                    att.legs.insert(leg.clone(), LegState::Delivered);
                    self.out.push(Emission::Deliver { leg: leg.clone(), msg_type: "invite".into(), reason: None });
                }
                self.attempts.insert(session.clone(), att);
            }
            RelayAction::LegExpired { session, leg } => {
                if let Some(att) = self.attempts.get_mut(session) {
                    if att.legs.get(leg) == Some(&LegState::Delivered) {
                        att.legs.insert(leg.clone(), LegState::Expired);
                        if !att.reasons.iter().any(|(l, _)| l == leg) {
                            att.reasons.push((leg.clone(), "endpoint.unavailable".into()));
                        }
                        let sid = session.clone();
                        self.check_complete(&sid);
                    }
                }
            }
        }
    }

    fn recv(&mut self, m: &Message) {
        let Some(sid) = m.session.clone() else {
            self.out.push(Emission::Drop("unknown-attempt"));
            return;
        };
        let Some(att) = self.attempts.get_mut(&sid) else {
            self.out.push(Emission::Drop("unknown-attempt"));
            return;
        };
        if m.msg_type == "cancel" && m.from == att.initiator {
            // §12.7 rule 3: per-leg cancel to every leg that has not terminated
            let live: Vec<String> = att.legs.iter().filter(|(_, s)| !s.terminated()).map(|(l, _)| l.clone()).collect();
            for leg in live {
                att.legs.insert(leg.clone(), LegState::Cancelled);
                self.out.push(Emission::Deliver { leg, msg_type: "cancel".into(), reason: m.reason.clone() });
            }
            if att.outcome.is_none() {
                att.outcome = Some("cancelled");
            }
            return;
        }
        let leg = m.from.clone();
        let Some(&state) = att.legs.get(&leg) else {
            self.out.push(Emission::Drop("unknown-leg"));
            return;
        };
        if state.terminated() && !(m.msg_type == "answer" && state == LegState::Answered) {
            self.out.push(Emission::Drop("leg-terminated"));
            return;
        }
        match m.msg_type.as_str() {
            "progress" => self.out.push(Emission::Forward {
                msg_type: "progress".into(),
                status: m.status.clone(),
                reason: None,
                from: leg,
            }),
            "answer" => {
                att.legs.insert(leg.clone(), LegState::Answered);
                if att.outcome.is_none() {
                    att.outcome = Some("answered");
                }
                // Always forwarded: the initiator decides (first-accept; late → bye already-answered).
                self.out.push(Emission::Forward { msg_type: "answer".into(), status: None, reason: None, from: leg });
            }
            "reject" => {
                att.legs.insert(leg.clone(), LegState::Rejected);
                att.reasons.push((leg, m.reason.clone().unwrap_or_default()));
                self.check_complete(&sid);
            }
            _ => self.out.push(Emission::Drop("not-attempt-scoped")),
        }
    }

    /// §12.7 rule 6: when the final outstanding leg terminates without an answer,
    /// forward the most informative reject as the attempt outcome.
    fn check_complete(&mut self, sid: &str) {
        let Some(att) = self.attempts.get_mut(sid) else { return };
        if att.outcome.is_some() || att.legs.values().any(|s| !s.terminated()) {
            return;
        }
        att.outcome = Some("rejected");
        let best = REASON_RANK
            .iter()
            .find(|r| att.reasons.iter().any(|(_, x)| x == *r))
            .map(|r| r.to_string())
            .or_else(|| att.reasons.first().map(|(_, r)| r.clone()))
            .unwrap_or_else(|| "endpoint.unavailable".into());
        let from = att.reasons.iter().find(|(_, r)| *r == best).map(|(l, _)| l.clone()).unwrap_or_default();
        self.out.push(Emission::Forward { msg_type: "reject".into(), status: None, reason: Some(best), from });
    }
}
