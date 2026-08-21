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
    /// A device bound via `hello` (§13.2); flushes queued introductions for the identity.
    Bind {
        /// Device DID.
        device: String,
        /// Identity DID.
        identity: String,
    },
    /// A device unbound.
    Unbind {
        /// Device DID.
        device: String,
        /// Identity DID.
        identity: String,
    },
}

/// The relay's attempt tracker.
pub struct Relay {
    /// Clock.
    pub now: i64,
    attempts: BTreeMap<String, Attempt>,
    out: Vec<Emission>,
    /// identity → bound devices (§13.2). A key, even with an empty set, marks a *known* identity.
    pub bindings: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// device → identity for every device ever bound.
    pub devices: BTreeMap<String, String>,
    /// recipient → queued envelopes with deadlines (§13.3 store-and-forward; §19.4 introductions).
    pub inbox: BTreeMap<String, Vec<Queued>>,
    /// Maximum seconds an envelope is held (`offline_retention_s`).
    pub retention: i64,
    /// session → invite (for legs added mid-attempt, §12.7 rule 3).
    invites: BTreeMap<String, Message>,
}

/// A queued envelope.
#[derive(Debug, Clone)]
pub struct Queued {
    /// The message.
    pub message: Message,
    /// Drop at this time.
    pub deadline: i64,
}

impl Relay {
    /// Create a relay tracker.
    pub fn new(start: i64) -> Relay {
        Relay::with_retention(start, 86_400)
    }

    /// Create a relay tracker with an explicit retention cap (seconds).
    pub fn with_retention(start: i64, retention: i64) -> Relay {
        Relay {
            now: start,
            attempts: BTreeMap::new(),
            out: vec![],
            bindings: BTreeMap::new(),
            devices: BTreeMap::new(),
            inbox: BTreeMap::new(),
            retention,
            invites: BTreeMap::new(),
        }
    }

    /// Impl (spec-gap 17): a recipient is known if any device has ever bound for it here.
    pub fn known(&self, to: &str) -> bool {
        self.bindings.contains_key(to) || self.devices.contains_key(to)
    }

    fn enqueue(&mut self, m: &Message) {
        let to = m.to.clone().unwrap_or_default();
        let deadline = m.expires_at.unwrap_or(self.now + self.retention).min(self.now + self.retention);
        self.inbox.entry(to.clone()).or_default().push(Queued { message: m.clone(), deadline });
        self.out.push(Emission::Queue { to, msg_type: m.msg_type.clone() });
    }

    fn flush_to(&mut self, device: &str, m: Message) {
        if m.msg_type == "invite" {
            // A queued invite becomes a tracked leg on delivery (§12.7 rule 3)
            let sid = m.id.clone();
            let att = self.attempts.entry(sid.clone()).or_insert_with(|| Attempt {
                session: sid.clone(),
                initiator: m.from.clone(),
                identity: m.to.clone().unwrap_or_default(),
                legs: BTreeMap::new(),
                reasons: vec![],
                outcome: None,
            });
            att.legs.insert(device.to_string(), LegState::Delivered);
            self.invites.entry(sid.clone()).or_insert(m);
            self.out.push(Emission::Deliver { leg: device.into(), msg_type: "invite".into(), reason: None, id: Some(sid) });
        } else {
            self.out.push(Emission::Deliver { leg: device.into(), msg_type: m.msg_type.clone(), reason: None, id: Some(m.id.clone()) });
        }
    }

    /// Drop queued envelopes past their deadline (§13.3 boundary; nothing is signaled — spec-gap 17).
    pub fn expire_queues(&mut self) {
        let now = self.now;
        let mut empties = vec![];
        let keys: Vec<String> = self.inbox.keys().cloned().collect();
        for to in keys {
            let q = self.inbox.get_mut(&to).expect("key");
            let (expired, keep): (Vec<Queued>, Vec<Queued>) = q.drain(..).partition(|e| e.deadline <= now);
            *q = keep;
            for e in expired {
                self.out.push(Emission::Dequeue { to: to.clone(), msg_type: e.message.msg_type.clone(), why: "expired" });
            }
            if q.is_empty() {
                empties.push(to);
            }
        }
        for to in empties {
            self.inbox.remove(&to);
        }
    }

    /// The initiator device of a tracked attempt.
    pub fn attempt_initiator(&self, session: &str) -> Option<&str> {
        self.attempts.get(session).map(|a| a.initiator.as_str())
    }

    /// Invite on record for a session (for delivering to legs added mid-attempt).
    pub fn invite(&self, session: &str) -> Option<&Message> {
        self.invites.get(session)
    }

    /// README `inbox` snapshot: identity → queued count (non-empty only).
    pub fn inbox_snapshot(&self) -> Value {
        let m: serde_json::Map<String, Value> =
            self.inbox.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), json!(v.len()))).collect();
        Value::Object(m)
    }

    /// Devices an identity (or device) DID routes to.
    pub fn legs_for(&self, to: &str) -> Vec<String> {
        if let Some(identity) = self.devices.get(to) {
            return if self.bindings.get(identity).is_some_and(|s| s.contains(to)) { vec![to.to_string()] } else { vec![] };
        }
        self.bindings.get(to).map(|s| s.iter().cloned().collect()).unwrap_or_default()
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
            RelayEvent::Advance { advance } => {
                self.now += advance;
                self.expire_queues();
            }
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
                    self.out.push(Emission::Deliver { leg: leg.clone(), msg_type: "invite".into(), reason: None, id: None });
                }
                self.attempts.insert(session.clone(), att);
            }
            RelayAction::Bind { device, identity } => {
                self.bindings.entry(identity.clone()).or_default().insert(device.clone());
                self.devices.insert(device.clone(), identity.clone());
                // §13.3: flush the queues for the identity and the device, in order
                for key in [identity.clone(), device.clone()] {
                    for q in self.inbox.remove(&key).unwrap_or_default() {
                        self.flush_to(device, q.message);
                    }
                }
                // §12.7 rule 3: a device binding while an attempt for its identity is live becomes a new leg
                let live: Vec<String> = self
                    .attempts
                    .values()
                    .filter(|a| &a.identity == identity && a.outcome.is_none() && !a.legs.contains_key(device))
                    .map(|a| a.session.clone())
                    .collect();
                for sid in live {
                    let fresh = self.invites.get(&sid).map(|inv| inv.expires_at.unwrap_or(self.now + 1) > self.now).unwrap_or(false);
                    if fresh {
                        self.attempts.get_mut(&sid).expect("live").legs.insert(device.clone(), LegState::Delivered);
                        self.out.push(Emission::Deliver { leg: device.clone(), msg_type: "invite".into(), reason: None, id: Some(sid) });
                    }
                }
            }
            RelayAction::Unbind { device, identity } => {
                if let Some(set) = self.bindings.get_mut(identity) {
                    set.remove(device);
                }
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
        let to = m.to.clone().unwrap_or_default();
        if m.msg_type == "introduction" {
            // §19.4 anti-enumeration: unknown and offline identities are treated identically — queued, no error.
            // Impl (spec-gap 14): §13.2 "no silent drops" yields to §19.4 for this one message type.
            let devices = self.legs_for(&to);
            if devices.is_empty() {
                self.enqueue(m);
            } else {
                for d in devices {
                    self.out.push(Emission::Deliver { leg: d, msg_type: "introduction".into(), reason: None, id: None });
                }
            }
            return;
        }
        if m.msg_type == "invite" {
            let legs = self.legs_for(&to);
            if legs.is_empty() {
                if self.known(&to) {
                    self.enqueue(m); // §13.3: known but offline → store-and-forward
                } else {
                    // Session traffic to an identity this relay has never seen is refused with a signed error (§13.2).
                    self.out.push(Emission::Send(crate::event::SendMsg {
                        msg_type: "error".into(),
                        to: m.from.clone(),
                        reason: Some("transport.unknown-recipient".into()),
                        in_reply_to: Some(m.id.clone()),
                        ..Default::default()
                    }));
                }
                return;
            }
            self.invites.insert(m.id.clone(), m.clone());
            let act = RelayAction::Invite { session: m.id.clone(), from: m.from.clone(), to, legs };
            return self.action(&act);
        }
        let sid = m.session.clone().unwrap_or_default();
        let attempt_scoped = matches!(m.msg_type.as_str(), "progress" | "answer" | "reject" | "cancel") && m.in_reply_to.is_none();
        if self.attempts.contains_key(&sid) && !attempt_scoped {
            // Post-answer and renegotiation traffic is not attempt-scoped: plain routing by `to` (§13.2/§13.3).
            return self.route_plain(m);
        }
        if !self.attempts.contains_key(&sid) {
            if m.msg_type == "cancel" {
                // A cancel for an invite that is still queued drops the queued invite (§12.11)
                if let Some(q) = self.inbox.get_mut(&to) {
                    let before = q.len();
                    q.retain(|e| !(e.message.msg_type == "invite" && e.message.id == sid));
                    if q.len() != before {
                        if q.is_empty() {
                            self.inbox.remove(&to);
                        }
                        self.out.push(Emission::Dequeue { to, msg_type: "invite".into(), why: "cancelled" });
                        return;
                    }
                }
            }
            return self.route_plain(m);
        }
        let att = self.attempts.get_mut(&sid).expect("checked");
        if m.msg_type == "cancel" && m.from == att.initiator {
            // §12.7 rule 3: per-leg cancel to every leg that has not terminated
            let live: Vec<String> = att.legs.iter().filter(|(_, s)| !s.terminated()).map(|(l, _)| l.clone()).collect();
            for leg in live {
                att.legs.insert(leg.clone(), LegState::Cancelled);
                self.out.push(Emission::Deliver { leg, msg_type: "cancel".into(), reason: m.reason.clone(), id: None });
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

    /// Plain routing by `to`: deliver to bound devices, queue for a known-offline recipient, else drop.
    fn route_plain(&mut self, m: &Message) {
        let to = m.to.clone().unwrap_or_default();
        let legs = self.legs_for(&to);
        if !legs.is_empty() {
            for d in legs {
                self.out.push(Emission::Deliver { leg: d, msg_type: m.msg_type.clone(), reason: None, id: Some(m.id.clone()) });
            }
        } else if self.known(&to) {
            self.enqueue(m);
        } else {
            self.out.push(Emission::Drop("unknown-attempt"));
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
