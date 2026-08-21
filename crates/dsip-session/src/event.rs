//! Events into, and emissions out of, the state engine.
//!
//! Spec: none (infrastructure) — the vocabulary is fixed by
//! `impl/vectors/README.md` ("Kind: state"); [`Emission::to_json`] produces
//! exactly those shapes so Rust and Python traces compare byte-for-byte.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::message::Message;

/// A local (application) request to the endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "local", rename_all = "snake_case")]
pub enum LocalEvent {
    /// Send an `invite` with id `session` to `to`.
    PlaceCall {
        /// Session (= invite) id.
        session: String,
        /// Addressed identity or device DID.
        to: String,
    },
    /// Abandon an attempt (`cancel user.cancelled`).
    Cancel {
        /// Session id.
        session: String,
    },
    /// End an ACTIVE session (`bye`, reason `user.hangup` unless given — the media layer
    /// ends a failed path with `media.failed`, WebRTC Media Binding B§8).
    Hangup {
        /// Session id.
        session: String,
        /// Reason token override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Policy admits the invite: alert the user (`progress ringing`).
    Alert {
        /// Session id.
        session: String,
        /// Advertised ring timeout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ring_timeout: Option<i64>,
    },
    /// Policy rejects at OFFERED.
    AutoReject {
        /// Session id.
        session: String,
        /// Reason token.
        reason: String,
    },
    /// User/service accepts (`answer`).
    Accept {
        /// Session id.
        session: String,
        /// `answered_by` (default `user`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
    },
    /// User declines (`reject user.declined`).
    Decline {
        /// Session id.
        session: String,
    },
    /// Send an `update`.
    Update {
        /// Session id.
        session: String,
        /// Update id.
        id: String,
        /// Optional role-transition signal (§14.4).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
    },
    /// Answer the inbound outstanding update.
    AnswerUpdate {
        /// Session id.
        session: String,
        /// The update id.
        in_reply_to: String,
        /// `answered_by` (default `user`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
    },
    /// Reject the inbound outstanding update.
    RejectUpdate {
        /// Session id.
        session: String,
        /// The update id.
        in_reply_to: String,
        /// Reason token.
        reason: String,
    },
    /// Send an `info`.
    Info {
        /// Session id.
        session: String,
    },
    /// Send an `introduction` (§19.4).
    Introduce {
        /// Introduction id.
        id: String,
        /// Recipient identity.
        to: String,
        /// Stated purpose (a claim).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
        /// Out-of-band contact token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contact_token: Option<String>,
    },
    /// Issue a grant for a pending introduction.
    Grant {
        /// Introduction id.
        introduction: String,
        /// Grant id.
        id: String,
        /// Scopes.
        #[serde(default)]
        scope: Vec<String>,
        /// Grant lifetime.
        valid_until: i64,
    },
    /// Decline a pending introduction.
    RejectIntroduction {
        /// Introduction id.
        introduction: String,
        /// Reason token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Revoke an issued grant.
    Revoke {
        /// Grant id.
        grant: String,
    },
    /// Pre-authorize a contact token.
    IssueToken {
        /// Token.
        token: String,
        /// Grant id to issue on match.
        grant_id: String,
    },
}

impl LocalEvent {
    /// The session the event targets (`PlaceCall` creates it); empty for contact events.
    pub fn session(&self) -> &str {
        match self {
            LocalEvent::Introduce { .. }
            | LocalEvent::Grant { .. }
            | LocalEvent::RejectIntroduction { .. }
            | LocalEvent::Revoke { .. }
            | LocalEvent::IssueToken { .. } => "",
            LocalEvent::PlaceCall { session, .. }
            | LocalEvent::Cancel { session }
            | LocalEvent::Hangup { session, .. }
            | LocalEvent::Alert { session, .. }
            | LocalEvent::AutoReject { session, .. }
            | LocalEvent::Accept { session, .. }
            | LocalEvent::Decline { session }
            | LocalEvent::Update { session, .. }
            | LocalEvent::AnswerUpdate { session, .. }
            | LocalEvent::RejectUpdate { session, .. }
            | LocalEvent::Info { session } => session,
        }
    }
}

/// An event into an [`crate::Endpoint`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    /// Advance the clock by seconds; due timers fire.
    Advance {
        /// Seconds.
        advance: i64,
    },
    /// A verified message arrived.
    Recv {
        /// The message.
        recv: Message,
    },
    /// A local request.
    Local(LocalEvent),
}

/// An outbound message the engine wants sent (abbreviated; the transport builds the payload).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendMsg {
    /// Message type.
    pub msg_type: String,
    /// Destination DID.
    pub to: String,
    /// Session id (absent on `introduction`).
    pub session: Option<String>,
    /// Message id, when chosen by the caller (updates, introductions, grants).
    pub id: Option<String>,
    /// Reason token.
    pub reason: Option<String>,
    /// Progress status.
    pub status: Option<String>,
    /// Ring timeout advertised.
    pub ring_timeout: Option<i64>,
    /// `answered_by`.
    pub answered_by: Option<String>,
    /// `in_reply_to`.
    pub in_reply_to: Option<String>,
    /// Other fields (`grant`, `purpose`, `contact_token`, `scope`, `valid_until`), in emission order.
    pub extra: Vec<(&'static str, Value)>,
}

/// Everything the engine can emit.
#[derive(Debug, Clone, PartialEq)]
pub enum Emission {
    /// Send a message.
    Send(SendMsg),
    /// Timer lifecycle: `start` (with seconds), `stop`, `fire`.
    Timer {
        /// `start` | `stop` | `fire`.
        action: &'static str,
        /// Timer name.
        name: &'static str,
        /// Seconds, on start.
        seconds: Option<i64>,
    },
    /// Media-layer instruction: `start` | `stop` | `apply_update`.
    Media(&'static str),
    /// UI surface: kind plus fields.
    Ui {
        /// `progress`, `answered`, `offered`, `update_offered`, `update_rejected`, `missed_call`, `ended`, `glare_retry`, `error`,
        /// `introduction_received`, `granted`, `introduction_rejected`.
        kind: &'static str,
        /// Named fields, in emission order.
        fields: Vec<(&'static str, Value)>,
    },
    /// Relay queued a message for an identity with no bound device (§19.4 anti-enumeration).
    Queue {
        /// Identity.
        to: String,
        /// Message type.
        msg_type: String,
    },
    /// `info` handed to the binding named by `about`.
    Info {
        /// The `about` namespace.
        about: String,
    },
    /// A local request was refused.
    Refused(&'static str),
    /// A message was silently ignored.
    Drop(&'static str),
    /// Relay: deliver to a specific leg.
    Deliver {
        /// Leg device DID.
        leg: String,
        /// Message type.
        msg_type: String,
        /// Reason (cancel).
        reason: Option<String>,
        /// Envelope id, when delivering a queued envelope or a leg added mid-attempt (§13.3).
        id: Option<String>,
    },
    /// Relay: a queued envelope was dropped (`expired` | `cancelled`).
    Dequeue {
        /// Recipient.
        to: String,
        /// Message type.
        msg_type: String,
        /// Why.
        why: &'static str,
    },
    /// Relay: forward a leg's message to the initiator.
    Forward {
        /// Message type.
        msg_type: String,
        /// Status (progress).
        status: Option<String>,
        /// Reason (reject).
        reason: Option<String>,
        /// Originating leg.
        from: String,
    },
}

impl Emission {
    /// The README JSON shape.
    pub fn to_json(&self) -> Value {
        match self {
            Emission::Send(m) => {
                let mut o = Map::new();
                o.insert("type".into(), m.msg_type.clone().into());
                o.insert("to".into(), m.to.clone().into());
                if let Some(s) = &m.session {
                    o.insert("session".into(), s.clone().into());
                }
                let mut opt = |k: &str, v: Option<Value>| {
                    if let Some(v) = v {
                        o.insert(k.into(), v);
                    }
                };
                opt("id", m.id.clone().map(Value::from));
                opt("reason", m.reason.clone().map(Value::from));
                opt("status", m.status.clone().map(Value::from));
                opt("ring_timeout", m.ring_timeout.map(Value::from));
                opt("answered_by", m.answered_by.clone().map(Value::from));
                opt("in_reply_to", m.in_reply_to.clone().map(Value::from));
                for (k, v) in &m.extra {
                    o.insert((*k).into(), v.clone());
                }
                json!({ "send": o })
            }
            Emission::Timer { action, name, seconds } => match seconds {
                Some(s) => json!({"timer": action, "name": name, "seconds": s}),
                None => json!({"timer": action, "name": name}),
            },
            Emission::Media(m) => json!({ "media": m }),
            Emission::Ui { kind, fields } => {
                let mut o = Map::new();
                o.insert("ui".into(), (*kind).into());
                for (k, v) in fields {
                    o.insert((*k).into(), v.clone());
                }
                Value::Object(o)
            }
            Emission::Queue { to, msg_type } => json!({"queue": {"to": to, "type": msg_type}}),
            Emission::Info { about } => json!({"info": {"about": about}}),
            Emission::Refused(r) => json!({ "refused": r }),
            Emission::Drop(r) => json!({ "drop": r }),
            Emission::Deliver { leg, msg_type, reason, id } => {
                let mut o = Map::new();
                o.insert("leg".into(), leg.clone().into());
                o.insert("type".into(), msg_type.clone().into());
                if let Some(r) = reason {
                    o.insert("reason".into(), r.clone().into());
                }
                if let Some(i) = id {
                    o.insert("id".into(), i.clone().into());
                }
                json!({ "deliver": o })
            }
            Emission::Dequeue { to, msg_type, why } => json!({"dequeue": {"to": to, "type": msg_type, "why": why}}),
            Emission::Forward { msg_type, status, reason, from } => {
                let mut o = Map::new();
                o.insert("type".into(), msg_type.clone().into());
                if let Some(s) = status {
                    o.insert("status".into(), s.clone().into());
                }
                if let Some(r) = reason {
                    o.insert("reason".into(), r.clone().into());
                }
                o.insert("from".into(), from.clone().into());
                json!({ "forward": o })
            }
        }
    }
}
