//! The verified, abbreviated message view the state machine consumes.
//!
//! Spec: §12.3 — "a message 'arrives' when the endpoint receives and
//! successfully verifies it." Only the fields transitions depend on are kept.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A verified session-layer message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Message {
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Message id (ULID).
    pub id: String,
    /// Signing device / identity DID.
    pub from: String,
    /// Addressed DID (`invite`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Session id (absent on `invite`, whose `id` is the session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// `progress.status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// `progress.ring_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_timeout: Option<i64>,
    /// `progress.queue_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_timeout: Option<i64>,
    /// Reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `answered_by` on `answer`/`update`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<String>,
    /// Update being answered/rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// `info.about`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// `invite.expires_at` (bounds pre-alerting delivery, §12.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Message {
    /// Extract the engine's view from a full verified payload.
    pub fn from_payload(p: &Value) -> Option<Message> {
        let s = |k: &str| p.get(k).and_then(Value::as_str).map(String::from);
        let n = |k: &str| p.get(k).and_then(Value::as_i64);
        Some(Message {
            msg_type: s("type")?,
            id: s("id")?,
            from: s("from")?,
            to: s("to"),
            session: s("session"),
            status: s("status"),
            ring_timeout: n("ring_timeout"),
            queue_timeout: n("queue_timeout"),
            reason: s("reason"),
            answered_by: s("answered_by"),
            in_reply_to: s("in_reply_to"),
            about: s("about"),
            expires_at: if s("type").as_deref() == Some("invite") { n("expires_at") } else { None },
        })
    }

    /// The session this message operates on (`id` for `invite`).
    pub fn session_id(&self) -> &str {
        if self.msg_type == "invite" { &self.id } else { self.session.as_deref().unwrap_or("") }
    }
}
