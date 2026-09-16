//! Profile-aware inbound verification.
//!
//! Spec: §10.2 and §12.9 (the envelope pipeline: signature over bytes, delegation binding, replay
//! window, ULID consistency), M§5 (then the profile's own message rules). The core relay's pipeline
//! validates against the *core* message set and would reject every profile type as `unknown-type`,
//! so a mailbox runs this instead.

use dsip_core::envelope::{self, Context, Envelope, Verified};
use dsip_messaging::checks::check_message;

/// Why a frame was refused: an implementation-neutral code and, where the profile defines one, the
/// reason token the sender is told (M§16).
#[derive(Debug, Clone)]
pub struct Rejection {
    /// Vector code (`replay-window`, `deposit-fields`, …).
    pub code: String,
    /// Reason token, when one is defined.
    pub reason: Option<String>,
}

impl Rejection {
    /// The reason token to send, defaulting to a routing refusal.
    pub fn token(&self) -> &str {
        self.reason.as_deref().unwrap_or("transport.routing-refused")
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.code, self.reason.as_ref().map(|r| format!(" ({r})")).unwrap_or_default())
    }
}

/// A verified inbound profile message.
pub struct Inbound {
    /// Verification output (`signer_did` is the device, `identity` the DID it acts for).
    pub verified: Verified,
}

impl Inbound {
    /// The decoded payload.
    pub fn payload(&self) -> &serde_json::Value {
        &self.verified.payload
    }

    /// Message type.
    pub fn msg_type(&self) -> &str {
        self.verified.msg_type()
    }

    /// The sending device DID.
    pub fn device(&self) -> &str {
        &self.verified.signer_did
    }

    /// The identity the device acts for.
    pub fn identity(&self) -> &str {
        &self.verified.identity
    }
}

/// The identity a device's header delegation proves, for a message that did not arrive on that device's
/// own binding: a deposit forwarded by a mailbox, or an `origin` (M§5.1, M§14.2). The delegation must be
/// for this device and carry `dsip.messaging` (M§6.2).
pub fn delegated_identity(verified: &Verified, ctx: &Context) -> Option<String> {
    verified.header.delegations.iter().find_map(|d| {
        let subject = dsip_core::b64::decode(&d.payload)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|p| p["subject"].as_str().map(String::from))?;
        dsip_core::delegation::verify_delegation_for(d, &subject, &verified.signer_did, "dsip.messaging", ctx)
            .ok()
            .then_some(subject)
    })
}

/// Verify one frame: envelope stages 1–11, then the profile message rules (M§5).
///
/// `hello` is passed through to the caller's binding logic; every other type must be a profile
/// message this service speaks.
pub fn verify_frame(frame: &str, ctx: &Context) -> Result<Inbound, Rejection> {
    let core = |v: dsip_core::Verdict| Rejection {
        code: v.code.and_then(|c| serde_json::to_value(c).ok()).and_then(|c| c.as_str().map(String::from)).unwrap_or_default(),
        reason: v.reason.map(String::from),
    };
    let envelope = Envelope::from_frame(frame).map_err(core)?;
    let verified = envelope::verify(&envelope, ctx, Some(frame)).map_err(core)?;
    if verified.msg_type() != "hello" {
        let v = check_message(&verified.payload);
        if v["verdict"] != "accept" {
            return Err(Rejection {
                code: v["code"].as_str().unwrap_or("schema-invalid").to_string(),
                reason: v["reason"].as_str().map(String::from),
            });
        }
    }
    Ok(Inbound { verified })
}
