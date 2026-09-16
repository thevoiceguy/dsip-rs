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

/// A presented grant, verified as a credential: its signature, and the binding of the signing device to the grant's
/// `from` through a delegation in its header (§7.4). Its replay window does not apply — it is presented after its
/// delivery (§19.4) — and liveness (`valid_until`, revocation) is the caller's rule. The payload, or `None`.
///
/// Spec: §19.4, §7.4, M§14.2. Impl: before this check was added a grant signed by any device was accepted as
/// consent from the identity it named.
pub fn grant_credential(compact: &str, ctx: &Context) -> Option<serde_json::Value> {
    let mut parts = compact.split('.');
    let env = Envelope { protected: parts.next()?.to_string(), payload: parts.next()?.to_string(), signature: parts.next()?.to_string() };
    let ver = envelope::verify_raw(&env, ctx, false).ok()?;
    let from = ver.payload.get("from")?.as_str()?;
    if !dsip_core::delegation::check_binding(from, &ver.signer_did, &ver.header.delegations, ctx).ok() {
        return None;
    }
    (ver.payload.get("type")? == "grant").then(|| ver.payload.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsip_core::delegation::delegation_payload;
    use dsip_core::did::StaticResolver;
    use dsip_core::envelope::{encode_payload, sign, sign_bytes};
    use dsip_core::keys::KeyPair;
    use serde_json::json;

    const NOW: i64 = 1_790_000_000;

    fn grant(from: &str) -> serde_json::Value {
        json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": []},
               "type": "grant", "id": "01M2NE6VSRPZKD9QDNPW24DYCT", "from": from, "to": "did:web:alice.example",
               "session": "01M2NE6VSRPZKD9QDNPW24DYCT", "scope": ["dsip.message"], "valid_until": NOW + 86400,
               "issued_at": NOW, "expires_at": NOW + 30})
    }

    #[test]
    fn only_a_device_delegated_by_the_granter_can_grant() {
        let bob = KeyPair::from_fixture_name("bob");
        let bob_phone = KeyPair::from_fixture_name("bob-phone");
        let mallory_phone = KeyPair::from_fixture_name("mallory");
        let mut resolver = StaticResolver::default();
        resolver.insert(dsip_core::did::DidDocument::minimal_web("did:web:bob.example", &bob.public(), None));
        let ctx = Context::new(NOW, &resolver);
        let deleg_caps = |device: &KeyPair, caps: &[&str]| {
            sign(&delegation_payload("did:web:bob.example", &device.did(), NOW - 60, NOW + 86400, caps), &bob, "did:web:bob.example#key-1")
        };
        let deleg = |device: &KeyPair| deleg_caps(device, &["dsip.signaling", "dsip.messaging"]);
        let compact = |e: Envelope| format!("{}.{}.{}", e.protected, e.payload, e.signature);

        let honest = sign_bytes(&encode_payload(&grant("did:web:bob.example")), &bob_phone, &bob_phone.kid(), vec![deleg(&bob_phone)]);
        assert!(grant_credential(&compact(honest), &ctx).is_some(), "Bob's delegated phone grants for Bob");

        let bare = sign(&grant("did:web:bob.example"), &bob_phone, &bob_phone.kid());
        assert!(grant_credential(&compact(bare), &ctx).is_none(), "no delegation presented: not Bob's consent");

        let forged = sign_bytes(&encode_payload(&grant("did:web:bob.example")), &mallory_phone, &mallory_phone.kid(), vec![deleg(&bob_phone)]);
        assert!(grant_credential(&compact(forged), &ctx).is_none(), "a delegation for another device does not bind Mallory's key");

        // spec-gap 56 (open): core §7.4 binds every envelope under `dsip.signaling`, so a device delegated for
        // messaging only cannot grant today. This pins the current behavior until the v0.8 core decides.
        let messaging_only = sign_bytes(&encode_payload(&grant("did:web:bob.example")), &bob_phone, &bob_phone.kid(),
            vec![deleg_caps(&bob_phone, &["dsip.messaging"])]);
        assert!(grant_credential(&compact(messaging_only), &ctx).is_none(), "messaging-only delegation: refused under core §7.4 today");
    }
}
