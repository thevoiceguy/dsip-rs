//! `hello` construction and relay-`hello` verification, shared by native and browser endpoints.
//!
//! Spec: §13.2 — the first envelope on a connection MUST be a client `hello`;
//! the relay's `hello` MUST echo the client id in `in_reply_to` (§20.5) and
//! carry `capabilities.max_envelope_bytes = 65536`.

use serde_json::{json, Value};

use dsip_core::did::Resolver;
use dsip_core::envelope::{sign_bytes, Envelope};
use dsip_core::version::{version_block, Supported};
use dsip_core::Verdict;
use dsip_schema::SemanticContext;

use crate::core::IdentityKeys;
use crate::verify::{verify_frame, SeenIds};

/// The binding identifier.
pub const BINDING: &str = "ws/1.0";

/// Build and sign a client `hello` (`on_behalf_of` = our identity, delegation inline). Returns (id, envelope).
pub fn client_hello(keys: &IdentityKeys, supported: &Supported, id: &str, now: i64) -> Envelope {
    let hello = json!({
        "dsip": version_block(supported, &[]),
        "type": "hello", "id": id, "from": keys.device.did(), "on_behalf_of": keys.identity,
        "bindings": [BINDING], "issued_at": now, "expires_at": now + 30,
    });
    sign_bytes(&serde_json::to_vec(&hello).expect("json"), &keys.device, &keys.device.kid(), vec![keys.delegation.clone()])
}

/// What a verified relay `hello` tells us.
#[derive(Debug, Clone)]
pub struct RelayHello {
    /// Relay identity DID.
    pub did: String,
    /// Advertised capabilities.
    pub capabilities: Value,
}

/// Verify the relay's `hello` against the client hello id we sent (anti-splicing, §20.5).
pub fn verify_relay_hello(
    frame: &str,
    sent_id: &str,
    now: i64,
    resolver: &dyn Resolver,
    seen: &mut SeenIds,
    supported: &Supported,
) -> Result<RelayHello, Verdict> {
    let sem = SemanticContext { supported: supported.clone(), sent_hello_id: Some(sent_id.to_string()), ..Default::default() };
    let inbound = verify_frame(frame, now, resolver, &[], seen, &sem)?;
    if inbound.verified.msg_type() != "hello" {
        return Err(Verdict::reject_with(dsip_core::RejectCode::HelloRequired, "transport.hello-required"));
    }
    Ok(RelayHello { did: inbound.verified.identity.clone(), capabilities: inbound.verified.payload["capabilities"].clone() })
}
