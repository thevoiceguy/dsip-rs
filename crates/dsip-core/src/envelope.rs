//! The DSIP-JOSE envelope: construction, signing, and verification stages 1–11.
//!
//! Spec: §10.2 — the signature covers the exact payload bytes; the `kid` is a
//! DID URL resolved through the DID document and delegation credentials
//! (§7.4); Ed25519 MUST, everything else rejected. §12.9 — replay window and
//! id deduplication. §20.6 — ULID/`issued_at` consistency. §13.2 — size cap.
//!
//! The payload is carried as bytes through signature verification and only
//! then decoded. Nothing on the verify path re-serializes JSON.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::b64;
use crate::delegation::check_binding;
use crate::did::{resolve_kid, split_did_url, Resolver, StaticResolver};
use crate::keys::{self, KeyPair};
use crate::ulid::Ulid;
use crate::verdict::{RejectCode, Verdict};
use crate::version::Supported;
use crate::wire::parse_payload;
use crate::{REPLAY_WINDOW_S, ULID_TOLERANCE_S, WS_MAX_ENVELOPE_BYTES};

/// The three-member JWS envelope.
///
/// Spec: §10.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// base64url(protected header JSON).
    pub protected: String,
    /// base64url(payload bytes).
    pub payload: String,
    /// base64url(Ed25519 signature over `protected.payload`).
    pub signature: String,
}

impl Envelope {
    /// The `ws/1.0` text frame for this envelope (compact JSON).
    ///
    /// Spec: §13.2 framing — one envelope per text frame.
    pub fn frame(&self) -> String {
        serde_json::to_string(self).expect("envelope serializes")
    }

    /// Parse an envelope from a text frame. Shape errors become `envelope-shape`.
    pub fn from_frame(text: &str) -> Result<Envelope, Verdict> {
        let v: Value = serde_json::from_str(text).map_err(|_| Verdict::reject(RejectCode::EnvelopeShape))?;
        Envelope::from_value(&v)
    }

    /// Parse from a JSON value (the vector `input.envelope` shape).
    pub fn from_value(v: &Value) -> Result<Envelope, Verdict> {
        serde_json::from_value(v.clone()).map_err(|_| Verdict::reject(RejectCode::EnvelopeShape))
    }
}

/// Protected header fields DSIP reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeader {
    /// MUST be `EdDSA`.
    pub alg: String,
    /// DID URL of the verification method.
    pub kid: String,
    /// Media type hint; `dsip+json` when emitted by this crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Optional delegation credentials presented inline (Impl, spec-gap 8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<Envelope>,
}

/// Compact-encode a JSON payload. Field order is whatever the value holds; the
/// signature covers these bytes, and the receiver never re-derives them.
pub fn encode_payload(payload: &Value) -> Vec<u8> {
    serde_json::to_vec(payload).expect("json serializes")
}

/// Sign raw payload bytes.
///
/// Spec: §10.2. The signing input is the ASCII `protected + "." + payload`.
pub fn sign_bytes(payload: &[u8], signer: &KeyPair, kid: &str, delegations: Vec<Envelope>) -> Envelope {
    let header = ProtectedHeader { alg: "EdDSA".into(), kid: kid.into(), typ: Some("dsip+json".into()), delegations };
    let protected = b64::encode(&serde_json::to_vec(&header).expect("header"));
    let payload = b64::encode(payload);
    let sig = signer.sign(format!("{protected}.{payload}").as_bytes());
    Envelope { protected, payload, signature: b64::encode(&sig) }
}

/// Sign a JSON payload.
pub fn sign(payload: &Value, signer: &KeyPair, kid: &str) -> Envelope {
    sign_bytes(&encode_payload(payload), signer, kid, vec![])
}

/// Receiver-side verification context.
///
/// Spec: §8.1 (resolver is the authority), §7.4 (delegation store), §12.9
/// (clock and seen ids), §11 (supported versions).
pub struct Context<'a> {
    /// Receiver clock, integer seconds.
    pub now: i64,
    /// DID resolver (authoritative).
    pub resolver: &'a dyn Resolver,
    /// Delegations the receiver already holds.
    pub delegations: Vec<Envelope>,
    /// Ids seen within the replay window.
    pub seen_ids: HashSet<String>,
    /// Supported versions/profiles/extensions.
    pub supported: Supported,
}

impl<'a> Context<'a> {
    /// A context over a resolver with no delegations and nothing seen.
    pub fn new(now: i64, resolver: &'a dyn Resolver) -> Context<'a> {
        Context { now, resolver, delegations: vec![], seen_ids: HashSet::new(), supported: Supported::default() }
    }

    /// Build the resolver and context from a vector's `context` object.
    /// Returns the resolver separately because the context borrows it.
    pub fn resolver_from_vector(ctx: &Value) -> StaticResolver {
        StaticResolver::from_json_map(ctx.get("did_documents").unwrap_or(&Value::Null))
    }

    /// Build from a vector's `context` object over a resolver.
    pub fn from_vector(ctx: &Value, resolver: &'a dyn Resolver) -> Context<'a> {
        let delegations = ctx
            .get("delegations")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|d| Envelope::from_value(d).ok()).collect())
            .unwrap_or_default();
        let seen_ids = ctx
            .get("seen_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        Context {
            now: ctx.get("now").and_then(Value::as_i64).unwrap_or(0),
            resolver,
            delegations,
            seen_ids,
            supported: Supported::from_json(ctx.get("supported")),
        }
    }
}

/// Output of a successful verification.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Parsed protected header.
    pub header: ProtectedHeader,
    /// Decoded payload.
    pub payload: Value,
    /// The exact payload bytes that were signed.
    pub payload_bytes: Vec<u8>,
    /// DID part of `kid`.
    pub signer_did: String,
    /// The DID the signer acts for (`from`, or `on_behalf_of` on `hello`). Set by [`verify`].
    pub identity: String,
}

impl Verified {
    /// The payload `type`.
    pub fn msg_type(&self) -> &str {
        self.payload.get("type").and_then(Value::as_str).unwrap_or("")
    }
}

/// Stages 2–6: shape, header, kid resolution, signature, payload parse. No binding, no timing.
///
/// `core_shape=false` is for delegation credentials.
pub fn verify_raw(env: &Envelope, ctx: &Context, core_shape: bool) -> Result<Verified, Verdict> {
    let shape = || Verdict::reject(RejectCode::EnvelopeShape);
    let prot = b64::decode(&env.protected).ok_or_else(shape)?;
    let pay = b64::decode(&env.payload).ok_or_else(shape)?;
    let sig = b64::decode(&env.signature).ok_or_else(shape)?;
    let header: ProtectedHeader = serde_json::from_slice::<Value>(&prot)
        .ok()
        .filter(|h| h.get("alg").is_some_and(Value::is_string) && h.get("kid").is_some_and(Value::is_string))
        .and_then(|h| serde_json::from_value(h).ok())
        .ok_or_else(|| Verdict::reject(RejectCode::HeaderInvalid))?;
    if header.alg != "EdDSA" {
        // §10.2: Ed25519 MUST; ES256 MAY (not implemented); all others MUST be rejected.
        return Err(Verdict::reject(RejectCode::AlgUnsupported));
    }
    let (signer_did, _) = split_did_url(&header.kid).ok_or_else(|| Verdict::reject(RejectCode::KidInvalid))?;
    let signer_did = signer_did.to_string();
    let pk = resolve_kid(&header.kid, ctx.resolver).ok_or_else(|| Verdict::reject(RejectCode::KidUnresolvable))?;
    let signing_input = format!("{}.{}", env.protected, env.payload);
    if sig.len() != 64 || !keys::verify(&pk, signing_input.as_bytes(), &sig) {
        return Err(Verdict::reject(RejectCode::SignatureInvalid));
    }
    let payload = parse_payload(&pay, core_shape)?;
    Ok(Verified { header, payload, payload_bytes: pay, signer_did: signer_did.clone(), identity: signer_did })
}

/// Stages 1–11 of the pipeline (see `impl/vectors/README.md`).
///
/// `frame` is the text frame when the envelope arrived over `ws/1.0` (size cap, §13.2).
pub fn verify(env: &Envelope, ctx: &Context, frame: Option<&str>) -> Result<Verified, Verdict> {
    if let Some(f) = frame {
        if f.len() > WS_MAX_ENVELOPE_BYTES {
            return Err(Verdict::reject_with(RejectCode::FrameTooLarge, "transport.envelope-too-large"));
        }
    }
    let mut ver = verify_raw(env, ctx, true)?;
    let p = &ver.payload;
    let msg_type = ver.msg_type().to_string();
    let from = p["from"].as_str().expect("core shape").to_string();
    let hello = msg_type == "hello";
    let with_hello_reason = |v: Verdict| if hello { Verdict { reason: Some("transport.hello-rejected"), ..v } } else { v };

    // Stage 7: bind kid → from (→ on_behalf_of on hello)
    let mut presented = ctx.delegations.clone();
    presented.extend(ver.header.delegations.iter().cloned());
    let b = check_binding(&from, &ver.signer_did, &presented, ctx);
    if !b.ok() {
        return Err(with_hello_reason(b));
    }
    let mut identity = from.clone();
    if hello {
        if let Some(obo) = p.get("on_behalf_of").and_then(Value::as_str) {
            let b = check_binding(obo, &from, &presented, ctx);
            if !b.ok() {
                return Err(with_hello_reason(b));
            }
            identity = obo.to_string();
        }
    }

    // Stages 8–9: expiry ordering, replay window, expiry
    let (ia, ea) = (p["issued_at"].as_i64().expect("shape"), p["expires_at"].as_i64().expect("shape"));
    if ea <= ia {
        return Err(Verdict::reject(RejectCode::ExpiryOrder));
    }
    if ia < ctx.now - REPLAY_WINDOW_S || ia > ctx.now + REPLAY_WINDOW_S {
        // Impl (spec-gap 7): symmetric window
        return Err(Verdict::reject(RejectCode::ReplayWindow));
    }
    if ea < ctx.now {
        return Err(if msg_type == "invite" {
            Verdict::reject_with(RejectCode::Expired, "session.expired")
        } else {
            Verdict::reject(RejectCode::Expired)
        });
    }
    // Stage 10: dedup
    let id = p["id"].as_str().expect("shape");
    if ctx.seen_ids.contains(id) {
        return Err(Verdict::reject(RejectCode::DuplicateId));
    }
    // Stage 11: ULID timestamp vs issued_at (§20.6)
    let ulid = Ulid::parse(id).expect("shape");
    if (ulid.timestamp_s() - ia).abs() > ULID_TOLERANCE_S {
        return Err(Verdict::reject(RejectCode::UlidIssuedAtMismatch));
    }
    ver.identity = identity;
    Ok(ver)
}

/// The accept-side `expect` extras for a verified envelope (`type`, `signer`, `identity`).
pub fn accept_verdict(ver: &Verified) -> Verdict {
    Verdict::accept()
        .with("type", ver.msg_type())
        .with("signer", ver.signer_did.as_str())
        .with("identity", ver.identity.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip_did_key() {
        let k = KeyPair::from_fixture_name("alice-phone");
        let id = Ulid::from_parts(1_760_000_000_000, [0; 10]);
        let payload = serde_json::json!({
            "dsip": {"core":"1.0","min_core":"1.0","profiles":[],"extensions":[],"critical":[]},
            "type": "hello", "id": id.as_str(), "from": k.did(), "bindings": ["ws/1.0"],
            "issued_at": 1_760_000_000, "expires_at": 1_760_000_030,
        });
        let env = sign(&payload, &k, &k.kid());
        let resolver = StaticResolver::default();
        let ctx = Context::new(1_760_000_001, &resolver);
        let ver = verify(&env, &ctx, Some(&env.frame())).expect("valid");
        assert_eq!(ver.identity, k.did());
        let mut bad = env.clone();
        bad.payload.push('A');
        assert_eq!(verify(&bad, &ctx, None).unwrap_err().code, Some(RejectCode::SignatureInvalid));
    }
}
