//! Device delegation credentials.
//!
//! Spec: §7.4 — a DID document or credential states that a device DID may act
//! for a subject DID with listed capabilities between `issued_at` and
//! `expires_at`. Session messages are signed by device keys, so every verifier
//! needs this check.
//!
//! Impl (spec-gap 8): a delegation is a DSIP-JOSE envelope over the
//! `DeviceDelegation` object, signed *directly* by a key of the subject (no
//! chains). Verifiers accept delegations from a local store and from the
//! envelope protected header's optional `delegations` array.

use serde_json::Value;

use crate::envelope::{verify_raw, Context, Envelope};
use crate::verdict::{RejectCode, Verdict};

/// The capability a device needs to sign session messages.
pub const SIGNALING_CAPABILITY: &str = "dsip.signaling";

/// Build the `DeviceDelegation` payload (§7.4 shape).
pub fn delegation_payload(subject: &str, device: &str, issued_at: i64, expires_at: i64, capabilities: &[&str]) -> Value {
    serde_json::json!({
        "type": "DeviceDelegation",
        "subject": subject,
        "device": device,
        "capabilities": capabilities,
        "issued_at": issued_at,
        "expires_at": expires_at,
    })
}

/// `(subject, device)` named by a delegation envelope, without verifying it.
pub fn names(deleg: &Envelope) -> Option<(String, String)> {
    let raw = crate::b64::decode(&deleg.payload)?;
    let p: Value = serde_json::from_slice(&raw).ok()?;
    Some((p.get("subject")?.as_str()?.to_string(), p.get("device")?.as_str()?.to_string()))
}

/// Verify that `deleg` authorizes `device` to act for `subject` at `ctx.now`.
///
/// Spec: §7.4. Checks, in order: envelope validity (signature over bytes),
/// `type`/`subject`/`device` match, signer is the subject itself,
/// `dsip.signaling` present, `issued_at ≤ now < expires_at`.
/// §7.5 — a delegation signed by a key the subject's document no longer lists fails the
/// first check ("device list update" is implied by rotation; vector
/// `envelope/rotated-did-web-old-key-delegation-rejected`).
pub fn verify_delegation(deleg: &Envelope, subject: &str, device: &str, ctx: &Context) -> Verdict {
    verify_delegation_for(deleg, subject, device, SIGNALING_CAPABILITY, ctx)
}

/// [`verify_delegation`] requiring an arbitrary capability instead of `dsip.signaling`.
///
/// Spec: §7.4; Messaging Profile M§6.2 — an MLS leaf requires `dsip.messaging` (spec-gap 39).
pub fn verify_delegation_for(deleg: &Envelope, subject: &str, device: &str, capability: &str, ctx: &Context) -> Verdict {
    let ver = match verify_raw(deleg, ctx, false) {
        Ok(v) => v,
        Err(v) => return Verdict::reject(RejectCode::DelegationInvalid).detail(format!("{:?}", v.code)),
    };
    let p = &ver.payload;
    let s = |k: &str| p.get(k).and_then(Value::as_str);
    if s("type") != Some("DeviceDelegation") || s("subject") != Some(subject) || s("device") != Some(device)
        || ver.signer_did != subject
    {
        return Verdict::reject(RejectCode::DelegationInvalid);
    }
    let has_cap = p
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|c| c.iter().any(|x| x == capability));
    if !has_cap {
        return Verdict::reject(RejectCode::DelegationCapability);
    }
    let issued_at = match (p.get("issued_at").and_then(Value::as_i64), p.get("expires_at").and_then(Value::as_i64)) {
        (Some(ia), Some(ea)) if ia <= ctx.now && ctx.now < ea => ia,
        _ => return Verdict::reject(RejectCode::DelegationExpired),
    };
    if revocations_for(subject, ctx).iter().any(|r| revokes(r, subject, device, issued_at, ctx)) {
        return Verdict::reject(RejectCode::DelegationRevoked);
    }
    Verdict::accept()
}

/// Every revocation a verifier can see for `subject`: those it holds and those the subject's DID document publishes.
///
/// Spec: v0.8 draft (spec-gap 57); §8.1 — the document is authoritative. Impl: a validly signed revocation only
/// removes authority, so a held one counts as well.
pub fn revocations_for(subject: &str, ctx: &Context) -> Vec<Envelope> {
    let mut out = ctx.revocations.clone();
    if let Some(doc) = ctx.resolver.resolve(subject) {
        out.extend(doc.delegation_revocations.iter().filter_map(|c| {
            let mut parts = c.split('.');
            Some(Envelope { protected: parts.next()?.to_string(), payload: parts.next()?.to_string(), signature: parts.next()?.to_string() })
        }));
    }
    out
}

/// Whether a `delegation-revocation` revokes `device`'s delegation for `subject` issued at `delegation_issued_at`.
///
/// Spec: v0.8 draft (spec-gap 57) — signed directly by a key of the subject, `from` = `subject`, covering delegations
/// issued at or before `revoked_at`. The record is a credential: no delivery window applies.
pub fn revokes(rev: &Envelope, subject: &str, device: &str, delegation_issued_at: i64, ctx: &Context) -> bool {
    let Ok(ver) = verify_raw(rev, ctx, false) else { return false };
    let p = &ver.payload;
    p["type"] == "delegation-revocation"
        && p["subject"] == subject
        && p["from"] == subject
        && ver.signer_did == subject
        && p["device"] == device
        && p["revoked_at"].as_i64().is_some_and(|t| delegation_issued_at <= t)
}

/// Is `device` authorized to act for `subject`? Direct when equal; otherwise via a presented delegation.
///
/// Spec: §7.4, §10.2 (`kid` resolves to the `from` DID or a valid delegation).
/// With several candidates, any valid one accepts; otherwise the first candidate's failure is reported.
pub fn check_binding(subject: &str, device: &str, presented: &[Envelope], ctx: &Context) -> Verdict {
    if subject == device {
        return Verdict::accept();
    }
    let mut first_failure: Option<Verdict> = None;
    let mut any = false;
    for d in presented {
        if names(d).as_ref().map(|(s, dv)| (s.as_str(), dv.as_str())) != Some((subject, device)) {
            continue;
        }
        any = true;
        let v = verify_delegation(d, subject, device, ctx);
        if v.ok() {
            return v;
        }
        first_failure.get_or_insert(v);
    }
    if !any {
        return Verdict::reject(RejectCode::SignerMismatch);
    }
    first_failure.expect("set when any")
}
