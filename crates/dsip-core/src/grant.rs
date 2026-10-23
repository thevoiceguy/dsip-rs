//! A presented grant, verified as a credential (§19.4): the grantee holds the signed grant and presents it where a
//! grant is checked — a mailbox's `key-package-fetch` (M§14.2), a presence `subscribe` (P§6).
//!
//! Spec: §19.4, §7.4, M§14.2, P§6.

use serde_json::Value;

use crate::envelope::{self, Context, Envelope};

/// Verify a presented grant: its signature, and the binding of the signing device to the grant's `from` through a
/// delegation in its header (§7.4). Its replay window and delivery expiry do not apply — it is presented long after its
/// delivery (§19.4) — and liveness (`valid_until`, revocation) is the caller's rule. Returns the payload with `from`
/// set to the granting identity, or `None`.
///
/// Spec: §19.4, §7.4, M§14.2, P§6. Impl: a core endpoint names its device in `from` and acts for the identity its
/// delegation binds it to (§13.2, §7.4); the granter is that identity, taken from the delegation presented in the
/// header, so the grant reads the same as one whose `from` is the identity (the console's).
pub fn credential(env: &Envelope, ctx: &Context) -> Option<Value> {
    let ver = envelope::verify_raw(env, ctx, false).ok()?;
    let from = ver.payload.get("from")?.as_str()?;
    if !crate::delegation::check_binding(from, &ver.signer_did, &ver.header.delegations, ctx).ok() {
        return None;
    }
    let mut payload = ver.payload.clone();
    if from == ver.signer_did {
        let identity = ver.header.delegations.iter().find_map(|d| {
            let (subject, device) = crate::delegation::names(d)?;
            (device == ver.signer_did && crate::delegation::verify_delegation(d, &subject, &device, ctx).ok()).then_some(subject)
        });
        if let Some(id) = identity {
            payload["from"] = Value::String(id);
        }
    }
    (payload.get("type")? == "grant").then_some(payload)
}

/// [`credential`] for a compact serialization (`protected.payload.signature`), as a grantee keeps its grants.
pub fn credential_compact(compact: &str, ctx: &Context) -> Option<Value> {
    let mut parts = compact.split('.');
    let env = Envelope { protected: parts.next()?.to_string(), payload: parts.next()?.to_string(), signature: parts.next()?.to_string() };
    credential(&env, ctx)
}
