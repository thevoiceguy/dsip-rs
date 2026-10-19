//! Which of a directory's KeyPackages to add: every one that authenticates, then the vector-pinned selection.
//!
//! Spec: M§5.5 (one KeyPackage per device, the last-resort one included), M§6.2 (each leaf authenticated before
//! use), C§5 (never this device, never only recorders for someone else, never a recorder for the personal group:
//! `dsip_recording::add_devices`, `check: "add-devices"`).

use dsip_core::envelope::Context;
use dsip_messaging::mls_wire::LeafIdentity;
use openmls::prelude::KeyPackage;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

/// Who is choosing: this device and its identity.
pub struct Me<'a> {
    /// This device's identity DID.
    pub identity: &'a str,
    /// This device's DID.
    pub device: &'a str,
}

/// The KeyPackages to add for `target` from a `key-packages` payload (the caller has checked its `type`), each with
/// the bytes it came as; `purpose` is `conversation` or `personal`. `Err` carries the C§5 refusal token.
pub fn select<P: OpenMlsProvider>(payload: &Value, target: &str, me: &Me, purpose: &str, provider: &P, ctx: &Context)
    -> Result<Vec<(Vec<u8>, KeyPackage)>, String> {
    let mut found: Vec<(Vec<u8>, KeyPackage, LeafIdentity)> = vec![];
    let candidates = payload["key_packages"].as_array().cloned().unwrap_or_default().into_iter().chain(payload.get("last_resort").cloned());
    for c in candidates {
        let bytes = c.as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
        if let Ok((kp, who)) = dsip_mls::authenticate_key_package(&bytes, provider, ctx) {
            found.push((bytes, kp, who));
        }
    }
    let listed: Vec<Value> = found.iter().map(|(_, _, w)| json!({"device": w.device, "identity": w.identity, "capabilities": w.capabilities})).collect();
    let pick = dsip_recording::add_devices(&json!({"target": target, "self_identity": me.identity, "self_device": me.device,
        "purpose": purpose, "key_packages": listed}));
    if let Some(why) = pick["refused"].as_str() {
        return Err(why.to_string());
    }
    let mut out = vec![];
    for d in pick["add"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if let Some(i) = found.iter().position(|(_, _, w)| w.device == d) {
            let (bytes, kp, _) = found.swap_remove(i);
            out.push((bytes, kp));
        }
    }
    Ok(out)
}
