//! Sealed bodies: stage 12b of the receive pipeline, and sealing for senders.
//!
//! Spec: §10.4 (extension `sealed-body/1.0`; spec-gap 97) — a type's sealable fields travel in `sealed`, HPKE-sealed
//! to the addressee identity's X25519 key agreement key with `info` = `dsip sealed body v1` and AAD
//! `type ‖ 0x00 ‖ id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`; the plaintext is a §10.3 JSON object padded with spaces to a
//! multiple of 256 bytes; the payload lists `sealed-body/1.0` in `dsip.extensions` and `dsip.critical`. The addressee
//! opens it after the version check and before schema validation ([`open`]); a router never does.

use serde_json::{Map, Value};

use dsip_core::hpke::{hpke_open, hpke_seal, x25519_public, ALG};
use dsip_core::{b64, wire, RejectCode, Verdict};

/// The extension identifier.
///
/// Spec: §10.4.
pub const EXT: &str = "sealed-body/1.0";
/// HPKE `info` for sealed bodies.
///
/// Spec: §10.4.
pub const INFO: &[u8] = b"dsip sealed body v1";
/// Plaintext lengths are a positive multiple of this many bytes.
///
/// Spec: §10.4.
pub const PAD: usize = 256;

/// The fields of `msg_type` that may travel sealed; empty for a type that cannot be sealed.
///
/// Spec: §10.4 table — the fields no routing rule reads.
pub fn sealable(msg_type: &str) -> &'static [&'static str] {
    match msg_type {
        "invite" => &["identity", "intent", "policy", "media", "transports"],
        "answer" | "update" => &["answered_by", "media", "policy", "transports"],
        "info" => &["about", "data"],
        "reject" | "cancel" | "bye" => &["detail"],
        _ => &[],
    }
}

/// The AAD binding a seal to its message: `type ‖ 0x00 ‖ id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`.
///
/// Spec: §10.4.
pub fn aad(p: &Value) -> Vec<u8> {
    let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").as_bytes().to_vec();
    [s("type"), s("id"), s("from"), s("to")].join(&0u8)
}

/// Stage 12b: open `sealed` with the addressee's X25519 secret and merge it into the clear fields.
///
/// Returns the merged payload and the opened keys (sorted), or the first failing condition: `sealed-not-critical` →
/// `sealed-alg-unsupported` → `body-unseal-failed` → `sealed-plaintext-invalid` → `sealed-field-not-sealable` →
/// `sealed-field-in-clear`. A `sealed` that is not an object of three strings, or a payload whose `type`, `id`,
/// `from` or `to` (the AAD inputs) is not a string, is returned unopened for the schema stage to reject.
///
/// Spec: §10.4 "Receiving".
pub fn open(payload: &Value, sk: &[u8; 32]) -> Result<(Value, Vec<String>), Verdict> {
    let sealed = &payload["sealed"];
    let field = |k: &str| sealed.get(k).and_then(Value::as_str);
    let aad_inputs = ["type", "id", "from", "to"].iter().all(|k| payload.get(*k).is_some_and(Value::is_string));
    let (Some(alg), Some(enc), Some(ct), true) = (field("alg"), field("enc"), field("ct"), aad_inputs) else {
        // §10.4: not opened — schema validation rejects the shape
        return Ok((payload.clone(), vec![]));
    };
    let critical = payload.pointer("/dsip/critical").and_then(Value::as_array);
    if !critical.is_some_and(|c| c.iter().any(|e| e == EXT)) {
        return Err(Verdict::reject(RejectCode::SealedNotCritical));
    }
    if alg != ALG {
        return Err(Verdict::reject(RejectCode::SealedAlgUnsupported));
    }
    let opened = b64::decode(enc).zip(b64::decode(ct)).and_then(|(e, c)| hpke_open(&e, sk, INFO, &aad(payload), &c));
    let Some(pt) = opened else {
        return Err(Verdict::reject(RejectCode::BodyUnsealFailed));
    };
    let body = match wire::parse_payload(&pt, false) {
        Ok(Value::Object(m)) if !m.is_empty() && pt.len() % PAD == 0 => m,
        _ => return Err(Verdict::reject(RejectCode::SealedPlaintextInvalid)),
    };
    let allowed = sealable(payload["type"].as_str().unwrap_or(""));
    if body.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Verdict::reject(RejectCode::SealedFieldNotSealable));
    }
    if body.keys().any(|k| payload.get(k).is_some()) {
        return Err(Verdict::reject(RejectCode::SealedFieldInClear));
    }
    let mut merged: Map<String, Value> = payload.as_object().cloned().unwrap_or_default();
    merged.remove("sealed");
    let mut keys: Vec<String> = body.keys().cloned().collect();
    keys.sort();
    merged.extend(body);
    Ok((Value::Object(merged), keys))
}

/// Seal every sealable field present in `payload` to the addressee key `pk_r`, as a §10.4 sender.
///
/// Moves the fields into `sealed`, pads the plaintext and lists the extension in `dsip.extensions` and `dsip.critical`.
/// A payload with nothing sealable is left unchanged. Call it before signing: the signature must cover `sealed`.
///
/// Spec: §10.4 "Construction". Impl: callers pass a fresh random `sk_e`.
pub fn seal(payload: &mut Value, pk_r: &[u8; 32], sk_e: &[u8; 32]) {
    let allowed = sealable(payload["type"].as_str().unwrap_or(""));
    let Some(obj) = payload.as_object_mut() else { return };
    let body: Map<String, Value> = allowed.iter().filter_map(|k| obj.remove(*k).map(|v| (k.to_string(), v))).collect();
    if body.is_empty() {
        return;
    }
    let mut pt = serde_json::to_vec(&body).expect("json");
    pt.resize(pt.len().div_ceil(PAD) * PAD, b' ');
    let (enc, ct) = hpke_seal(pk_r, INFO, &aad(&Value::Object(obj.clone())), &pt, sk_e);
    obj.insert("sealed".into(), serde_json::json!({"alg": ALG, "enc": b64::encode(&enc), "ct": b64::encode(&ct)}));
    for list in ["extensions", "critical"] {
        if let Some(Value::Array(a)) = obj.get_mut("dsip").and_then(|d| d.get_mut(list)) {
            if !a.iter().any(|e| e == EXT) {
                a.push(EXT.into());
            }
        }
    }
}

/// The X25519 public key a sender seals to, from the addressee's secret (tests and `did:key` derivation).
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    x25519_public(sk)
}
