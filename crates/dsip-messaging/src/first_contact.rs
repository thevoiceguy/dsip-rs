//! First contact for messaging: sealed introductions (HPKE) and how introductions and grants reach a mailbox.
//!
//! Spec: M§6.9 (HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM; the recipient key is the
//! identity's X25519 key agreement key, derived from Ed25519 as `did:key` defines — [`x25519_from_ed25519_seed`]),
//! M§14.1 (`sealed` replaces `purpose`, `info` = `"dsip sealed introduction v1"`, AAD `id ‖ 0 ‖ from ‖ 0 ‖ to`,
//! never both — [`check_introduction`], [`seal_introduction`], [`open_sealed_introduction`]), core §19.4.
//!
//! Impl: RFC 9180 is implemented here from its definition (single-shot base mode, sequence 0), so that vectors can
//! pin it byte for byte; it is anchored by the RFC's own Appendix A.1.1 test vector (`messaging/hpke-open-rfc9180-*`)
//! and cross-checked against `hpke-rs` in `dsip-mls`. Introductions and grants for messaging identities travel as
//! mailbox deposits (spec-gap 54, [`crate::mailbox`]); a `did:web` identity's devices hold its key agreement key
//! (spec-gap 55).

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes128Gcm;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::checks::{accept_effective, reject};

/// The only sealing algorithm of 1.0.
///
/// Spec: M§6.9, M§14.1.
pub const SEALED_ALG: &str = "hpke-base-x25519-sha256-aes128gcm";
/// HPKE `info` for sealed introductions.
///
/// Spec: M§14.1.
pub const SEALED_INFO: &[u8] = b"dsip sealed introduction v1";
/// `purpose` length bound, in characters.
///
/// Spec: §19.4.
pub const PURPOSE_MAX_CHARS: usize = 280;

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;

fn kem_suite() -> Vec<u8> {
    [b"KEM".as_slice(), &KEM_ID.to_be_bytes()].concat()
}

fn hpke_suite() -> Vec<u8> {
    [b"HPKE".as_slice(), &KEM_ID.to_be_bytes(), &KDF_ID.to_be_bytes(), &AEAD_ID.to_be_bytes()].concat()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite: &[u8]) -> [u8; 32] {
    let zero = [0u8; 32];
    hmac(if salt.is_empty() { &zero } else { salt }, &[b"HPKE-v1", suite, label, ikm])
}

fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], n: usize, suite: &[u8]) -> Vec<u8> {
    let labeled = [&(n as u16).to_be_bytes()[..], b"HPKE-v1", suite, label, info].concat();
    let (mut out, mut t, mut i) = (Vec::new(), Vec::new(), 1u8);
    while out.len() < n {
        t = hmac(prk, &[&t, &labeled, &[i]]).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(n);
    out
}

/// The X25519 public key of a secret.
pub fn x25519_public(sk: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*sk)).to_bytes()
}

fn shared_secret(dh: &[u8; 32], enc: &[u8], pk_r: &[u8]) -> Vec<u8> {
    let prk = labeled_extract(&[], b"eae_prk", dh, &kem_suite());
    labeled_expand(&prk, b"shared_secret", &[enc, pk_r].concat(), 32, &kem_suite())
}

fn key_schedule(shared: &[u8], info: &[u8]) -> ([u8; 16], [u8; 12]) {
    let suite = hpke_suite();
    let ctx = [&[0u8][..], &labeled_extract(&[], b"psk_id_hash", &[], &suite), &labeled_extract(&[], b"info_hash", info, &suite)].concat();
    let secret = labeled_extract(shared, b"secret", &[], &suite);
    let key = labeled_expand(&secret, b"key", &ctx, 16, &suite).try_into().expect("16");
    let nonce = labeled_expand(&secret, b"base_nonce", &ctx, 12, &suite).try_into().expect("12");
    (key, nonce)
}

/// RFC 9180 §7.1.3 DeriveKeyPair for X25519: the secret key from input keying material.
///
/// Spec: M§6.9.
pub fn hpke_derive_sk(ikm: &[u8]) -> [u8; 32] {
    let prk = labeled_extract(&[], b"dkp_prk", ikm, &kem_suite());
    labeled_expand(&prk, b"sk", &[], 32, &kem_suite()).try_into().expect("32")
}

/// HPKE base-mode single-shot seal with the ephemeral secret supplied: `(enc, ct)`.
///
/// Spec: M§6.9. Impl: callers pass a fresh random `sk_e`; vectors pass a fixed one.
pub fn hpke_seal(pk_r: &[u8; 32], info: &[u8], aad: &[u8], pt: &[u8], sk_e: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let secret = StaticSecret::from(*sk_e);
    let enc = PublicKey::from(&secret).to_bytes();
    let dh = secret.diffie_hellman(&PublicKey::from(*pk_r)).to_bytes();
    let (key, nonce) = key_schedule(&shared_secret(&dh, &enc, pk_r), info);
    let ct = Aes128Gcm::new(&key.into()).encrypt(Nonce::<Aes128Gcm>::from_slice(&nonce), Payload { msg: pt, aad }).expect("aes-gcm");
    (enc, ct)
}

/// HPKE base-mode single-shot open; `None` when it does not open.
///
/// Spec: M§6.9.
pub fn hpke_open(enc: &[u8], sk_r: &[u8; 32], info: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let enc: [u8; 32] = enc.try_into().ok()?;
    let secret = StaticSecret::from(*sk_r);
    let pk_r = PublicKey::from(&secret).to_bytes();
    let dh = secret.diffie_hellman(&PublicKey::from(enc)).to_bytes();
    let (key, nonce) = key_schedule(&shared_secret(&dh, &enc, &pk_r), info);
    Aes128Gcm::new(&key.into()).decrypt(Nonce::<Aes128Gcm>::from_slice(&nonce), Payload { msg: ct, aad }).ok()
}

/// The X25519 key agreement secret of an Ed25519 key: the first 32 bytes of SHA-512 of its seed (clamped by X25519).
///
/// Spec: M§6.9 — "as the did:key method defines". Impl (spec-gap 55): a `did:web` identity's messaging devices
/// derive the same key from the identity key they hold.
pub fn x25519_from_ed25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    Sha512::digest(seed)[..32].try_into().expect("32")
}

/// The AAD binding a sealed body to its introduction: `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`.
///
/// Spec: M§14.1.
pub fn sealed_aad(p: &Value) -> Vec<u8> {
    let s = |k: &str| p[k].as_str().unwrap_or("").as_bytes().to_vec();
    [s("id"), vec![0], s("from"), vec![0], s("to")].concat()
}

/// An introduction under the profile: the core §19.4 shape plus `sealed`, never both `purpose` and `sealed`.
///
/// Spec: M§14.1.
pub fn check_introduction(p: &Value) -> Value {
    // The core v0.8 introduction schema carries `sealed` (§19.4).
    if dsip_schema::validate::validate_against("introduction", p).is_err() {
        return reject("schema-invalid", None);
    }
    if p.get("purpose").is_some() && p.get("sealed").is_some() {
        return reject("introduction-purpose-and-sealed", None);
    }
    if p.get("sealed").is_some_and(|s| s["alg"] != SEALED_ALG) {
        return reject("sealed-alg-unsupported", None);
    }
    accept_effective(json!({"sealed": p.get("sealed").is_some()}))
}

/// Seal `purpose` into an introduction payload for the recipient's X25519 key (M§14.1).
pub fn seal_introduction(p: &mut Value, purpose: &str, pk_r: &[u8; 32], sk_e: &[u8; 32]) {
    let (enc, ct) = hpke_seal(pk_r, SEALED_INFO, &sealed_aad(p), &serde_json::to_vec(&json!({"purpose": purpose})).expect("json"), sk_e);
    if let Some(m) = p.as_object_mut() {
        m.remove("purpose");
    }
    p["sealed"] = json!({"alg": SEALED_ALG, "enc": dsip_core::b64::encode(&enc), "ct": dsip_core::b64::encode(&ct)});
}

/// Check an introduction and, if sealed, open it with the recipient's Ed25519 identity seed: `accept` with `purpose`.
///
/// Spec: M§14.1, M§6.9.
pub fn open_sealed_introduction(p: &Value, recipient_seed: &[u8; 32]) -> Value {
    let v = check_introduction(p);
    if v["verdict"] != "accept" {
        return v;
    }
    let Some(sealed) = p.get("sealed") else {
        return json!({"verdict": "accept", "purpose": p.get("purpose").cloned().unwrap_or(Value::Null)});
    };
    let d = |k: &str| sealed[k].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
    let sk = x25519_from_ed25519_seed(recipient_seed);
    let Some(pt) = hpke_open(&d("enc"), &sk, SEALED_INFO, &sealed_aad(p), &d("ct")) else {
        return reject("sealed-open-failed", None);
    };
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&pt) else {
        return reject("sealed-plaintext-invalid", None);
    };
    let purpose = match (body.len(), body.get("purpose").and_then(Value::as_str)) {
        (1, Some(p)) => p.to_string(),
        _ => return reject("sealed-plaintext-invalid", None),
    };
    if purpose.chars().count() > PURPOSE_MAX_CHARS {
        return reject("purpose-too-long", None);
    }
    json!({"verdict": "accept", "purpose": purpose})
}

fn hex_in(v: &Value) -> Vec<u8> {
    v.as_str().and_then(|s| hex::decode(s).ok()).unwrap_or_default()
}

fn arr32(v: &Value) -> [u8; 32] {
    hex_in(v).try_into().unwrap_or([0; 32])
}

/// Run one first-contact vector check; `None` when `check` is not one of them.
///
/// Spec: none (infrastructure).
pub fn run_check(check: &str, inp: &Value) -> Option<Value> {
    Some(match check {
        "hpke-open" => match hpke_open(&hex_in(&inp["enc_hex"]), &arr32(&inp["sk_r_hex"]), &hex_in(&inp["info_hex"]), &hex_in(&inp["aad_hex"]), &hex_in(&inp["ct_hex"])) {
            Some(pt) => json!({"verdict": "accept", "plaintext_hex": hex::encode(pt)}),
            None => reject("hpke-open-failed", None),
        },
        "hpke-derive-key-pair" => {
            let sk = hpke_derive_sk(&hex_in(&inp["ikm_hex"]));
            json!({"sk_hex": hex::encode(sk), "pk_hex": hex::encode(x25519_public(&sk))})
        }
        "x25519-key-agreement" => json!({"x25519_pk_hex": hex::encode(x25519_public(&x25519_from_ed25519_seed(&arr32(&inp["ed25519_seed_hex"]))))}),
        "introduction" => check_introduction(&inp["payload"]),
        "sealed-introduction-open" => open_sealed_introduction(&inp["payload"], &arr32(&inp["recipient_ed25519_seed_hex"])),
        _ => return None,
    })
}
