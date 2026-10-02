//! HPKE (RFC 9180) base mode, single shot: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
//!
//! Spec: §10.4 (sealed bodies, extension `sealed-body/1.0`), §19.4 and M§6.9, M§14.1 (sealed introductions) — the
//! one suite DSIP seals with, to an identity's X25519 key agreement key (§7.2).
//!
//! Impl: implemented from the RFC's definition so that vectors can pin it byte for byte; anchored by RFC 9180
//! Appendix A.1.1 (`messaging/hpke-open-rfc9180-*`) and cross-checked against `hpke-rs` in `dsip-mls`. It lives in
//! `dsip-core` because sealed bodies are opened at stage 12b (`dsip-schema`), below the messaging profile.

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes128Gcm;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

/// The only sealing algorithm of 1.0.
///
/// Spec: §10.4, §19.4, M§6.9.
pub const ALG: &str = "hpke-base-x25519-sha256-aes128gcm";

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

/// The X25519 key agreement public key of an Ed25519 public key (the birational map to Montgomery form); `None`
/// for bytes that are not a valid Ed25519 point. This is how a sender seals to a `did:key`.
///
/// Spec: M§6.9, §10.4 — "as the did:key method defines".
pub fn x25519_from_ed25519_public(public: &[u8; 32]) -> Option<[u8; 32]> {
    Some(ed25519_dalek::VerifyingKey::from_bytes(public).ok()?.to_montgomery().to_bytes())
}

/// The X25519 key agreement secret of an Ed25519 key: the first 32 bytes of SHA-512 of its seed (clamped by X25519).
///
/// Spec: M§6.9, §10.4 — "as the did:key method defines". Impl (spec-gap 55): a `did:web` identity's devices
/// derive the same key from the identity key they hold.
pub fn x25519_from_ed25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    Sha512::digest(seed)[..32].try_into().expect("32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_conversion_matches_the_seed_derivation() {
        // did:key: the sender converts the Ed25519 public key; the holder derives from the seed. They must meet.
        let seed = [7u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(x25519_from_ed25519_public(&public), Some(x25519_public(&x25519_from_ed25519_seed(&seed))));
    }
}
