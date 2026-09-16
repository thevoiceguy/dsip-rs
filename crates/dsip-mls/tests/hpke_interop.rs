//! The Messaging Profile's HPKE (M§6.9, `dsip_messaging::first_contact`, written from RFC 9180 so vectors can pin it)
//! against an independent implementation, `hpke-rs`, in both directions, with a sealed introduction's AAD.
//!
//! Spec: M§6.9, M§14.1.

use dsip_messaging::first_contact::{hpke_open, hpke_seal, x25519_public, SEALED_INFO};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;

fn suite() -> Hpke<HpkeRustCrypto> {
    Hpke::new(Mode::Base, KemAlgorithm::DhKem25519, KdfAlgorithm::HkdfSha256, AeadAlgorithm::Aes128Gcm)
}

#[test]
fn profile_hpke_interoperates_with_hpke_rs() {
    let sk_r: [u8; 32] = rand::random();
    let pk_r = x25519_public(&sk_r);
    let aad = b"01M2ND00000000000000000000\0did:web:alice.example\0did:web:bob.example";
    let pt = br#"{"purpose":"We met at the meetup"}"#;

    // ours → hpke-rs
    let (enc, ct) = hpke_seal(&pk_r, SEALED_INFO, aad, pt, &rand::random());
    let opened = suite().open(&enc, &HpkePrivateKey::new(sk_r.to_vec()), SEALED_INFO, aad, &ct, None, None, None).expect("hpke-rs opens ours");
    assert_eq!(opened, pt);

    // hpke-rs → ours
    let (enc, ct) = suite().seal(&HpkePublicKey::new(pk_r.to_vec()), SEALED_INFO, aad, pt, None, None, None).expect("hpke-rs seals");
    assert_eq!(hpke_open(&enc, &sk_r, SEALED_INFO, aad, &ct).as_deref(), Some(&pt[..]));

    // and a different AAD opens in neither
    assert!(hpke_open(&enc, &sk_r, SEALED_INFO, b"other", &ct).is_none());
    assert!(suite().open(&enc, &HpkePrivateKey::new(sk_r.to_vec()), SEALED_INFO, b"other", &ct, None, None, None).is_err());
}
