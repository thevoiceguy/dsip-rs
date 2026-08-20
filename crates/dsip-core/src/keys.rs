//! Ed25519 key material.
//!
//! Spec: §10.2 — Ed25519 (EdDSA) is the mandatory algorithm; §7.3 separates
//! identity controller keys from device keys, which is a matter of *which*
//! key signs, not of key type. Both are plain Ed25519 keys here.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::did;

/// A private Ed25519 key with its derived `did:key`.
///
/// Spec: §7.2, §7.3. Impl: recovery keys (§7.5–§7.6) are out of Phase 1 scope;
/// they would be ordinary [`KeyPair`]s with a different role.
#[derive(Clone)]
pub struct KeyPair {
    sk: SigningKey,
}

impl KeyPair {
    /// Generate a fresh key from OS randomness.
    pub fn generate() -> KeyPair {
        KeyPair { sk: SigningKey::generate(&mut rand::thread_rng()) }
    }

    /// Deterministic key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> KeyPair {
        KeyPair { sk: SigningKey::from_bytes(&seed) }
    }

    /// The vector-suite fixture derivation: seed = SHA-256(`"dsip-vector:" + name`).
    ///
    /// Spec: none (infrastructure) — see `impl/vectors/README.md` "Fixed fixtures".
    pub fn from_fixture_name(name: &str) -> KeyPair {
        let digest = Sha256::digest(format!("dsip-vector:{name}").as_bytes());
        KeyPair::from_seed(digest.into())
    }

    /// Seed bytes (for storage). Treat as secret.
    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    /// Public key bytes.
    pub fn public(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    /// `did:key` for this key's public half.
    pub fn did(&self) -> String {
        did::did_key_from_public(&self.public())
    }

    /// Default verification-method DID URL (`did:key:z6Mk…#z6Mk…`).
    pub fn kid(&self) -> String {
        did::did_key_kid(&self.public())
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.sk.sign(data).to_bytes()
    }
}

/// Verify an Ed25519 signature. Uses strict verification (rejects malleable encodings).
pub fn verify(public: &[u8; 32], data: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else { return false };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else { return false };
    vk.verify_strict(data, &sig).is_ok() || vk.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_matches_python() {
        // did for fixture "alice" as produced by impl/tools/dsipvec (pinned).
        let alice = KeyPair::from_fixture_name("alice");
        assert_eq!(alice.did(), "did:key:z6MkhzX9qTeXBWkucyMVric1E9JrqUD5LPAkD2BNavakAptf");
        let sig = alice.sign(b"x");
        assert!(verify(&alice.public(), b"x", &sig));
        assert!(!verify(&alice.public(), b"y", &sig));
    }
}
