//! Sealed presence records (`presence/0.2`): the keys an identity derives for its records, sealing and opening a
//! record's state, and the keys a grant carries to its grantee.
//!
//! Spec: P§12.1 (audience tags and keys derived from the identity's X25519 key agreement secret with HKDF-SHA256),
//! P§12.2 (the record: `{"state": S}` padded to 128 bytes, AES-256-GCM, the AAD), P§12.3 (`presence_keys` in a grant:
//! HPKE to the grantee identity), P§12.4 (when a record is unreadable, in order).
//!
//! Impl: it lives in `dsip-core` beside [`crate::hpke`] because both the authority's semantic check (`dsip-schema`)
//! and the endpoint that seals and opens records need it, and neither depends on the presence profile's crate.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::{b64, hpke};

/// The profile a sealed record names in `dsip.profiles`.
///
/// Spec: P§12.2, P§12.6.
pub const PROFILE: &str = "presence/0.2";

/// The scope of the keys for records with no audience.
///
/// Spec: P§12.1.
pub const MAIN: &str = "main";

/// The length of every sealed state's plaintext.
///
/// Spec: P§12.2.
pub const PLAINTEXT_LEN: usize = 128;

/// The decoded length of every `sealed_state`: nonce, plaintext, tag.
///
/// Spec: P§12.2 (AES-256-GCM as M§11.1).
pub const SEALED_LEN: usize = 12 + PLAINTEXT_LEN + 16;

/// HPKE `info` for a grant's `presence_keys`.
///
/// Spec: P§12.3.
pub const KEYS_INFO: &[u8] = b"dsip presence keys v1";

/// RFC 7748 `decodeScalar25519`: P§12.1 derives from the key agreement secret as clamped, so every encoding of one
/// key derives the same keys.
///
/// Spec: P§12.1.
pub fn clamp(sk: &[u8; 32]) -> [u8; 32] {
    let mut b = *sk;
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    b
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869), empty salt, IKM the clamped secret.
fn hkdf(secret: &[u8; 32], info: &[&[u8]], n: usize) -> Vec<u8> {
    let prk = hmac(&[0u8; 32], &[&clamp(secret)]);
    let info = info.concat();
    let (mut out, mut t, mut i) = (Vec::new(), Vec::new(), 1u8);
    while out.len() < n {
        t = hmac(&prk, &[&t, &info, &[i]]).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(n);
    out
}

/// RFC 4648 base32, lower case, unpadded.
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The wire name of an audience the subject labels `label`: `k-` and 16 base32 characters.
///
/// Spec: P§12.1.
pub fn audience_tag(secret: &[u8; 32], subject: &str, label: &str) -> String {
    let raw = hkdf(secret, &[b"dsip presence audience v1\0", subject.as_bytes(), b"\0", label.as_bytes()], 10);
    format!("k-{}", base32_lower(&raw))
}

/// The 32-byte key that `kid` names.
///
/// Spec: P§12.1.
pub fn key(secret: &[u8; 32], subject: &str, kid: &str) -> [u8; 32] {
    hkdf(secret, &[b"dsip presence key v1\0", subject.as_bytes(), b"\0", kid.as_bytes()], 32).try_into().expect("32")
}

/// Whether `kid` is a key id: a scope (`main` or an audience token), `.`, an epoch without leading zeros.
///
/// Spec: P§12.1.
pub fn is_kid(kid: &str) -> bool {
    kid.rsplit_once('.').is_some_and(|(scope, epoch)| {
        (scope == MAIN || crate::is_presence_audience(scope))
            && !epoch.is_empty()
            && epoch.bytes().all(|c| c.is_ascii_digit())
            && (epoch == "0" || !epoch.starts_with('0'))
    })
}

/// A key id's scope: the part before its last `.`.
///
/// Spec: P§12.1.
pub fn kid_scope(kid: &str) -> &str {
    kid.rsplit_once('.').map_or(kid, |(scope, _)| scope)
}

/// `kid` for `scope` at `epoch`.
///
/// Spec: P§12.1.
pub fn kid(scope: &str, epoch: u64) -> String {
    format!("{scope}.{epoch}")
}

/// The fields a sealed record's AAD binds.
///
/// Spec: P§12.2.
#[derive(Debug, Clone, Copy)]
pub struct RecordFields<'a> {
    /// The identity.
    pub subject: &'a str,
    /// The signing device.
    pub device: &'a str,
    /// The audience tag, if any.
    pub audience: Option<&'a str>,
    /// The key id.
    pub kid: &'a str,
    /// The record's `seq`.
    pub seq: u64,
    /// The record's `expires_at`.
    pub expires_at: u64,
}

impl<'a> RecordFields<'a> {
    /// The fields of a record payload, `None` when one is missing or of the wrong type.
    pub fn of(r: &'a Value) -> Option<RecordFields<'a>> {
        Some(RecordFields {
            subject: r["subject"].as_str()?,
            device: r["device"].as_str()?,
            audience: r["audience"].as_str(),
            kid: r["kid"].as_str()?,
            seq: r["seq"].as_u64()?,
            expires_at: r["expires_at"].as_u64()?,
        })
    }

    fn aad(&self) -> Vec<u8> {
        let parts: [&[u8]; 5] = [
            b"dsip presence v1",
            self.subject.as_bytes(),
            self.device.as_bytes(),
            self.audience.unwrap_or("").as_bytes(),
            self.kid.as_bytes(),
        ];
        [parts.join(&0u8).as_slice(), &[0], &self.seq.to_be_bytes(), &self.expires_at.to_be_bytes()].concat()
    }
}

/// Seal `state` for a record with `fields` under `key`: the record's `sealed_state`.
///
/// Spec: P§12.2. Impl: callers pass a fresh random nonce; vectors pass a fixed one.
pub fn seal_record(fields: &RecordFields, state: &str, key: &[u8; 32], nonce: &[u8; 12]) -> String {
    let mut pt = json!({"state": state}).to_string().into_bytes();
    pt.resize(PLAINTEXT_LEN, b' ');
    let ct = Aes256Gcm::new(key.into())
        .encrypt(Nonce::<Aes256Gcm>::from_slice(nonce), Payload { msg: &pt, aad: &fields.aad() })
        .expect("aes-gcm");
    b64::encode(&[nonce.as_slice(), &ct].concat())
}

/// Why a sealed record could not be read, in the order P§12.4 checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// No key held for its `kid`.
    KeyUnknown,
    /// `sealed_state` is not 156 bytes.
    TooShort,
    /// It does not open under the key and the AAD.
    OpenFailed,
    /// The plaintext is not `{"state": S}` with `S` a P§5 token.
    PlaintextInvalid,
}

impl Unreadable {
    /// The vectors' code.
    pub fn code(self) -> &'static str {
        match self {
            Unreadable::KeyUnknown => "presence-key-unknown",
            Unreadable::TooShort => "sealed-too-short",
            Unreadable::OpenFailed => "aead-open-failed",
            Unreadable::PlaintextInvalid => "presence-plaintext-invalid",
        }
    }
}

/// Open a sealed record's state with the key `keys` returns for its `kid`.
///
/// Spec: P§12.4. The state is returned raw: P§5's fallback is the combining rule's.
pub fn open_record(fields: &RecordFields, sealed_state: &str, keys: impl Fn(&str) -> Option<[u8; 32]>) -> Result<String, Unreadable> {
    let key = keys(fields.kid).ok_or(Unreadable::KeyUnknown)?;
    let sealed = b64::decode(sealed_state).filter(|s| s.len() == SEALED_LEN).ok_or(Unreadable::TooShort)?;
    let pt = Aes256Gcm::new(&key.into())
        .decrypt(Nonce::<Aes256Gcm>::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad: &fields.aad() })
        .map_err(|_| Unreadable::OpenFailed)?;
    let body: Value = std::str::from_utf8(&pt).ok().and_then(|t| serde_json::from_str(t).ok()).ok_or(Unreadable::PlaintextInvalid)?;
    match body.as_object() {
        Some(o) if o.len() == 1 => match o.get("state").and_then(Value::as_str) {
            Some(s) if crate::is_presence_audience(s) => Ok(s.to_string()),
            _ => Err(Unreadable::PlaintextInvalid),
        },
        _ => Err(Unreadable::PlaintextInvalid),
    }
}

fn grant_aad(grant: &Value) -> Vec<u8> {
    let s = |k: &str| grant[k].as_str().unwrap_or("").as_bytes().to_vec();
    [s("id"), s("from"), s("to")].join(&0u8)
}

/// A grant's `presence_keys` carrying `keys` (`kid` → key), sealed to the grantee's X25519 public key `pk_r`.
///
/// Spec: P§12.3. Impl: callers pass a fresh random `sk_e`; the plaintext is written in `kid` order.
pub fn seal_grant_keys(grant: &Value, keys: &BTreeMap<String, [u8; 32]>, pk_r: &[u8; 32], sk_e: &[u8; 32]) -> Value {
    let entries: Vec<Value> = keys.iter().map(|(kid, k)| json!({"kid": kid, "key": b64::encode(k)})).collect();
    let mut pt = json!({"keys": entries}).to_string().into_bytes();
    pt.resize(pt.len().div_ceil(256).max(1) * 256, b' ');
    let (enc, ct) = hpke::hpke_seal(pk_r, KEYS_INFO, &grant_aad(grant), &pt, sk_e);
    json!({"alg": hpke::ALG, "enc": b64::encode(&enc), "ct": b64::encode(&ct)})
}

/// Why a grant's `presence_keys` could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKeysError {
    /// An `alg` other than HPKE's one suite.
    AlgUnsupported,
    /// It does not open with the grantee's secret and the grant's AAD.
    OpenFailed,
    /// The plaintext is not `{"keys": [{kid, key}]}` padded to a multiple of 256 bytes, or names a foreign scope.
    PlaintextInvalid,
}

impl GrantKeysError {
    /// The vectors' code.
    pub fn code(self) -> &'static str {
        match self {
            GrantKeysError::AlgUnsupported => "sealed-alg-unsupported",
            GrantKeysError::OpenFailed => "sealed-open-failed",
            GrantKeysError::PlaintextInvalid => "sealed-plaintext-invalid",
        }
    }
}

/// The keys a grant carries, opened with the grantee identity's key agreement `secret` (as stored).
///
/// Spec: P§12.3 (the grant names no scope but `main` and its `presence_audience`).
pub fn open_grant_keys(grant: &Value, secret: &[u8; 32]) -> Result<BTreeMap<String, [u8; 32]>, GrantKeysError> {
    let pk = &grant["presence_keys"];
    if pk["alg"].as_str() != Some(hpke::ALG) {
        return Err(GrantKeysError::AlgUnsupported);
    }
    let field = |k: &str| pk[k].as_str().and_then(b64::decode).ok_or(GrantKeysError::OpenFailed);
    let pt = hpke::hpke_open(&field("enc")?, &clamp(secret), KEYS_INFO, &grant_aad(grant), &field("ct")?).ok_or(GrantKeysError::OpenFailed)?;
    let bad = GrantKeysError::PlaintextInvalid;
    if pt.is_empty() || pt.len() % 256 != 0 {
        return Err(bad);
    }
    let body: Value = std::str::from_utf8(&pt).ok().and_then(|t| serde_json::from_str(t).ok()).ok_or(bad)?;
    let entries = match body.as_object() {
        Some(o) if o.len() == 1 => o.get("keys").and_then(Value::as_array).ok_or(bad)?,
        _ => return Err(bad),
    };
    let audience = grant["presence_audience"].as_str();
    let mut out = BTreeMap::new();
    for e in entries {
        let o = e.as_object().filter(|o| o.len() == 2).ok_or(bad)?;
        let (kid, k) = (o.get("kid").and_then(Value::as_str).ok_or(bad)?, o.get("key").and_then(Value::as_str).ok_or(bad)?);
        let scope = kid_scope(kid);
        if !is_kid(kid) || !(scope == MAIN || Some(scope) == audience) {
            return Err(bad);
        }
        let key: [u8; 32] = b64::decode(k).and_then(|k| k.try_into().ok()).ok_or(bad)?;
        out.insert(kid.to_string(), key);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_keys_round_trip() {
        let (sk, sk_e) = ([3u8; 32], [9u8; 32]);
        let grant = json!({"id": "01K742SG0000000000GRANT001", "from": "did:key:zA", "to": "did:key:zB", "presence_audience": "k-abc"});
        let keys = BTreeMap::from([("main.0".to_string(), [1u8; 32]), ("k-abc.2".to_string(), [2u8; 32])]);
        let sealed = seal_grant_keys(&grant, &keys, &hpke::x25519_public(&clamp(&sk)), &sk_e);
        let mut g = grant.clone();
        g["presence_keys"] = sealed;
        assert_eq!(open_grant_keys(&g, &sk), Ok(keys));
    }

    #[test]
    fn record_round_trip() {
        let f = RecordFields { subject: "did:key:zA", device: "did:key:zP", audience: None, kid: "main.0", seq: 7, expires_at: 99 };
        let k = key(&[5u8; 32], f.subject, f.kid);
        let sealed = seal_record(&f, "dnd", &k, &[0u8; 12]);
        assert_eq!(open_record(&f, &sealed, |_| Some(k)), Ok("dnd".into()));
    }
}
