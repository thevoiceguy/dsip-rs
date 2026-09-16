//! The MLS layer as DSIP defines it: extension wire encoding, the DSIP authentication service for
//! MLS leaves, `dsip_conversation` bytes, and the AES-256-GCM formats for blobs, activity and archive.
//!
//! Spec: M§6.2 (basic credential naming the device DID; `dsip_delegation` carrying a compact
//! delegation with `dsip.messaging`; leaf signature key = the device's Ed25519 key), M§6.3
//! (`dsip_conversation` is UTF-8 JSON under §10.3), M§8.4 (blob: nonce ‖ ciphertext ‖ tag, size and
//! hash checked before decrypting), M§11.1 (activity AAD `group_id ‖ epoch`), M§12.2 (archive AAD
//! `group_id ‖ seq`), M§17 (private-use extension codepoints), RFC 9420 §2.1.2 (variable-length
//! vector lengths).
//!
//! Impl: extension codepoints `0xF0D1` (`dsip_delegation`) and `0xF0D2` (`dsip_conversation`) from the
//! private-use range; blobs carry no AAD; a device DID must be `did:key` in this implementation (a
//! `did:web` device would resolve its key through its document, not yet implemented).

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use dsip_core::delegation::{names, verify_delegation_for};
use dsip_core::did::public_from_did_key;
use dsip_core::envelope::{Context, Envelope};

use crate::checks::{check_conversation_ext, reject};

/// `dsip_delegation` LeafNode extension type (private use until registered).
///
/// Spec: M§17.
pub const EXT_DSIP_DELEGATION: u16 = 0xF0D1;
/// `dsip_conversation` GroupContext extension type (private use until registered).
///
/// Spec: M§17.
pub const EXT_DSIP_CONVERSATION: u16 = 0xF0D2;
/// RFC 9420 credential type `basic`.
pub const CREDENTIAL_BASIC: u16 = 0x0001;
/// Delegation capability an MLS leaf requires.
///
/// Spec: M§6.2 (spec-gap 39).
pub const MESSAGING_CAPABILITY: &str = "dsip.messaging";

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn hex_in(v: &Value) -> Option<Vec<u8>> {
    hex::decode(v.as_str()?).ok()
}

/// RFC 9420 §2.1.2 minimal variable-length vector length prefix.
pub fn vl_len(n: usize) -> Vec<u8> {
    if n < 1 << 6 {
        vec![n as u8]
    } else if n < 1 << 14 {
        ((0x4000 | n) as u16).to_be_bytes().to_vec()
    } else {
        assert!(n < 1 << 30, "vector too long for MLS");
        ((0x8000_0000 | n) as u32).to_be_bytes().to_vec()
    }
}

/// Serialize an MLS `Extension { extension_type, extension_data<V> }`.
pub fn encode_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = ext_type.to_be_bytes().to_vec();
    out.extend(vl_len(data.len()));
    out.extend_from_slice(data);
    out
}

/// Parse one serialized MLS `Extension`, rejecting non-minimal, over-long, truncated or trailing input.
pub fn decode_extension(b: &[u8]) -> Result<(u16, Vec<u8>), &'static str> {
    if b.len() < 3 {
        return Err("mls-truncated");
    }
    let n = match b[2] >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return Err("mls-length-invalid"), // 8-byte lengths exceed MLS's 30-bit bound
    };
    if b.len() < 2 + n {
        return Err("mls-truncated");
    }
    let raw = b[2..2 + n].iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    let len = (raw & ((1u64 << (8 * n - 2)) - 1)) as usize;
    if (n == 2 && len < 1 << 6) || (n == 4 && len < 1 << 14) {
        return Err("mls-length-non-minimal");
    }
    let data = &b[2 + n..];
    match data.len().cmp(&len) {
        std::cmp::Ordering::Less => Err("mls-truncated"),
        std::cmp::Ordering::Greater => Err("mls-trailing-bytes"),
        std::cmp::Ordering::Equal => Ok((u16::from_be_bytes([b[0], b[1]]), data.to_vec())),
    }
}

/// The outcome of authenticating an MLS leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafIdentity {
    /// The identity that delegated the device (the delegation `subject`).
    pub identity: String,
    /// The device DID named by the credential.
    pub device: String,
}

/// Authenticate an MLS leaf: basic credential, `dsip_delegation`, and signature key.
///
/// Spec: M§6.2. `extensions` are the leaf's `(type, data)` pairs.
pub fn authenticate_leaf(
    credential_type: u16,
    identity: &[u8],
    signature_key: &[u8],
    extensions: &[(u16, Vec<u8>)],
    ctx: &Context,
) -> Result<LeafIdentity, &'static str> {
    if credential_type != CREDENTIAL_BASIC {
        return Err("credential-type");
    }
    let device = std::str::from_utf8(identity).map_err(|_| "credential-identity")?;
    let is_did = device.strip_prefix("did:").and_then(|r| r.split_once(':')).is_some_and(|(m, rest)| {
        !m.is_empty()
            && m.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && !rest.is_empty()
            && rest.bytes().all(|c| c.is_ascii_alphanumeric() || b".%_:-".contains(&c))
    });
    if !is_did {
        return Err("credential-identity");
    }
    let delegations: Vec<&Vec<u8>> = extensions.iter().filter(|(t, _)| *t == EXT_DSIP_DELEGATION).map(|(_, d)| d).collect();
    let data = match delegations.as_slice() {
        [] => return Err("delegation-missing"),
        [one] => *one,
        _ => return Err("delegation-invalid"),
    };
    let text = std::str::from_utf8(data).map_err(|_| "delegation-invalid")?;
    let parts: Vec<&str> = text.split('.').collect();
    let [protected, payload, signature] = parts.as_slice() else { return Err("delegation-invalid") };
    let deleg = Envelope { protected: protected.to_string(), payload: payload.to_string(), signature: signature.to_string() };
    let Some((subject, named_device)) = names(&deleg) else { return Err("delegation-invalid") };
    if named_device != device {
        return Err("delegation-invalid");
    }
    let v = verify_delegation_for(&deleg, &subject, device, MESSAGING_CAPABILITY, ctx);
    if let Some(code) = v.code {
        return Err(match serde_json::to_value(code).ok().as_ref().and_then(Value::as_str) {
            Some("delegation-capability") => "delegation-capability",
            Some("delegation-expired") => "delegation-expired",
            _ => "delegation-invalid",
        });
    }
    // Impl: did:key devices only (see module docs)
    if public_from_did_key(device).is_none_or(|k| k.as_slice() != signature_key) {
        return Err("credential-key-mismatch");
    }
    Ok(LeafIdentity { identity: subject, device: device.to_string() })
}

/// Check `dsip_conversation` extension bytes.
///
/// Spec: M§6.3, §10.3.
pub fn check_conversation_bytes(data: &[u8]) -> Value {
    let Ok(text) = std::str::from_utf8(data) else { return reject("payload-not-utf8", None) };
    let obj: Value = match serde_json::from_str(text) {
        Ok(v @ Value::Object(_)) => v,
        _ => return reject("payload-not-json", None),
    };
    if crate::checks::has_float(&obj) {
        return reject("payload-float", None);
    }
    check_conversation_ext(&obj)
}

/// What a sealed value is for; selects its AAD.
#[derive(Debug, Clone, Copy)]
pub enum SealUse<'a> {
    /// Blob ciphertext (M§8.4): no AAD.
    Blob,
    /// Activity (M§11.1): `group_id ‖ epoch`.
    Activity {
        /// MLS group id bytes.
        group: &'a [u8],
        /// Epoch.
        epoch: u64,
    },
    /// Archive record (M§12.2): `group_id ‖ seq`.
    Archive {
        /// MLS group id bytes.
        group: &'a [u8],
        /// Hub seq of the archived item.
        seq: u64,
    },
}

fn aad(u: SealUse) -> Vec<u8> {
    match u {
        SealUse::Blob => vec![],
        SealUse::Activity { group, epoch: c } | SealUse::Archive { group, seq: c } => {
            let mut a = group.to_vec();
            a.extend_from_slice(&c.to_be_bytes());
            a
        }
    }
}

/// Seal `plaintext` under a 32-byte key and 12-byte nonce: `nonce ‖ ciphertext ‖ tag`.
///
/// Spec: M§8.4, M§11.1, M§12.2.
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8], u: SealUse) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let mut out = nonce.to_vec();
    let a = aad(u);
    out.extend(cipher.encrypt(Nonce::<Aes256Gcm>::from_slice(nonce), Payload { msg: plaintext, aad: &a }).expect("aes-gcm encrypt"));
    out
}

/// Open a sealed value produced by [`seal`].
pub fn open(key: &[u8; 32], sealed: &[u8], u: SealUse) -> Result<Vec<u8>, &'static str> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err("sealed-too-short");
    }
    let cipher = Aes256Gcm::new(key.into());
    let a = aad(u);
    cipher
        .decrypt(Nonce::<Aes256Gcm>::from_slice(&sealed[..NONCE_LEN]), Payload { msg: &sealed[NONCE_LEN..], aad: &a })
        .map_err(|_| "aead-open-failed")
}

/// Open a blob after checking the manifest size and SHA-256.
///
/// Spec: M§8.4 rule 7.
pub fn open_blob(key: &[u8; 32], stored: &[u8], size: usize, sha256_hex: &str) -> Result<Vec<u8>, &'static str> {
    if stored.len() != size {
        return Err("blob-size-mismatch");
    }
    if hex::encode(Sha256::digest(stored)) != sha256_hex {
        return Err("blob-hash-mismatch");
    }
    open(key, stored, SealUse::Blob)
}

fn seal_use<'a>(inp: &Value, group: &'a [u8]) -> Option<SealUse<'a>> {
    match inp["use"].as_str()? {
        "blob" => Some(SealUse::Blob),
        "activity" => Some(SealUse::Activity { group, epoch: inp["epoch"].as_u64()? }),
        "archive" => Some(SealUse::Archive { group, seq: inp["seq"].as_u64()? }),
        _ => None,
    }
}

/// Run one MLS-layer vector check; `None` when `check` is not an MLS-layer check.
///
/// Spec: none (infrastructure).
pub fn run_check(check: &str, v: &Value) -> Option<Value> {
    let inp = &v["input"];
    let key = || -> [u8; 32] { hex_in(&inp["key_hex"]).and_then(|k| k.try_into().ok()).unwrap_or([0; 32]) };
    Some(match check {
        "mls-extension-encode" => {
            let data = hex_in(&inp["data_hex"]).unwrap_or_default();
            json!({"hex": hex::encode(encode_extension(inp["extension_type"].as_u64().unwrap_or(0) as u16, &data))})
        }
        "mls-extension-decode" => match decode_extension(&hex_in(&inp["hex"]).unwrap_or_default()) {
            Ok((t, d)) => json!({"verdict": "accept", "extension_type": t, "data_hex": hex::encode(d)}),
            Err(code) => reject(code, None),
        },
        "mls-credential" => {
            let resolver = Context::resolver_from_vector(&v["context"]);
            let ctx = Context::from_vector(&v["context"], &resolver);
            let cred = &inp["credential"];
            let exts: Vec<(u16, Vec<u8>)> = inp["extensions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| (e["extension_type"].as_u64().unwrap_or(0) as u16, hex_in(&e["data_hex"]).unwrap_or_default()))
                .collect();
            let identity = hex_in(&cred["identity_hex"]).unwrap_or_default();
            match authenticate_leaf(
                cred["credential_type"].as_u64().unwrap_or(0) as u16,
                &identity,
                &hex_in(&inp["signature_key_hex"]).unwrap_or_default(),
                &exts,
                &ctx,
            ) {
                Ok(l) => json!({"verdict": "accept", "identity": l.identity, "device": l.device}),
                Err(code) => reject(code, None),
            }
        }
        "mls-conversation-bytes" => check_conversation_bytes(&hex_in(&inp["data_hex"]).unwrap_or_default()),
        "seal" => {
            let nonce: [u8; NONCE_LEN] = hex_in(&inp["nonce_hex"]).and_then(|n| n.try_into().ok()).unwrap_or([0; NONCE_LEN]);
            let group = hex_in(&inp["group_hex"]).unwrap_or_default();
            let Some(u) = seal_use(inp, &group) else { return Some(json!({"error": "bad use"})) };
            json!({"sealed_hex": hex::encode(seal(&key(), &nonce, &hex_in(&inp["plaintext_hex"]).unwrap_or_default(), u))})
        }
        "open" => {
            let sealed = hex_in(&inp["sealed_hex"]).unwrap_or_default();
            let group = hex_in(&inp["group_hex"]).unwrap_or_default();
            let Some(u) = seal_use(inp, &group) else { return Some(json!({"error": "bad use"})) };
            let r = match u {
                SealUse::Blob => open_blob(
                    &key(),
                    &sealed,
                    inp["size"].as_u64().unwrap_or(0) as usize,
                    inp["sha256"].as_str().unwrap_or(""),
                ),
                other => open(&key(), &sealed, other),
            };
            match r {
                Ok(pt) => json!({"verdict": "accept", "plaintext_hex": hex::encode(pt)}),
                Err(code) => reject(code, None),
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_round_trip_across_length_forms() {
        for n in [0usize, 63, 64, 16383, 16384] {
            let data = vec![7u8; n];
            let enc = encode_extension(EXT_DSIP_CONVERSATION, &data);
            assert_eq!(decode_extension(&enc), Ok((EXT_DSIP_CONVERSATION, data)));
        }
    }
}
