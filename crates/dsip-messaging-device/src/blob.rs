//! Audio and video blobs: sealed for upload, named by the content object, fetched from the manifest's sources and
//! opened only when they are the content's bytes.
//!
//! Spec: M§8.2 (the `audio` content object), M§8.4 (rule 1: a fresh single-use key, AES-256-GCM, no AAD,
//! `nonce ‖ ciphertext ‖ tag`; rules 6–7: sources in order, size and SHA-256 checked before decrypting; "Fetching",
//! spec-gap 106: try again or give up).

use dsip_messaging::mls_wire::{open_blob, seal, SealUse};
use serde_json::{json, Value};

/// A blob sealed for upload.
pub struct Sealed {
    /// `nonce ‖ ciphertext ‖ tag`, the bytes uploaded.
    pub bytes: Vec<u8>,
    /// Hex SHA-256 of `bytes`.
    pub sha256: String,
}

/// Seal `plain` under a fresh single-use `key` and `nonce` the host draws.
pub fn seal_blob(key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> Sealed {
    let bytes = seal(key, nonce, plain, SealUse::Blob);
    Sealed { sha256: dsip_mls::digest(&bytes), bytes }
}

/// What the content object says of an uploaded blob.
pub struct Uploaded<'a> {
    /// Where it was uploaded.
    pub uri: &'a str,
    /// Hex SHA-256 of the stored bytes.
    pub sha256: &'a str,
    /// Size of the stored bytes.
    pub size: u64,
    /// The single-use key, base64url.
    pub key: &'a str,
    /// The plaintext's media type.
    pub content_type: &'a str,
}

/// An `audio` content object for an uploaded blob (M§8.2); `session` for a voicemail (M§13.2).
#[allow(clippy::too_many_arguments)]
pub fn audio_content(id: &str, conversation: &str, sender: &str, now: i64, purpose: &str, duration_ms: i64, blob: &Uploaded,
                     session: Option<&str>) -> Value {
    let mut obj = json!({"object": "content", "id": id, "conversation": conversation, "sender": sender, "sent_at": now, "kind": "audio",
        "purpose": purpose, "duration_ms": duration_ms,
        "blob": {"uri": blob.uri, "sha256": blob.sha256, "size": blob.size, "key": blob.key, "alg": "A256GCM",
                 "content_type": blob.content_type}});
    if let Some(s) = session {
        obj["session"] = json!(s);
    }
    obj
}

/// Where to fetch a content's blob from, in order (rules 6–7, the pinned `blob_sources`): the item's manifest
/// (`blobs`, or null) first, then the content's own `uri`.
pub fn sources(object: &Value, manifest: &Value) -> Vec<String> {
    dsip_messaging::client::blob_sources(&json!({"blob": object["blob"], "manifest": manifest}))["sources"]
        .as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect()
}

/// Open fetched bytes for a content object (rule 7): the size and SHA-256 must match its `blob` before they are
/// decrypted under the key it carries. `Err` is the refusal code.
pub fn open(object: &Value, stored: &[u8]) -> Result<Vec<u8>, &'static str> {
    let b = &object["blob"];
    let key: [u8; 32] = b["key"].as_str().and_then(dsip_core::b64::decode).and_then(|k| k.try_into().ok()).ok_or("blob-key")?;
    open_blob(&key, stored, b["size"].as_u64().unwrap_or(0) as usize, b["sha256"].as_str().unwrap_or(""))
}

/// What to do once the sources have answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetch {
    /// A source served the content's bytes: play them, from this source.
    Play(String),
    /// A source had nothing to serve yet (`unavailable`).
    Retry,
    /// Given up, with the reason (`mismatch`, or `unavailable` after the last attempt).
    GiveUp(String),
}

/// The pinned `blob_fetch` (spec-gap 106) over what the sources answered: `tried` is `[{uri, status, sha256?, size?}]`.
pub fn fetch_decision(object: &Value, tried: &Value, attempt: i64) -> Fetch {
    let b = &object["blob"];
    let d = dsip_messaging::client::blob_fetch(&json!({"blob": {"sha256": b["sha256"], "size": b["size"]}, "tried": tried, "attempt": attempt}));
    match d["action"].as_str() {
        Some("play") => Fetch::Play(d["source"].as_str().unwrap_or("").to_string()),
        Some("retry") => Fetch::Retry,
        _ => Fetch::GiveUp(d["reason"].as_str().unwrap_or("").to_string()),
    }
}
