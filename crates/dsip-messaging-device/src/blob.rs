//! Audio and video blobs: sealed for upload, named by the content object, fetched from the manifest's sources and
//! opened only when they are the content's bytes.
//!
//! Spec: M§8.2 (the `audio` content object), M§8.4 (rule 1: a fresh single-use key, AES-256-GCM, no AAD,
//! `nonce ‖ ciphertext ‖ tag`; rules 6–7: sources in order, size and SHA-256 checked before decrypting; "Fetching",
//! spec-gap 106: try again or give up).

use dsip_messaging::mls_wire::{open_blob, seal, SealUse};
use serde::{Deserialize, Serialize};
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

/// The pinned `blob_fetch` (spec-gap 106) over what the sources answered.
pub fn fetch_decision(object: &Value, tried: &[Tried], attempt: i64) -> Fetch {
    let b = &object["blob"];
    let d = dsip_messaging::client::blob_fetch(&json!({"blob": {"sha256": b["sha256"], "size": b["size"]}, "tried": tried, "attempt": attempt}));
    match d["action"].as_str() {
        Some("play") => Fetch::Play(d["source"].as_str().unwrap_or("").to_string()),
        Some("retry") => Fetch::Retry,
        _ => Fetch::GiveUp(d["reason"].as_str().unwrap_or("").to_string()),
    }
}

/// What one source answered, as [`fetch_decision`] takes it: `status` 0 when it could not be reached; `stored`, the
/// bytes a 200 served that did not open, entered with their size and SHA-256 (rule 7: other bytes, or bytes that are
/// the content's but do not decrypt under its key).
pub fn tried(uri: &str, status: u16, stored: Option<&[u8]>) -> Tried {
    Tried { uri: uri.to_string(), status, sha256: stored.map(dsip_mls::digest), size: stored.map(<[u8]>::len) }
}

/// One source's answer, as [`fetch_decision`] takes it, serialized `{uri, status, sha256?, size?}` (M§8.4 rule 7, spec-gap 106).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Tried {
    /// The source.
    pub uri: String,
    /// Its HTTP status; 0 when it was not reached.
    pub status: u16,
    /// Hex SHA-256 of bytes a 200 served that did not open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", tsify(optional))]
    pub sha256: Option<String>,
    /// Their size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", tsify(optional))]
    pub size: Option<usize>,
}

/// Seconds before fetch `attempt` is tried again after a [`Fetch::Retry`]: the mailbox replication schedule
/// (spec-gap 67), 4 s doubling, at most 60 s.
pub fn retry_delay_s(attempt: i64) -> i64 {
    (4i64 << (attempt - 1).clamp(0, 4)).min(60)
}
