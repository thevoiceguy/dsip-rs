//! Archive records: content shown from MLS sealed under an archive key for later devices, and archive items opened.
//!
//! Spec: M§12.1 (archive keys), M§12.2 (the `archive-record`, sealed with AAD `group_id ‖ seq`), M§12.3 step 5
//! (history from the archive).

use dsip_messaging::mls_wire::{open, seal, SealUse};
use serde_json::{json, Value};

/// Where an archived object was received, and from whom.
pub struct Received<'a> {
    /// The conversation id.
    pub conversation: &'a str,
    /// The group, base64url.
    pub group: &'a str,
    /// The hub's seq of the item.
    pub seq: i64,
    /// The sender's identity.
    pub sender: &'a str,
    /// The sender's device.
    pub sender_device: &'a str,
    /// When this device received it.
    pub received_at: i64,
}

/// The `archive-record` for `payload` (M§12.2).
pub fn record(r: &Received, payload: &Value) -> Value {
    json!({"object": "archive-record", "conversation": r.conversation, "group": r.group, "seq": r.seq, "sender": r.sender,
        "sender_device": r.sender_device, "received_at": r.received_at, "payload": payload})
}

/// The `archive` deposit's fields for `record` sealed under the archive key `akid` (M§12.2); `None` when the group
/// id is not base64url.
pub fn seal_record(key: &[u8; 32], nonce: &[u8; 12], akid: &str, record: &Value) -> Option<Value> {
    let group = record["group"].as_str()?;
    let seq = record["seq"].as_i64().unwrap_or(0);
    let group_bytes = dsip_core::b64::decode(group)?;
    let sealed = seal(key, nonce, &serde_json::to_vec(record).ok()?, SealUse::Archive { group: &group_bytes, seq: seq as u64 });
    Some(json!({"archive": dsip_core::b64::encode(&sealed), "akid": akid, "ref_group": group, "ref_seq": seq}))
}

/// An archive item opened.
pub struct Opened {
    /// The group the item names.
    pub group: String,
    /// The seq the item names.
    pub seq: i64,
    /// The `archive-record`.
    pub record: Value,
}

/// Why an archive item did not open.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// It does not open for its group and seq (or its key).
    DoesNotOpen,
    /// It opened but is not JSON.
    NotJson,
}

/// Open an archive item under its key.
pub fn open_item(key: &[u8; 32], item: &Value) -> Result<Opened, OpenError> {
    let group = item["group"].as_str().unwrap_or("").to_string();
    let seq = item["seq"].as_i64().unwrap_or(0);
    let group_bytes = dsip_core::b64::decode(&group).unwrap_or_default();
    let sealed = item["archive"].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
    let plain = open(key, &sealed, SealUse::Archive { group: &group_bytes, seq: seq as u64 }).map_err(|_| OpenError::DoesNotOpen)?;
    let record = serde_json::from_slice::<Value>(&plain).map_err(|_| OpenError::NotJson)?;
    Ok(Opened { group, seq, record })
}

/// The `History` machine's `archive` event for an opened item whose payload's key is `id`.
pub fn history_event(item: &Value, opened: &Opened, id: &str) -> Value {
    json!({"archive": {"cursor": item["cursor"], "akid": item["akid"], "group": opened.group, "seq": opened.seq, "id": id,
        "object": opened.record["payload"]["object"]}})
}
