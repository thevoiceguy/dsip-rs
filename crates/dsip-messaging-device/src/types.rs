//! What a [`crate::messenger::Messenger`]'s calls take and return besides its step outputs ([`crate::events`]): the
//! structured results built for the call (dsip-rs B3b, `impl/docs/dsip-stack-design.md` §6) and the host's inputs
//! that are not wire payloads. They serialize as the JSON the hosts read before these types existed.
//!
//! Records the `Messenger` keeps as it received or saved them (the thread's messages, the call log, the records,
//! the roster log, the requests, a receipts snapshot) and wire payloads (a `key-packages` answer, a content object,
//! a manifest) stay JSON values: their shape is the stored record's or the wire's, not this crate's.
//!
//! Spec: none (infrastructure). The sections each value reports are cited on its type.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A mailbox, or a group's hub (M§4.2, M§6.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Hub {
    /// Its DID.
    pub did: String,
    /// Where it is reached.
    pub uri: String,
}

/// A group whose hub is unreachable (M§9.4).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Outage {
    /// When the hub was first found unreachable.
    pub down_since: Option<i64>,
    /// How many items wait for it.
    pub pending: usize,
    /// Whether the items were given up after the threshold.
    pub abandoned: bool,
    /// The successor this device converged on, if any (M§7.5).
    pub successor: Option<String>,
}

/// An archive key this device holds (M§12.1); the key itself never leaves the `Messenger`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct ArchiveKey {
    /// Its id.
    pub akid: String,
    /// When it was created.
    pub created_at: i64,
}

/// A group this device can join by external commit (M§6.8), as its GroupInfo describes it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Available {
    /// The group id.
    pub group: String,
    /// The conversation it carries.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub conversation: Value,
    /// Its kind (`personal`, `direct`, `group`).
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub kind: Value,
    /// Its hub, `{did, uri}`.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub hub: Value,
}

/// How one inbound leg of this device ended, as the host saw it (M§13.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(default)]
pub struct CallLeg {
    /// The call's session id.
    pub session: String,
    /// The caller.
    pub peer: String,
    /// Whether this device alerted.
    pub alerted: bool,
    /// Whether this device answered.
    pub answered_here: bool,
    /// Who ended it: `local` or `remote`.
    pub ended_by: String,
    /// The reason token, or empty.
    pub reason: String,
}

/// What [`crate::messenger::Messenger::call_ended_item`] did (M§13.3).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct CallEnded {
    /// The `call-event` sent, `None` when the decision is to send none.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub event: Option<Value>,
    /// The outbox item it went out under, named by its `sent`.
    pub item: Option<String>,
    /// The frame; empty while the hub is down or when nothing is sent.
    pub send: String,
    /// Whether it is the first entry for its session on this identity (spec-gap 63).
    pub fresh: bool,
}

/// What [`crate::messenger::Messenger::call_record`] built and sent (C§9).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct CallRecorded {
    /// The `call-record`.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub record: Value,
    /// The frames sending every held record, `[]` while there is no conversation with the record-keeper.
    pub frames: Vec<String>,
}

/// What [`crate::messenger::Messenger::accept_recording`] accepted (C§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct RecordingAccepted {
    /// The recorder devices accepted.
    pub accepted: Vec<String>,
    /// The frames: the `recording-acceptance` to the personal group.
    pub frames: Vec<String>,
}

/// An object sent (M§8): the outbox item it went out under (`None`: kept for a successor, M§9.4), whose `sent` event
/// names it, and the frame (empty: queued behind an unreachable hub).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Sent {
    /// The outbox item.
    pub item: Option<String>,
    /// The frame.
    pub send: String,
}

/// One conversation as [`crate::messenger::Messenger::conversations`] lists it (M§6.2, M§7, C§5).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Conversation {
    /// The group id.
    pub group: String,
    /// The conversation id.
    pub conversation: String,
    /// `personal`, `direct` or `group`.
    pub kind: String,
    /// The other identity of a direct conversation.
    pub peer: Option<String>,
    /// The identities with a leaf that authenticates now, sorted (M§6.2).
    pub members: Vec<String>,
    /// The MLS epoch.
    pub epoch: u64,
    /// Whether a recorder is in it (C§5).
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub recorded: Value,
    /// The recorders in it, `[{device, subject}]`.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub recorders: Value,
    /// Whether content may be sent there (C§5: every recorder accepted).
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub may_send: Value,
    /// The recorders the user has still to accept.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub recorders_pending: Value,
    /// Its hub.
    pub hub: Hub,
    /// The items not yet accepted by the hub, with those kept for a successor (M§9.4).
    pub pending: usize,
    /// Whether its hub is unreachable (M§9.4).
    pub hub_down: bool,
    /// The groups it succeeds, by lineage (M§7.5).
    pub predecessors: Vec<String>,
}

/// A payload sealed for upload (M§8.4 rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct SealedBlob {
    /// `nonce ‖ ciphertext ‖ tag`, base64url: the bytes uploaded.
    pub sealed: String,
    /// The single-use key, base64url.
    pub key: String,
    /// Hex SHA-256 of the stored bytes.
    pub sha256: String,
    /// Their size.
    pub size: usize,
}

/// A blob uploaded for an `audio` content (M§8.2, M§8.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(default)]
pub struct BlobRef {
    /// Where it was uploaded.
    pub uri: String,
    /// Hex SHA-256 of the stored bytes.
    pub sha256: String,
    /// Their size.
    pub size: u64,
    /// The key, base64url.
    pub key: String,
    /// The media type.
    pub content_type: String,
}

/// What a device does after its blob sources answered (M§8.4 rule 7, the pinned `blob_fetch`, spec-gap 106).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum FetchDecision {
    /// Play the bytes `source` served.
    Play {
        /// The source.
        source: String,
    },
    /// Try again later.
    Retry {
        /// Why: `unavailable`.
        reason: String,
    },
    /// Stop trying.
    GiveUp {
        /// Why.
        reason: String,
    },
}

impl From<crate::blob::Fetch> for FetchDecision {
    fn from(f: crate::blob::Fetch) -> FetchDecision {
        match f {
            crate::blob::Fetch::Play(source) => FetchDecision::Play { source },
            crate::blob::Fetch::Retry => FetchDecision::Retry { reason: "unavailable".into() },
            crate::blob::Fetch::GiveUp(reason) => FetchDecision::GiveUp { reason },
        }
    }
}

/// What a device discloses to other identities (M§10.5, M§11); `delivered` defaults on, the rest off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(default)]
pub struct ReceiptPolicy {
    /// `delivered` receipts.
    pub delivered: bool,
    /// Read watermarks to the conversation (else to the personal group).
    pub read: bool,
    /// `played` receipts.
    pub played: bool,
    /// Activity (M§11).
    pub activity: bool,
}

impl Default for ReceiptPolicy {
    fn default() -> ReceiptPolicy {
        ReceiptPolicy { delivered: true, read: false, played: false, activity: false }
    }
}

/// A device a `key-packages` answer would add (M§5.5, M§6.2, C§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct KeyPackageDevice {
    /// The device.
    pub device: String,
    /// Whether it is a recorder (C§5).
    pub recorder: bool,
}

/// An introduction made (M§14.1, spec-gap 81).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Introduction {
    /// Its id.
    pub id: String,
    /// The compact envelope to deposit at the target's mailbox.
    pub envelope: String,
    /// The `mailbox-config` telling this identity's own mailbox first.
    pub send: String,
}

/// A request answered with a grant (M§14.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Granted {
    /// Who asked.
    pub requester: String,
    /// The grant's compact envelope, to deposit at the requester's mailbox.
    pub envelope: String,
}
