//! The messaging device in the browser (client stage 6): `dsip_messaging_device::messenger::Messenger`, the device
//! side of the Messaging Profile on OpenMLS, bound for JavaScript. It is driven with JSON strings and emits frames and
//! events, as the §12 engine is driven; every method forwards to the library (dsip-rs stage 3j-2).
//!
//! Spec: M§4–M§14 as the library implements them (`dsip_messaging_device::messenger`); §7.4 (a delegation re-issued
//! with `dsip.messaging`, [`redelegate`]).
//!
//! Impl: MLS state lives in OpenMLS's memory storage and is exported with the delivery state in one `save()`, which
//! the host writes as one record after each step — the atomic commit of spec-gap 44 in a browser.

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use dsip_core::envelope::{self, Envelope};
use dsip_core::keys::KeyPair;
use dsip_messaging_device::messenger::{Error, Messenger as Inner};

use crate::{js, unhex};

fn js_err(e: Error) -> JsValue {
    JsValue::from_str(&e.0)
}

/// The library's typed result as the JSON text this binding still returns (dsip-rs B3c makes it an object).
fn text<T: serde::Serialize>(v: T) -> String {
    serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())
}

/// A JSON parameter as the library's typed input, refused as the library refused unreadable JSON.
fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// A JSON parameter the library read leniently: what does not parse is `T::default()`.
fn lenient<T: serde::de::DeserializeOwned + Default>(json: &str) -> T {
    serde_json::from_str(json).unwrap_or_default()
}

/// A messaging device: this identity's device key under its delegation, its MLS groups, and the state the
/// Messaging Profile asks a device to keep (M§5.4, M§8.5). The host moves frames between it and the mailbox.
#[wasm_bindgen]
pub struct Messenger(Inner);

#[wasm_bindgen]
impl Messenger {
    /// `identity_json` as returned by `create_identity`; `mailbox_did`/`mailbox_uri` this identity's mailbox
    /// (M§4.2: the operator's, from `config.json`, or the person's); `saved_json` what [`Messenger::save`] returned,
    /// or null for a fresh device.
    #[wasm_bindgen(constructor)]
    pub fn new(identity_json: &str, mailbox_did: &str, mailbox_uri: &str, saved_json: Option<String>, now: f64) -> Result<Messenger, JsValue> {
        Inner::new(identity_json, mailbox_did, mailbox_uri, saved_json, now).map(Messenger).map_err(js_err)
    }

    /// Everything to keep: the MLS storage and this device's delivery state, as one JSON record. The host writes it
    /// after every step that returned something (spec-gap 44: MLS state and delivery state committed together).
    pub fn save(&self) -> String {
        self.0.save()
    }

    /// Whether this device's delegation carries `dsip.messaging` (M§4.3): without it the mailbox refuses the binding.
    pub fn delegation_ok(&self) -> bool {
        self.0.delegation_ok()
    }

    /// The identity's mailbox `{did, uri}`.
    pub fn mailbox(&self) -> String {
        text(self.0.mailbox())
    }

    /// Grants held from others, `{identity: compact}` (from the calling engine's contact file, §19.4): what is
    /// presented to the peer's mailbox (M§14.2), beside grants that arrive through this mailbox.
    pub fn set_grants(&mut self, grants_json: &str) {
        self.0.set_grants(&lenient(grants_json))
    }

    /// M§10.5: disclose read watermarks to the conversation (`true`) or keep them in the personal group (`false`,
    /// the default). Applies to every conversation's receipts machine.
    pub fn set_read_disclosed(&mut self, disclosed: bool, now: f64) {
        self.0.set_read_disclosed(disclosed, now)
    }

    /// The user has read a conversation through `content_id` (M§10.3): the receipts machine decides whether a
    /// watermark goes out, to the conversation or to the personal group (M§10.5), at most one per 5 s. Frames and
    /// events, as `inbound` returns them.
    pub fn read_through(&mut self, gid: &str, content_id: &str, now: f64) -> String {
        text(self.0.read_through(gid, content_id, now))
    }

    /// Advance every conversation's clock (M§10.3: a read held back by the 5 s interval goes out when it passes).
    pub fn tick(&mut self, now: f64) -> String {
        text(self.0.tick(now))
    }

    /// This device's hub-outage threshold, seconds (M§9.4: the client's own; 24 h RECOMMENDED).
    pub fn set_hub_timeout(&mut self, seconds: f64) {
        self.0.set_hub_timeout(seconds)
    }

    /// Seconds a seq gap may stay open before this device re-joins the group by external commit (M§6.5, spec-gap 69;
    /// RECOMMENDED 300). Set before the device processes anything: each group's tracker takes it when made.
    pub fn set_gap_timeout(&mut self, seconds: f64) {
        self.0.set_gap_timeout(seconds as i64)
    }

    /// Groups whose hub is unreachable: `{group: {down_since, pending, abandoned}}` (M§9.4).
    pub fn outages(&self) -> String {
        text(self.0.outages())
    }

    /// Create the successor of `dead` (M§7.5) once its hub has been unreachable past the threshold: a group for the
    /// same conversation hubbed at this identity's mailbox, `successor_of` naming the dead group, re-adding the dead
    /// group's last roster from `key_packages_json` (`{identity: key-packages answer}`, fetched with `successor_of`,
    /// M§7.5 spec-gap 61). When this device already converged on a successor, that one is used. The pending items
    /// follow once the successor holds its members (M§9.4). Frames.
    pub fn create_successor(&mut self, dead: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        self.0.create_successor(dead, &lenient(key_packages_json), now).map_err(js_err).map(text)
    }

    /// The hand-over to a successor could not be done (the peers' KeyPackages could not be fetched): retried with the
    /// §13.2 backoff (M§9.4, spec-gap 72).
    pub fn successor_failed(&mut self, dead: &str) {
        self.0.successor_failed(dead)
    }

    /// Add one device of this identity (M§12.3, M§6.7) to `gid` from its mailbox's `key-packages` answer (only the
    /// package of `device` is used): the commit to deposit. After the personal group's add is accepted, every live
    /// archive key is re-sent there ([`Messenger::resend_archive_keys`]). The groups to add it to, in order, are
    /// [`Messenger::groups_for_new_device`].
    pub fn add_device(&mut self, gid: &str, device: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        self.0.add_device(gid, device, &parse(key_packages_json)?, now).map_err(js_err)
    }

    /// The groups a new device of this identity joins, in order: the personal group first (M§12.3 step 3), then
    /// every conversation it is not in yet (M§6.7); `[]` when it is everywhere already.
    pub fn groups_for_new_device(&self, device: &str, now: f64) -> String {
        text(self.0.groups_for_new_device(device, now))
    }

    /// M§12.3 step 3: every live archive key, as `archive-key` objects to the personal group, so a device just added
    /// can read the archive. Frames to send.
    pub fn resend_archive_keys(&mut self, now: f64) -> String {
        text(self.0.resend_archive_keys(now))
    }

    /// Archive keys this device holds, `[{akid, created_at}]`, newest current (M§12.1).
    pub fn archive_keys(&self) -> String {
        text(self.0.archive_keys())
    }

    /// Groups this identity's mailbox delivered a GroupInfo for that this device is not in (M§6.8): what it can join by
    /// external commit. `[{group, conversation, kind}]`, the personal group first.
    pub fn available(&self) -> String {
        text(self.0.available())
    }

    /// Join `gid` by external commit (M§6.8): a device of an identity that has a leaf there, or the identity's own
    /// personal group, with no sibling online to add it. The commit goes to the hub; a `commit-conflict` or
    /// `stale-epoch` refusal discards the joined state, syncs and joins again from the newer GroupInfo (the pinned
    /// `CommitRetry`, spec-gap 58). No archive key comes with it: history waits for a sibling (M§12.3). Frames.
    pub fn external_join(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        self.0.external_join(gid, now).map_err(js_err).map(text)
    }

    /// A callee leg of this device ended (M§13.3): whether it sends a `call-event` to the personal group, by the
    /// vector-pinned decision (spec-gap 63) — alerted here and not answered here, never `session.answered-elsewhere`;
    /// `declined` when this device ended it with `user.declined`, else `missed`. `leg_json` is `{session, peer, alerted,
    /// answered_here, ended_by: "local"|"remote", reason}`. Frames to send (`[]` when none).
    pub fn call_ended(&mut self, leg_json: &str, now: f64) -> Result<String, JsValue> {
        self.0.call_ended(&parse(leg_json)?, now).map_err(js_err).map(text)
    }

    /// One leg's `call-record` for this identity's record-keeper `keeper` (C§9), built from what the host saw of the
    /// leg: `leg_json` is `{session, direction, peer, relay?, invited_at, answered, answered_at?, ended_by, reason?,
    /// media?, evidence?}`. The outcome is the pinned order (`call-record-outcome`); `answered_at` goes in exactly when
    /// it is `answered`; `ended_at` is now. A record the record-keeper would drop (`check: "object"`) is never sent.
    /// The record is held, then everything held goes to the conversation with `keeper` if it exists
    /// ([`Messenger::flush_records`]). Returns `{record, frames}`.
    ///
    /// Spec: C§9 (v0.13, spec-gaps 121 and 123).
    pub fn call_record(&mut self, keeper: &str, leg_json: &str, now: f64) -> Result<String, JsValue> {
        self.0.call_record(keeper, &parse(leg_json)?, now).map_err(js_err).map(text)
    }

    /// The held call records, sent to the direct conversation with `keeper` when there is one (C§9: the record-keeper
    /// opens it, spec-gap 123); frames to send, `[]` while there is none.
    pub fn flush_records(&mut self, keeper: &str, now: f64) -> Result<String, JsValue> {
        self.0.flush_records(keeper, now).map_err(js_err).map(text)
    }

    /// Leave the conversation `gid` for this identity (M§7.3 "Leaving", spec-gap 125): a Remove proposal for each of
    /// its leaves goes to the hub, another member commits them, and until then nothing is sent there and it is not
    /// listed. The personal group is never left. Returns the frames to send.
    pub fn leave(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        self.0.leave(gid, now).map_err(js_err).map(text)
    }

    /// The user accepted the recording of `gid` (C§5): every recorder now in it is accepted for this conversation, and
    /// a `recording-acceptance` goes to the personal group so this identity's other devices accept them too. Returns
    /// `{accepted: [device], frames}`; content may then be sent there. A recorder that joins later asks again.
    ///
    /// Spec: C§5 "Acceptance is the person's, not one device's".
    pub fn accept_recording(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        self.0.accept_recording(gid, now).map_err(js_err).map(text)
    }

    /// How many of this device's call records wait for the conversation with the record-keeper (C§9).
    pub fn held_records(&self) -> usize {
        self.0.held_records()
    }

    /// As a record-keeper: the records received (C§9), `[{group, from, device, received_at, record}]`.
    pub fn records(&self) -> String {
        text(self.0.records())
    }

    /// Whether this device is a recorder (its delegation carries `dsip.record`, C§5).
    pub fn is_recorder(&self) -> bool {
        self.0.is_recorder()
    }

    /// The call log, one entry per session (M§13.3).
    pub fn calls(&self) -> String {
        text(self.0.calls())
    }

    /// One conversation's timeline (M§13.3, the pinned `peer_timeline`): its messages with this identity's call events
    /// for the peer interleaved — `{"call": {…}}` or the message as [`Messenger::thread`] gives it.
    pub fn timeline(&self, gid: &str) -> String {
        text(self.0.timeline(gid))
    }

    /// Whether this device can send to `peer` (M§13.2 condition 2): a direct conversation exists, or a grant from them
    /// is held that would let one be created (M§14.2).
    pub fn can_send(&self, peer: &str) -> bool {
        self.0.can_send(peer)
    }

    /// Seal a payload for upload (M§8.4 rule 1): a fresh single-use 32-byte key, AES-256-GCM, no AAD, stored as
    /// `nonce ‖ ciphertext ‖ tag`. Returns `{"sealed": b64url, "key": b64url, "sha256": hex, "size": n}`.
    pub fn seal_blob(&self, plain_b64: &str) -> String {
        text(self.0.seal_blob(plain_b64))
    }

    /// The `blob-put` that authorizes one upload of `sha256`/`size` to this identity's mailbox (M§5.6), as the compact
    /// envelope for `Authorization: DSIP …`, carrying the device's delegation (M§5.1).
    pub fn blob_put(&self, sha256: &str, size: f64, now: f64) -> String {
        self.0.blob_put(sha256, size, now)
    }

    /// An `audio` content object (M§8.2) for a blob already uploaded: `blob_json` is `{uri, sha256, size, key, content_type}`
    /// from [`Messenger::seal_blob`] and the upload; `purpose` `voice-message` or `voicemail` (with `session`). The deposit
    /// carries the manifest without the key (M§8.4 rule 4). The frame to send.
    pub fn send_audio(&mut self, gid: &str, blob_json: &str, duration_ms: f64, purpose: &str, session: Option<String>, now: f64) -> Result<String, JsValue> {
        self.0.send_audio(gid, &parse(blob_json)?, duration_ms, purpose, session, now).map_err(js_err)
    }

    /// Where to fetch a content's blob from, in order (M§8.4 rules 6–7, the pinned `blob_sources`): the manifest's copy
    /// at another `uri` for the same `sha256` and `size`, then the content's own. `object_json` is the content object,
    /// `manifest_json` the item's `blobs` (or null).
    pub fn blob_sources(&self, object_json: &str, manifest_json: &str) -> String {
        text(self.0.blob_sources(&lenient(object_json), &lenient(manifest_json)))
    }

    /// Open a fetched blob for a content object (M§8.4 rule 7): the size and SHA-256 must match the content's `blob`
    /// before it is decrypted under the key the content carries. The plaintext, base64url, or the refusal code.
    pub fn open_blob(&self, object_json: &str, stored_b64: &str) -> Result<String, JsValue> {
        self.0.open_blob(&parse(object_json)?, stored_b64).map_err(js_err)
    }

    /// One source's answer as the fetch decision takes it (`status` 0: not reached; `stored_b64`, bytes a 200 served
    /// that did not open, or empty): `{uri, status, sha256?, size?}` (M§8.4 rule 7, spec-gap 106).
    pub fn blob_tried(&self, uri: &str, status: u16, stored_b64: &str) -> String {
        text(self.0.blob_tried(uri, status, stored_b64))
    }

    /// Seconds before fetch `attempt` is tried again (spec-gap 67's schedule: 4 s doubling, at most 60 s).
    pub fn blob_retry_delay_s(&self, attempt: f64) -> f64 {
        self.0.blob_retry_delay_s(attempt)
    }

    /// What a device does after its blob sources answered (`tried`: `[{uri, status, sha256?, size?}]`; the pinned
    /// `blob_fetch`, spec-gap 106): `{"action": "retry"|"give-up", "reason"}`.
    pub fn blob_fetch_decision(&self, object_json: &str, tried_json: &str, attempt: f64) -> String {
        text(self.0.blob_fetch_decision(&lenient(object_json), &lenient::<Vec<_>>(tried_json), attempt))
    }

    /// The user played an `audio` or `video` content (M§10.4): a `played` receipt under the same opt-in as `read`
    /// (M§10.5). Frames and events, as `inbound` returns them.
    pub fn played(&mut self, gid: &str, content_id: &str, now: f64) -> String {
        text(self.0.played(gid, content_id, now))
    }

    /// A DID document to hold (§8.1), for `did:web` peers.
    pub fn add_document(&mut self, doc_json: &str) -> bool {
        match serde_json::from_str(doc_json) {
            Ok(doc) => {
                self.0.add_document(doc);
                true
            }
            Err(_) => false,
        }
    }

    /// The client `hello` to send first on a connection to a mailbox (§13.2, M§4.3); one per connection.
    pub fn hello_frame(&mut self, now: f64) -> String {
        self.0.hello_frame(now)
    }

    /// Verify a service's `hello` (must echo one of ours, §20.5). Returns `{"ok":true,"did":…,"capabilities":…}` or
    /// `{"ok":false,"code":…}`. Named as the relay host expects, so one connection class serves both.
    pub fn relay_hello(&mut self, frame: &str, now: f64) -> String {
        match self.0.relay_hello(frame, now) {
            Ok(h) => json!({"ok": true, "did": h.did, "capabilities": h.capabilities}),
            Err(code) => json!({"ok": false, "code": code}),
        }
        .to_string()
    }

    /// A `sync` for this identity's mailbox (M§5.4): `since`/`ack_through` from the durable state, `live` once asked.
    pub fn sync_frame(&mut self, live: bool, now: f64) -> String {
        self.0.sync_frame(live, now)
    }

    /// A `key-packages` upload of `n` fresh KeyPackages and a last-resort one (M§5.5, M§6.7).
    pub fn key_packages_frame(&mut self, n: usize, now: f64) -> Result<String, JsValue> {
        self.0.key_packages_frame(n, now).map_err(js_err)
    }

    /// What to send on a fresh binding: pending application items again (M§9.3, the same bytes), then a sync.
    pub fn on_bound(&mut self, now: f64) -> String {
        text(self.0.on_bound(now))
    }

    /// Create this identity's personal group at its mailbox (M§7.1): the `mailbox-config` that registers it and the
    /// GroupInfo deposit; the first archive key follows once the hub holds the group (M§12.1). Frames to send.
    pub fn create_personal(&mut self, now: f64) -> Result<String, JsValue> {
        self.0.create_personal(now).map_err(js_err).map(text)
    }

    /// A `key-package-fetch` for `target` to send on a connection to `to_mailbox` (M§5.5), presenting the grant
    /// held from `target` if any (M§14.2).
    /// `successor_of` names the dead group a successor is created for: the target's mailbox serves it without a
    /// grant when that group is registered for the target (M§7.5, spec-gap 61).
    pub fn fetch_frame(&mut self, to_mailbox: &str, target: &str, now: f64, successor_of: Option<String>) -> String {
        self.0.fetch_frame(to_mailbox, target, now, successor_of)
    }

    /// Create a direct conversation with `target` from its mailbox's `key-packages` answer (M§7.2): every device of
    /// the target the vector-pinned rule picks (C§5), plus this identity's own other devices from `own_json` (the
    /// same answer shape, or null), in one commit once the group is hubbed. Returns the frames to send, or the refusal.
    pub fn create_direct(&mut self, target: &str, key_packages_json: &str, own_json: Option<String>, now: f64) -> Result<String, JsValue> {
        let own: Option<Value> = own_json.and_then(|o| serde_json::from_str(&o).ok());
        self.0.create_direct(target, &parse(key_packages_json)?, own.as_ref(), now).map_err(js_err).map(text)
    }

    /// Create a group conversation (M§7.3, `kind: group`) with the identities of `targets_json`, `{identity: its
    /// mailbox's key-packages answer}`, plus this identity's own other devices from `own_json` (or null): every device
    /// the vector-pinned rule picks, added in one commit once the group is hubbed at this identity's mailbox, with the
    /// grants held from them (M§14.2). Returns the frames to send.
    pub fn create_group(&mut self, targets_json: &str, own_json: Option<String>, now: f64) -> Result<String, JsValue> {
        let own: Option<Value> = own_json.and_then(|o| serde_json::from_str(&o).ok());
        self.0.create_group(&parse(targets_json)?, own.as_ref(), now).map_err(js_err).map(text)
    }

    /// Add `target`'s devices to the group conversation `gid` from its mailbox's `key-packages` answer (M§7.3: any
    /// member identity MAY add another, holding its grant, M§14.2): the commit to deposit.
    pub fn add_member(&mut self, gid: &str, target: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        self.0.add_member(gid, target, &parse(key_packages_json)?, now).map_err(js_err)
    }

    /// Remove the member identity `target` from the conversation `gid`, every leaf of it (M§7.3: any member identity
    /// MAY remove another; this identity leaves with [`Messenger::leave`] instead): the commit to deposit.
    pub fn remove_member(&mut self, gid: &str, target: &str, now: f64) -> Result<String, JsValue> {
        self.0.remove_member(gid, target, now).map_err(js_err)
    }

    /// Move the conversation `gid` to this identity's own mailbox as its hub (M§7.4: while the hub is alive, any member
    /// MAY move the group): the commit to deposit at the current hub. On `accepted` this device's mailbox follows and
    /// the new hub is bootstrapped with the GroupInfo and `handover_seq`.
    pub fn move_hub(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        self.0.move_hub(gid, now).map_err(js_err)
    }

    /// Refresh this device's own leaf key material in `gid` (post-compromise security): an Update commit (M§6.5). The
    /// frame to send.
    pub fn rekey(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        self.0.rekey(gid, now).map_err(js_err)
    }

    /// The roster changes of a conversation and its predecessors, oldest first: `[{group, seq, epoch, by, added,
    /// removed, left}]` (M§7.3: rendered, attributed to the committing identity).
    pub fn roster_log(&self, gid: &str) -> String {
        text(self.0.roster_log(gid))
    }

    /// A text message to a conversation (M§8.1 `content`, kind `text`): the deposit to send, pending until the hub's
    /// `accepted` (M§9.2).
    pub fn send_text(&mut self, gid: &str, text: &str, now: f64) -> Result<String, JsValue> {
        self.0.send_text(gid, text, now).map_err(js_err)
    }

    /// Conversations: `[{group, conversation, kind, peer, members, epoch, hub, pending, recorded, recorders, may_send,
    /// recorders_pending}]`; members are the leaves that authenticate at `now` (M§6.2); `pending` counts items not yet
    /// accepted by the hub; `recorders_pending` lists the recorders the user has still to accept (C§5).
    pub fn conversations(&self, now: f64) -> String {
        text(self.0.conversations(now))
    }

    /// The thread of one group in `seq` order (M§8.5): `[{key, sender, sender_device, object, seq, mine, delivered,
    /// from_archive}]`; `read_through` of the whole thread is `{identity: content id}` (M§10.3), in
    /// [`Messenger::read_marks`].
    pub fn thread(&self, gid: &str) -> String {
        text(self.0.thread(gid))
    }

    /// Each identity's read watermark in a conversation, `{identity: content id}` (M§10.3; a sibling's undisclosed
    /// one reaches us through the personal group, M§10.5).
    pub fn read_marks(&self, gid: &str) -> String {
        text(self.0.read_marks(gid))
    }

    /// Introductions delivered through the mailbox and not yet answered (M§14.1), `{id: payload}`.
    pub fn requests(&self) -> String {
        text(self.0.requests())
    }

    /// The personal group's id, once created.
    pub fn personal(&self) -> Option<String> {
        self.0.personal()
    }

    /// Process one frame from the mailbox. Returns the emissions: `{send: frame}` (to the mailbox), `{ui: …}`
    /// events, `{sync: true}` when a refused commit asks for one (spec-gap 58), `{refused: …}`, `{error: …}`.
    pub fn inbound(&mut self, frame: &str, now: f64) -> String {
        text(self.0.inbound(frame, now))
    }

    /// A fresh ULID (§12.9: timestamp-consistent with `now`).
    pub fn new_id(&mut self, now: f64) -> String {
        self.0.new_id(now)
    }
}

/// Re-issue this identity's delegation to its device with `dsip.messaging`, and `extra` when given (`dsip.record` for
/// a record-keeper, C§9), beside the capabilities it has (M§4.3, §7.4), signed by the identity key this browser
/// holds. The identity JSON with the new delegation, or an error when the identity key is not here (a device enrolled
/// from a file holds only its own key).
pub fn redelegate(identity_json: &str, now: i64, extra: Option<&str>) -> Result<String, JsValue> {
    let mut id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().ok_or_else(|| JsValue::from_str("no identity key on this device"))?)?);
    let old = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
    let mut caps = dsip_core::delegation::capabilities(&old);
    for c in ["dsip.messaging"].into_iter().chain(extra) {
        if !caps.iter().any(|x| x == c) {
            caps.push(c.into());
        }
    }
    let caps_ref: Vec<&str> = caps.iter().map(String::as_str).collect();
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), id["device"].as_str().unwrap_or(""), now - 60, now + 365 * 86_400, &caps_ref);
    let kid = if id["identity"].as_str().is_some_and(|i| i.starts_with("did:web:")) {
        format!("{}#key-1", id["identity"].as_str().unwrap_or(""))
    } else {
        controller.kid()
    };
    id["delegation"] = json!(envelope::sign(&payload, &controller, &kid).frame());
    Ok(id.to_string())
}
