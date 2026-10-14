//! The messaging device in the browser (client stage 6): the Messaging Profile's device side on OpenMLS, driven
//! with JSON strings and emitting frames and events, as the §12 engine is driven.
//!
//! Spec: M§4.2 (the mailbox a `did:key` identity names in its reachability hint; the peer's found the same way),
//! M§4.3 (bind with a verified `hello`; the delegation carries `dsip.messaging`), M§5.2–M§5.5 (`deposit`,
//! `accepted`, `sync`/`items`, `key-packages`/`key-package-fetch`), M§6.2 (every leaf authenticated), M§6.4 (wire
//! forms), M§6.5 (a commit is applied only on the hub's `accepted`; refusals as the vector-pinned `CommitRetry`
//! decides, spec-gap 58; seq gaps held by `GapTracker`, spec-gap 69), M§6.6 (`mailbox-config` `joined`/`left`),
//! M§6.7 (KeyPackages uploaded), M§7.1 (the personal group and the first archive key), M§7.2 (a direct
//! conversation: the peer's devices and our own in one commit, hubbed at our mailbox, the held grant presented),
//! M§8.1 (content objects checked before rendering), M§8.5 (seq dedup and the ack cursor — `Resume`, spec-gap 44),
//! M§9.2–M§9.3 (pending until `accepted`; the same bytes re-deposited), M§10.2 (delivered receipts decided per sync
//! batch by the vector-pinned `Client`), M§12.1 (the archive key, kept for the device that will read history),
//! M§14.2 (a grant presented to the peer's mailbox), M§8.4 and M§5.6 (a blob sealed under a single-use key, uploaded
//! with a signed `blob-put`, named with its key in the content and without it in the manifest; fetched from the
//! sources the pinned rule orders and verified before it is opened), M§8.2 (`audio` content), M§10.4 (`played`, under
//! the same opt-in as `read`), M§13.2–M§13.3 (voicemail as caller-recorded audio carrying the session; a callee
//! leg's call event to the personal group, collapsed by session, interleaved into the peer's timeline), M§9.4 (a hub
//! that stops answering: content kept pending and retried by the pinned outbox, and past the device's threshold handed
//! to a successor), M§7.5 (the successor created at this identity's mailbox, re-adding the dead group's roster;
//! a successor welcome checked and converged on by the pinned tracker), M§12.1–M§12.3 (archive keys, archive records written for what
//! is shown and read back as history by a device added later, every live key re-sent to a new sibling), M§10.3 and
//! M§10.5 (a read watermark per conversation, disclosed only with the opt-in, else to the personal group).
//!
//! Impl: MLS state lives in OpenMLS's memory storage and is exported with the delivery state in one `save()`, which
//! the host writes as one record after each step — the atomic commit of spec-gap 44 in a browser. A reload restores
//! both. Pending deposits (not yet `accepted`) are kept with their bytes and re-deposited on the next bind (M§9.3:
//! idempotent at the hub by digest). What this device does not do yet: archive records and history for a second
//! device by external commit (M§6.8), voice and blobs, successor groups; and a seq gap that does not fill is
//! reported, not re-joined (M§6.8).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::RwLock;

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_endpoint::hello::{client_hello, verify_relay_hello};
use dsip_endpoint::verify::SeenIds;
use dsip_endpoint::IdentityKeys;
use dsip_messaging::checks::check_object;
use dsip_messaging::client::{registration_on_removal, Client, CommitRetry, GapTracker, History, HubOutage, Resume, SuccessorTracker};
use dsip_messaging::mls_wire::{open as open_sealed, open_blob, seal, SealUse};
use dsip_messaging::verify::verify_frame;
use dsip_messaging::wire;
use dsip_mls::{authenticate_key_package, authenticate_members, conversation_extension, conversation_update, digest, external_commit, member_identity, message_header, Device, MlsError};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use crate::{js, unhex};

/// The MLS provider for the browser: OpenMLS's rust-crypto, with its memory storage — exported by [`Messenger::save`]
/// and restored by [`Messenger::new`], so a page reload keeps the groups and the KeyPackages' private halves.
#[derive(Default)]
pub struct BrowserProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for BrowserProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

fn b64(bytes: &[u8]) -> String {
    dsip_core::b64::encode(bytes)
}

fn unb64(v: &Value) -> Vec<u8> {
    v.as_str().and_then(dsip_core::b64::decode).unwrap_or_default()
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn compact(e: &Envelope) -> String {
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}

/// One group this device is in.
struct Conv {
    group: MlsGroup,
    conversation: String,
    kind: String,
    /// `(did, uri)` of the hub.
    hub: (String, String),
    /// The other identity of a direct conversation, once known.
    peer: Option<String>,
    /// M§10 receipts for this conversation (vector-pinned).
    receipts: Client,
    /// The epoch this device joined at: items from before are history (M§12.3), not for this device's MLS state.
    joined_epoch: u64,
    /// Content and receipts of the sync batch being processed (M§10.2 decides per batch).
    batch: Vec<Value>,
}

/// A membership change this device proposes (M§6.5): re-proposed after a lost conflict while still needed.
#[derive(Clone)]
enum Op {
    /// Add `peer`'s devices (and our own others) from these TLS-serialized KeyPackages, with the grants that
    /// authorize the add (M§14.2). `device` names one device of our own identity when that is what is added (M§12.3).
    Add { peer: String, kps: Vec<Vec<u8>>, grants: Vec<String>, device: Option<String> },
    /// Join the group by external commit from the latest GroupInfo this identity's mailbox delivered (M§6.8).
    Rejoin,
    /// Commit the pending Remove proposals by which `identity` leaves (M§7.3 "Leaving", spec-gap 125).
    Leave { identity: String },
    /// Remove every leaf of another member identity (M§7.3: any member identity MAY remove another).
    Remove { identity: String },
    /// Move the group to another hub, `{did, uri}`: a commit changing `dsip_conversation.hub` and nothing else (M§7.4).
    MoveHub { hub: Value },
}

/// A deposit awaiting the hub's answer, by deposit id (M§9.2).
#[derive(Clone)]
enum Pending {
    /// A commit staged in the group: merged on `accepted`, discarded on refusal (M§6.5). `fields` are the deposit's,
    /// re-deposited as the same MLS bytes when the answer is lost (M§9.3).
    Commit { gid: String, op: Option<Op>, fields: Value },
    /// A GroupInfo for the hub (M§6.5 rule 6); `then` is proposed once it is accepted.
    GroupInfo { gid: String, then: Option<Op> },
    /// An application message of this device's own, in the outbox until accepted (M§9.2).
    Application { gid: String, item: String },
    /// The archive key is sent to the personal group once its GroupInfo is accepted (M§7.1).
    PersonalReady { gid: String },
    /// A KeyPackage upload (M§5.5).
    KeyPackages { count: usize },
    /// A `mailbox-config` (M§6.6) with these fields.
    Config { fields: Value },
    /// An archive record deposited to our mailbox (M§12.2) with these fields; acknowledged, nothing else to do.
    Archive { fields: Value },
    /// A Remove proposal of this device's leave (M§7.3): sequenced by the hub, nothing to merge.
    Proposal { gid: String },
}

impl Op {
    fn to_json(&self) -> Value {
        match self {
            Op::Add { peer, kps, grants, device } => {
                json!({"add": {"peer": peer, "kps": kps.iter().map(|k| b64(k)).collect::<Vec<_>>(), "grants": grants, "device": device}})
            }
            Op::Rejoin => json!("rejoin"),
            Op::Leave { identity } => json!({"leave": identity}),
            Op::Remove { identity } => json!({"remove": identity}),
            Op::MoveHub { hub } => json!({"move_hub": hub}),
        }
    }

    fn from_json(v: &Value) -> Option<Op> {
        if v == "rejoin" {
            return Some(Op::Rejoin);
        }
        if let Some(i) = v.get("leave").and_then(Value::as_str) {
            return Some(Op::Leave { identity: i.to_string() });
        }
        if let Some(i) = v.get("remove").and_then(Value::as_str) {
            return Some(Op::Remove { identity: i.to_string() });
        }
        if let Some(h) = v.get("move_hub") {
            return Some(Op::MoveHub { hub: h.clone() });
        }
        let a = v.get("add")?;
        Some(Op::Add {
            peer: s_of(&a["peer"]),
            kps: a["kps"].as_array()?.iter().map(unb64).collect(),
            grants: serde_json::from_value(a["grants"].clone()).unwrap_or_default(),
            device: a["device"].as_str().map(String::from),
        })
    }
}

impl Pending {
    /// What survives a restart: everything but application items, which the outbox holds (M§9.2), and key package
    /// uploads, made afresh.
    fn to_json(&self) -> Option<Value> {
        Some(match self {
            Pending::Commit { gid, op, fields } => json!({"commit": {"gid": gid, "op": op.as_ref().map(Op::to_json), "fields": fields}}),
            Pending::GroupInfo { gid, then } => json!({"group_info": {"gid": gid, "then": then.as_ref().map(Op::to_json)}}),
            Pending::PersonalReady { gid } => json!({"personal_ready": gid}),
            Pending::Config { fields } => json!({"config": fields}),
            Pending::Archive { fields } => json!({"archive": fields}),
            Pending::Application { .. } | Pending::KeyPackages { .. } | Pending::Proposal { .. } => return None,
        })
    }

    fn from_json(v: &Value) -> Option<Pending> {
        let op = |o: &Value| if o.is_null() { None } else { Op::from_json(o) };
        if let Some(c) = v.get("commit") {
            return Some(Pending::Commit { gid: s_of(&c["gid"]), op: op(&c["op"]), fields: c["fields"].clone() });
        }
        if let Some(g) = v.get("group_info") {
            return Some(Pending::GroupInfo { gid: s_of(&g["gid"]), then: op(&g["then"]) });
        }
        if let Some(g) = v.get("personal_ready") {
            return Some(Pending::PersonalReady { gid: s_of(g) });
        }
        if let Some(f) = v.get("config") {
            return Some(Pending::Config { fields: f.clone() });
        }
        v.get("archive").map(|f| Pending::Archive { fields: f.clone() })
    }
}

/// What processing one inbound item produced.
enum Outcome {
    /// A welcome joined; `by` is the identity whose commit added this device (the GroupInfo's signer).
    Joined { members: Vec<String>, group: String, conv: Value, epoch: u64, by: String },
    NotForDevice,
    Object { sender: String, sender_device: String, object: Value },
    Dropped(String),
    Unauthenticated(String),
    /// A commit merged; `left` names the identities it removed by their own Remove proposals (M§7.3 "Leaving").
    Epoch { epoch: u64, by: String, added: Vec<String>, removed: Vec<String>, left: Vec<String>, hub: Option<Value> },
    Removed { by: String, remaining: Vec<String> },
    /// A proposal stored for the next commit (M§7.3 "Leaving"): the proposer's identity's pending proposals in this
    /// epoch, Remove ones as `{identity, device}` and the count of others, with the group's roster.
    Proposal { proposer: Value, removes: Vec<Value>, others: usize, roster: Vec<Value> },
    Nothing,
}

fn mls_err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> MlsError {
    move |e| MlsError(format!("{what}: {e:?}"))
}

/// A messaging device: this identity's device key under its delegation, its MLS groups, and the state the
/// Messaging Profile asks a device to keep (M§5.4, M§8.5). The host moves frames between it and the mailbox.
#[wasm_bindgen]
pub struct Messenger {
    keys: IdentityKeys,
    controller_seed: Option<[u8; 32]>,
    mls: Device<BrowserProvider>,
    mailbox: (String, String),
    resolver: StaticResolver,
    seen: SeenIds,
    supported: Supported,
    /// Hello ids sent and not yet answered: one per connection being opened (§20.5 anti-splicing).
    hello_ids: BTreeSet<String>,
    counter: u64,
    convs: BTreeMap<String, Conv>,
    personal: Option<String>,
    resume: Resume,
    /// Digests of this device's own deposits: the hub fans them back and MLS cannot decrypt them (spec-gap 47).
    own: HashSet<String>,
    pending: BTreeMap<String, Pending>,
    /// Application items not yet accepted, per group, oldest first: `{id, mls, obj}` (M§9.2).
    outbox: BTreeMap<String, Vec<Value>>,
    /// The thread, every content object shown, in arrival order: `{group, key, sender, sender_device, object, seq, mine}`.
    messages: Vec<Value>,
    /// Object keys shown (M§8.5: the archive and MLS copies are one message).
    shown: BTreeSet<String>,
    /// Grants other identities issued to this one, by granter: compact envelopes (§19.4; presented at M§14.2).
    grants_held: BTreeMap<String, String>,
    /// Archive keys by `akid`: `(key, created_at)` (M§12.1).
    archive_keys: BTreeMap<String, (Vec<u8>, i64)>,
    /// The latest GroupInfo per group (M§6.8), base64url.
    group_info: BTreeMap<String, String>,
    /// Call events of this identity's devices, in personal-group order, one per `session` (M§13.3, spec-gap 63).
    calls: Vec<Value>,
    /// Seq gaps per group (M§6.5, spec-gap 69), and the items held behind them.
    gaps: BTreeMap<String, GapTracker>,
    held_items: BTreeMap<String, Vec<Value>>,
    /// Membership changes refused by the hub and waiting for a sync before re-proposal (spec-gap 58).
    retries: BTreeMap<String, (CommitRetry, Op)>,
    /// The hub that answered a deposit `mailbox.unknown-group`, by group: after the sync, a different hub means the
    /// group moved (M§7.4 "A member that missed the move").
    unknown_at: BTreeMap<String, String>,
    /// Application items refused `mailbox.unknown-group`, by group, held until the sync shows whether the group moved:
    /// re-encrypted and re-sent to the new hub if it did, refused for good if not (M§7.4).
    moved_items: BTreeMap<String, Vec<String>>,
    /// Introductions delivered through the mailbox, by id (M§14.1: requests, never messages).
    requests: BTreeMap<String, Value>,
    want_live: bool,
    gap_timeout: i64,
    /// History (M§12): archive keys and join epochs, what to archive, records held until their key arrives.
    history: History,
    /// Archive records under a key this device does not hold yet, by cursor, still sealed (M§12.3 step 5).
    held_archive: BTreeMap<String, Value>,
    /// Content and receipts opened from archive and waiting for their conversation to be joined (spec-gap 64).
    restored: Vec<Value>,
    /// M§10.5: whether read watermarks are disclosed to the conversation (opt-in) or kept in the personal group.
    read_disclosed: bool,
    /// M§9.4: per group whose hub stopped answering, the vector-pinned outbox; `hub_timeout` is this device's threshold.
    outages: BTreeMap<String, HubOutage>,
    hub_timeout: i64,
    /// When each application deposit went out, by deposit id: one with no answer at all counts as the hub down (M§9.4).
    sent_at: BTreeMap<String, i64>,
    /// M§7.5: the successor groups this device knows of and converged on (vector-pinned, spec-gap 61).
    successors: SuccessorTracker,
    /// Objects of an abandoned group's outbox, by the group they go to: the dead group until its successor exists,
    /// then the successor until it holds its members (M§9.4: re-encrypted for the successor, spec-gap 72).
    handover: BTreeMap<String, Vec<Value>>,
    /// The mailbox this state was saved at; a different one at start is a move. Spec: M§4.1 "Moving to another
    /// mailbox" (v0.13, spec-gap 122): the device registers every group it is in at the new mailbox and syncs it from
    /// the start.
    moved_from: Option<String>,
    /// Whether this device's delegation carries `dsip.record` (C§5): a recorder device, receive-only, never in its
    /// identity's personal group; as a record-keeper it keeps the `call-record`s parties send it (C§9).
    recorder: bool,
    /// This device's call records not yet handed to the conversation with its record-keeper, oldest first (C§9: held
    /// until that conversation exists, spec-gap 123).
    records_held: Vec<Value>,
    /// As a record-keeper: the records received, `{group, from, device, received_at, record}`, one per session leg.
    records: Vec<Value>,
    /// Recorder devices this identity accepted, by conversation id: this device's acceptances and its siblings', from
    /// the `recording-acceptance` objects in the personal group (C§5: the union).
    recording_accepted: BTreeMap<String, BTreeSet<String>>,
    /// Groups this identity is leaving (M§7.3): nothing is sent there and they are not listed; the device proposes its
    /// identity's removal again at each new epoch until a commit removes it.
    leaving: BTreeSet<String>,
    /// Each group's roster changes by identity, oldest first: `{seq, epoch, by, added, removed, left}` (M§7.3: every
    /// roster change rendered, attributed to the committing identity).
    roster_log: BTreeMap<String, Vec<Value>>,
}

#[wasm_bindgen]
impl Messenger {
    /// `identity_json` as returned by `create_identity`; `mailbox_did`/`mailbox_uri` this identity's mailbox
    /// (M§4.2: the operator's, from `config.json`, or the person's); `saved_json` what [`Messenger::save`] returned,
    /// or null for a fresh device.
    #[wasm_bindgen(constructor)]
    pub fn new(identity_json: &str, mailbox_did: &str, mailbox_uri: &str, saved_json: Option<String>, now: f64) -> Result<Messenger, JsValue> {
        let id: Value = serde_json::from_str(identity_json).map_err(js)?;
        let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
        let delegation = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
        let keys = IdentityKeys {
            identity: id["identity"].as_str().unwrap_or("").to_string(),
            device: device.clone(),
            delegation: delegation.clone(),
            display_name: id["display_name"].as_str().unwrap_or("").to_string(),
        };
        let controller_seed = id["controller_seed_hex"].as_str().and_then(|h| unhex(h).ok());
        let saved: Value = saved_json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        // the MLS storage as saved: `{b64url key: b64url value}`
        let mut values = std::collections::HashMap::new();
        for (k, v) in saved["mls"].as_object().into_iter().flatten() {
            if let (Some(k), Some(v)) = (dsip_core::b64::decode(k), v.as_str().and_then(dsip_core::b64::decode)) {
                values.insert(k, v);
            }
        }
        let provider = BrowserProvider { crypto: RustCrypto::default(), storage: MemoryStorage { values: RwLock::new(values) } };
        let mls = Device::with_provider(device, compact(&delegation), provider);
        let st = &saved["state"];
        let now_i = now as i64;
        let mut m = Messenger {
            keys,
            controller_seed,
            mls,
            mailbox: (mailbox_did.to_string(), mailbox_uri.to_string()),
            resolver: StaticResolver::default(),
            seen: SeenIds::default(),
            supported: Supported::all_known(),
            hello_ids: BTreeSet::new(),
            counter: 0,
            convs: BTreeMap::new(),
            personal: st["personal"].as_str().map(String::from),
            resume: Resume::new(if st["resume"].is_object() { &st["resume"] } else { &Value::Null }),
            own: st["own"].as_array().into_iter().flatten().map(s_of).collect(),
            // M§9.3: deposits awaiting an answer are sent again at the next binding (redeposit_pending)
            pending: st["pending"].as_object().into_iter().flatten().filter_map(|(id, p)| Some((id.clone(), Pending::from_json(p)?))).collect(),
            outbox: serde_json::from_value(st["outbox"].clone()).unwrap_or_default(),
            messages: st["messages"].as_array().cloned().unwrap_or_default(),
            shown: st["messages"].as_array().into_iter().flatten().map(|m| s_of(&m["key"])).collect(),
            grants_held: serde_json::from_value(st["grants_held"].clone()).unwrap_or_default(),
            archive_keys: st["archive_keys"].as_object().into_iter().flatten()
                .map(|(a, v)| (a.clone(), (unb64(&v["key"]), v["created_at"].as_i64().unwrap_or(0)))).collect(),
            group_info: serde_json::from_value(st["group_info"].clone()).unwrap_or_default(),
            calls: st["calls"].as_array().cloned().unwrap_or_default(),
            gaps: BTreeMap::new(),
            held_items: serde_json::from_value(st["held_items"].clone()).unwrap_or_default(),
            retries: BTreeMap::new(),
            unknown_at: BTreeMap::new(),
            moved_items: BTreeMap::new(),
            requests: serde_json::from_value(st["requests"].clone()).unwrap_or_default(),
            want_live: false,
            gap_timeout: 60,
            history: History::new(&Value::Null),
            held_archive: serde_json::from_value(st["held_archive"].clone()).unwrap_or_default(),
            restored: st["restored"].as_array().cloned().unwrap_or_default(),
            read_disclosed: st["read_disclosed"].as_bool().unwrap_or(false),
            outages: BTreeMap::new(),
            hub_timeout: dsip_messaging::client::HUB_TIMEOUT_S,
            sent_at: BTreeMap::new(),
            successors: serde_json::from_value(st["successors"].clone()).unwrap_or_default(),
            handover: serde_json::from_value(st["handover"].clone()).unwrap_or_default(),
            moved_from: st["mailbox"].as_str().filter(|d| *d != mailbox_did).map(String::from),
            recorder: dsip_core::delegation::capabilities(&delegation).iter().any(|c| c == "dsip.record"),
            records_held: st["records_held"].as_array().cloned().unwrap_or_default(),
            records: st["records"].as_array().cloned().unwrap_or_default(),
            recording_accepted: serde_json::from_value(st["recording_accepted"].clone()).unwrap_or_default(),
            leaving: serde_json::from_value(st["leaving"].clone()).unwrap_or_default(),
            roster_log: serde_json::from_value(st["roster_log"].clone()).unwrap_or_default(),
        };
        if let Some(t) = st["hub_timeout"].as_i64() {
            m.hub_timeout = t;
        }
        if m.moved_from.is_some() {
            // spec-gap 122: the cursors were the old mailbox's; the new one delivers from its own beginning
            m.resume.cursor_invalid();
        }
        // M§9.4: an outage survives a restart; its first retry is due at once
        for (gid, down_since) in st["outages"].as_object().into_iter().flatten() {
            let pending: Vec<Value> = m.outbox.get(gid).into_iter().flatten().map(|i| i["id"].clone()).collect();
            let mut o = HubOutage::new(&json!({"now": now_i, "hub_timeout": m.hub_timeout, "pending": pending, "down_since": down_since}));
            if down_since.is_null() {
                o = HubOutage::new(&json!({"now": now_i, "hub_timeout": m.hub_timeout}));
            }
            m.outages.insert(gid.clone(), o);
        }
        // the history machine from what this device holds: its keys and the epochs it joined at
        let keys: Vec<Value> = m.archive_keys.iter().map(|(a, (_, at))| json!({"akid": a, "created_at": at})).collect();
        let joined: serde_json::Map<String, Value> = st["convs"].as_object().into_iter().flatten()
            .map(|(g, c)| (g.clone(), c["joined_epoch"].clone())).collect();
        m.history = History::new(&json!({"keys": keys, "joined": joined}));
        // the groups: reloaded from the MLS storage by id, with what this device knew about each
        for (gid, c) in st["convs"].as_object().into_iter().flatten() {
            let Some(group) = m.mls.load_group(&dsip_core::b64::decode(gid).unwrap_or_default()).ok().flatten() else { continue };
            let conv = Conv {
                group,
                conversation: s_of(&c["conversation"]),
                kind: s_of(&c["kind"]),
                hub: (s_of(&c["hub"]["did"]), s_of(&c["hub"]["uri"])),
                peer: c["peer"].as_str().map(String::from),
                receipts: m.new_receipts(now_i),
                joined_epoch: c["joined_epoch"].as_u64().unwrap_or(0),
                batch: vec![],
            };
            m.convs.insert(gid.clone(), conv);
        }
        Ok(m)
    }

    /// Everything to keep: the MLS storage and this device's delivery state, as one JSON record. The host writes it
    /// after every step that returned something (spec-gap 44: MLS state and delivery state committed together).
    pub fn save(&self) -> String {
        let values = self.mls.provider().storage().values.read().map(|v| v.clone()).unwrap_or_default();
        let mls: serde_json::Map<String, Value> = values.iter().map(|(k, v)| (b64(k), json!(b64(v)))).collect();
        let convs: serde_json::Map<String, Value> = self.convs.iter().map(|(g, c)| (g.clone(), json!({
            "conversation": c.conversation, "kind": c.kind, "hub": {"did": c.hub.0, "uri": c.hub.1}, "peer": c.peer, "joined_epoch": c.joined_epoch,
        }))).collect();
        let archive: serde_json::Map<String, Value> = self.archive_keys.iter().map(|(a, (k, at))| (a.clone(), json!({"key": b64(k), "created_at": at}))).collect();
        json!({"mls": mls, "state": {
            "convs": convs, "personal": self.personal, "resume": self.resume.snapshot(), "own": self.own, "outbox": self.outbox,
            "messages": self.messages, "grants_held": self.grants_held, "archive_keys": archive, "group_info": self.group_info,
            "held_items": self.held_items, "requests": self.requests, "held_archive": self.held_archive, "restored": self.restored,
            "read_disclosed": self.read_disclosed, "calls": self.calls,
            "outages": self.outages.iter().filter(|(_, o)| o.is_down()).map(|(g, o)| (g.clone(), json!(o.down_since()))).collect::<serde_json::Map<_, _>>(),
            "hub_timeout": self.hub_timeout, "successors": self.successors, "handover": self.handover, "mailbox": self.mailbox.0,
            "pending": self.pending.iter().filter_map(|(id, p)| Some((id.clone(), p.to_json()?))).collect::<serde_json::Map<_, _>>(),
            "records_held": self.records_held, "records": self.records, "recording_accepted": self.recording_accepted, "leaving": self.leaving,
            "roster_log": self.roster_log,
        }}).to_string()
    }

    /// Whether this device's delegation carries `dsip.messaging` (M§4.3): without it the mailbox refuses the binding.
    pub fn delegation_ok(&self) -> bool {
        dsip_core::delegation::capabilities(&self.keys.delegation).iter().any(|c| c == "dsip.messaging")
    }

    /// The identity's mailbox `{did, uri}`.
    pub fn mailbox(&self) -> String {
        json!({"did": self.mailbox.0, "uri": self.mailbox.1}).to_string()
    }

    /// Grants held from others, `{identity: compact}` (from the calling engine's contact file, §19.4): what is
    /// presented to the peer's mailbox (M§14.2), beside grants that arrive through this mailbox.
    pub fn set_grants(&mut self, grants_json: &str) {
        if let Ok(g) = serde_json::from_str::<BTreeMap<String, String>>(grants_json) {
            for (k, v) in g {
                self.grants_held.insert(k, v);
            }
        }
    }

    /// M§10.5: disclose read watermarks to the conversation (`true`) or keep them in the personal group (`false`,
    /// the default). Applies to every conversation's receipts machine.
    pub fn set_read_disclosed(&mut self, disclosed: bool, now: f64) {
        if self.read_disclosed == disclosed {
            return;
        }
        self.read_disclosed = disclosed;
        // The policy is the machine's construction (vector context): each conversation gets a fresh machine, and the
        // content it had shown is restored into it as history (spec-gap 64: nothing is sent or archived again).
        // Receipts booked so far are not carried over; they arrive again only if re-sent, so the marks reset.
        let me = self.keys.identity.clone();
        for (gid, c) in self.convs.iter_mut() {
            let mut fresh = Client::new(&json!({"now": now as i64, "me": me, "member_identities": 2, "policy": {"delivered": true, "read": disclosed, "played": disclosed}}));
            let items: Vec<Value> = self.messages.iter().filter(|m| m["group"] == *gid && m["seq"].is_i64())
                .map(|m| json!({"seq": m["seq"], "object": m["object"]})).collect();
            let _ = fresh.step(&json!({"restore": {"items": items}}));
            c.receipts = fresh;
        }
    }

    /// The user has read a conversation through `content_id` (M§10.3): the receipts machine decides whether a
    /// watermark goes out, to the conversation or to the personal group (M§10.5), at most one per 5 s. Frames and
    /// events, as `inbound` returns them.
    pub fn read_through(&mut self, gid: &str, content_id: &str, now: f64) -> String {
        let now_i = now as i64;
        let Some(c) = self.convs.get_mut(gid) else { return "[]".into() };
        c.receipts.step(&json!({"advance": (now_i - c.receipts.now()).max(0)}));
        let emissions = c.receipts.step(&json!({"read": {"through": content_id}}));
        json!(self.receipt_sends(gid, emissions, now_i)).to_string()
    }

    /// Advance every conversation's clock (M§10.3: a read held back by the 5 s interval goes out when it passes).
    pub fn tick(&mut self, now: f64) -> String {
        let now_i = now as i64;
        let mut out = vec![];
        for gid in self.convs.keys().cloned().collect::<Vec<_>>() {
            let emissions = {
                let c = self.convs.get_mut(&gid).expect("group");
                c.receipts.step(&json!({"advance": (now_i - c.receipts.now()).max(0)}))
            };
            out.extend(self.receipt_sends(&gid, emissions, now_i));
        }
        // M§9.4: a deposit with no answer at all counts as the hub unreachable
        let silent: Vec<(String, String, String)> = self.sent_at.iter().filter(|(_, at)| now_i - **at >= NO_ANSWER_S)
            .filter_map(|(id, _)| match self.pending.get(id) { Some(Pending::Application { gid, item }) => Some((id.clone(), gid.clone(), item.clone())), _ => None })
            .collect();
        self.sent_at.retain(|id, at| now_i - *at < NO_ANSWER_S && self.pending.contains_key(id));
        for (id, gid, item) in silent {
            self.pending.remove(&id);
            out.extend(self.hub_unreachable(&gid, &item, true, now_i));
        }
        for gid in self.outages.keys().cloned().collect::<Vec<_>>() {
            let ems = {
                let o = self.outages.get_mut(&gid).expect("outage");
                let dt = (now_i - o.now()).max(0);
                o.advance(dt)
            };
            out.extend(self.outage_emissions(&gid, ems, now_i));
        }
        json!(out).to_string()
    }

    /// This device's hub-outage threshold, seconds (M§9.4: the client's own; 24 h RECOMMENDED).
    pub fn set_hub_timeout(&mut self, seconds: f64) {
        self.hub_timeout = seconds as i64;
    }

    /// Groups whose hub is unreachable: `{group: {down_since, pending, abandoned}}` (M§9.4).
    pub fn outages(&self) -> String {
        let m: serde_json::Map<String, Value> = self.outages.iter().map(|(g, o)| (g.clone(), json!({"down_since": o.down_since(),
            "pending": o.pending().len(), "abandoned": o.is_abandoned(), "successor": self.successors.successor(g)}))).collect();
        Value::Object(m).to_string()
    }

    /// Create the successor of `dead` (M§7.5) once its hub has been unreachable past the threshold: a group for the
    /// same conversation hubbed at this identity's mailbox, `successor_of` naming the dead group, re-adding the dead
    /// group's last roster from `key_packages_json` (`{identity: key-packages answer}`, fetched with `successor_of`,
    /// M§7.5 spec-gap 61). When this device already converged on a successor, that one is used. The pending items
    /// follow once the successor holds its members (M§9.4). Frames.
    pub fn create_successor(&mut self, dead: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        self.track_rosters(now_i);
        let decision = self.successors.step(&json!({"create": {"predecessor": dead}}));
        let d = decision.first().cloned().unwrap_or(Value::Null);
        if let Some(w) = d["use"].as_str() {
            let moved = self.handover.remove(dead).unwrap_or_default();
            self.handover.entry(w.to_string()).or_default().extend(moved);
            let out = self.flush_handover(w, now_i);
            return Ok(json!(out.into_iter().filter_map(|e| e.get("send").cloned()).collect::<Vec<_>>()).to_string());
        }
        let Some(create) = d.get("create") else { return Err(JsValue::from_str(&format!("successor refused: {}", d["refuse"]))) };
        let (conversation, kind) = self.convs.get(dead).map(|c| (c.conversation.clone(), c.kind.clone())).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        let all: Value = serde_json::from_str(key_packages_json).unwrap_or(Value::Null);
        let me = self.keys.identity.clone();
        let mut kps = vec![];
        let mut grants = vec![];
        let peers: Vec<String> = create["roster"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|i| *i != me).map(String::from).collect();
        for peer in &peers {
            if let Some(answer) = all.get(peer) {
                kps.extend(self.pick_key_packages(peer, &answer.to_string(), now_i).unwrap_or_default());
                grants.extend(self.grants_held.get(peer).cloned());
            }
        }
        let (gid, frames) = self.new_group_for(Some(conversation), &kind, Some(dead), now_i)?;
        let peer = self.convs.get(dead).and_then(|c| c.peer.clone());
        if let Some(c) = self.convs.get_mut(&gid) {
            c.peer = peer;
        }
        let ems = self.successors.step(&json!({"created": {"group": gid, "successor_of": dead}}));
        let moved = self.handover.remove(dead).unwrap_or_default();
        self.handover.entry(gid.clone()).or_default().extend(moved);
        if kind == "personal" {
            self.personal = Some(gid.clone());
        }
        let op = (!kps.is_empty()).then(|| Op::Add { peer: peers.first().cloned().unwrap_or_default(), kps, grants, device: None });
        let gi_id = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(gi_id, Pending::GroupInfo { gid: gid.clone(), then: op });
        if kind == "personal" {
            // M§12.1: the personal group's successor gets an archive key of its own, as a new personal group does
            self.pending.insert(format!("personal:{gid}"), Pending::PersonalReady { gid: gid.clone() });
        }
        let mut out: Vec<String> = frames;
        for e in ems {
            if let Some(g) = e["leave"].as_str() {
                out.extend(self.leave_group(g, now_i));
            }
        }
        Ok(json!(out).to_string())
    }

    /// The hand-over to a successor could not be done (the peers' KeyPackages could not be fetched): retried with the
    /// §13.2 backoff (M§9.4, spec-gap 72).
    pub fn successor_failed(&mut self, dead: &str) {
        if let Some(o) = self.outages.get_mut(dead) {
            o.handover_failed();
        }
    }

    /// Add one device of this identity (M§12.3, M§6.7) to `gid` from its mailbox's `key-packages` answer (only the
    /// package of `device` is used): the commit to deposit. After the personal group's add is accepted, every live
    /// archive key is re-sent there ([`Messenger::resend_archive_keys`]). The groups to add it to, in order, are
    /// [`Messenger::groups_for_new_device`].
    pub fn add_device(&mut self, gid: &str, device: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let payload: Value = serde_json::from_str(key_packages_json).map_err(js)?;
        let ctx = self.ctx(now_i);
        let candidates = payload["key_packages"].as_array().cloned().unwrap_or_default().into_iter().chain(payload.get("last_resort").cloned());
        let mut kps = vec![];
        let mut seen = vec![];
        for c in candidates {
            let bytes = unb64(&c);
            if let Ok((_, who)) = authenticate_key_package(&bytes, self.mls.provider(), &ctx) {
                seen.push(format!("{}#{}", who.identity, who.device));
                if who.identity == self.keys.identity && who.device == device {
                    kps.push(bytes);
                }
            }
        }
        if kps.is_empty() {
            return Err(JsValue::from_str(&format!("no KeyPackage of device {device} in the answer (it holds: {})", seen.join(", "))));
        }
        kps.truncate(1);
        let op = Op::Add { peer: self.keys.identity.clone(), kps, grants: vec![], device: Some(device.to_string()) };
        self.propose(gid, &op, now_i)
    }

    /// The groups a new device of this identity joins, in order: the personal group first (M§12.3 step 3), then
    /// every conversation it is not in yet (M§6.7); `[]` when it is everywhere already.
    pub fn groups_for_new_device(&self, device: &str, now: f64) -> String {
        let ctx = Context::new(now as i64, &self.resolver);
        let in_group = |c: &Conv| c.group.members().any(|m| member_identity(&c.group, m.index, &ctx).ok().is_some_and(|w| w.device == device));
        let mut order: Vec<String> = vec![];
        if let Some(p) = &self.personal {
            if self.convs.get(p).is_some_and(|c| !in_group(c)) {
                order.push(p.clone());
            }
        }
        for (g, c) in &self.convs {
            if c.kind != "personal" && !in_group(c) {
                order.push(g.clone());
            }
        }
        json!(order).to_string()
    }

    /// M§12.3 step 3: every live archive key, as `archive-key` objects to the personal group, so a device just added
    /// can read the archive. Frames to send.
    pub fn resend_archive_keys(&mut self, now: f64) -> String {
        let now_i = now as i64;
        let Some(personal) = self.personal.clone() else { return "[]".into() };
        let keys: Vec<(String, Vec<u8>, i64)> = self.archive_keys.iter().map(|(a, (k, t))| (a.clone(), k.clone(), *t)).collect();
        let mut frames = vec![];
        for (akid, key, at) in keys {
            let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": at});
            if let Ok(f) = self.send_object(&personal, &obj, now_i) {
                frames.push(f);
            }
        }
        json!(frames).to_string()
    }

    /// Archive keys this device holds, `[{akid, created_at}]`, newest current (M§12.1).
    pub fn archive_keys(&self) -> String {
        json!(self.archive_keys.iter().map(|(a, (_, at))| json!({"akid": a, "created_at": at})).collect::<Vec<_>>()).to_string()
    }

    /// Groups this identity's mailbox delivered a GroupInfo for that this device is not in (M§6.8): what it can join by
    /// external commit. `[{group, conversation, kind}]`, the personal group first.
    pub fn available(&self) -> String {
        let mut out: Vec<Value> = self.group_info.iter().filter(|(g, _)| !self.convs.contains_key(*g)).filter_map(|(g, gi)| {
            let conv = dsip_mls::group_info_conversation(&unb64(&json!(gi)))?;
            Some(json!({"group": g, "conversation": conv["conversation"], "kind": conv["kind"], "hub": conv["hub"]}))
        }).collect();
        out.sort_by_key(|c| c["kind"] != "personal");
        json!(out).to_string()
    }

    /// Join `gid` by external commit (M§6.8): a device of an identity that has a leaf there, or the identity's own
    /// personal group, with no sibling online to add it. The commit goes to the hub; a `commit-conflict` or
    /// `stale-epoch` refusal discards the joined state, syncs and joins again from the newer GroupInfo (the pinned
    /// `CommitRetry`, spec-gap 58). No archive key comes with it: history waits for a sibling (M§12.3). Frames.
    pub fn external_join(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        if self.convs.contains_key(gid) {
            return Err(JsValue::from_str("this device is in that group already"));
        }
        let frame = self.external_commit(gid, now as i64)?;
        self.retries.insert(gid.to_string(), (CommitRetry::new(&json!({})), Op::Rejoin));
        Ok(json!([frame]).to_string())
    }

    /// A callee leg of this device ended (M§13.3): whether it sends a `call-event` to the personal group, by the
    /// vector-pinned decision (spec-gap 63) — alerted here and not answered here, never `session.answered-elsewhere`;
    /// `declined` when this device ended it with `user.declined`, else `missed`. `leg_json` is `{session, peer, alerted,
    /// answered_here, ended_by: "local"|"remote", reason}`. Frames to send (`[]` when none).
    pub fn call_ended(&mut self, leg_json: &str, now: f64) -> Result<String, JsValue> {
        let leg: Value = serde_json::from_str(leg_json).map_err(js)?;
        let d = dsip_messaging::client::call_event_decision(&json!({"alerted": leg["alerted"], "answered_here": leg["answered_here"],
            "ended_by": leg["ended_by"], "reason": leg["reason"]}));
        if d["send"] != json!(true) {
            return Ok("[]".into());
        }
        let personal = self.personal.clone().ok_or_else(|| JsValue::from_str("no personal group yet"))?;
        let obj = json!({"object": "call-event", "session": leg["session"], "peer": leg["peer"], "direction": "inbound", "outcome": d["outcome"], "at": now as i64});
        self.record_call(&obj);
        Ok(json!([self.send_object(&personal, &obj, now as i64)?]).to_string())
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
        let leg: Value = serde_json::from_str(leg_json).map_err(js)?;
        let outcome = dsip_recording::call_record_outcome(&json!({"direction": leg["direction"], "answered": leg["answered"] == json!(true),
            "ended_by": leg["ended_by"], "reason": leg["reason"]}));
        let mut rec = json!({"object": "call-record", "session": leg["session"], "device": self.keys.device.did(), "direction": leg["direction"],
            "peer": leg["peer"], "invited_at": leg["invited_at"], "outcome": outcome, "ended_by": leg["ended_by"]});
        let mut last = leg["invited_at"].as_i64().unwrap_or(0);
        if outcome == "answered" {
            rec["answered_at"] = leg["answered_at"].clone();
            last = last.max(leg["answered_at"].as_i64().unwrap_or(0));
        }
        // C§9: the times never decrease; an invite or answer stamped by a peer's clock ahead of ours ends no earlier
        rec["ended_at"] = json!((now as i64).max(last));
        for k in ["relay", "reason"] {
            if leg[k].as_str().is_some_and(|v| !v.is_empty()) {
                rec[k] = leg[k].clone();
            }
        }
        for k in ["media", "evidence"] {
            if leg[k].as_array().is_some_and(|a| !a.is_empty()) {
                rec[k] = leg[k].clone();
            }
        }
        let v = check_object(&rec, &json!({"conversation_kind": "direct", "leaf_device": self.keys.device.did()}));
        if v["verdict"] != "accept" {
            return Err(JsValue::from_str(&format!("call record not sent: {}", v["code"].as_str().unwrap_or("invalid"))));
        }
        self.records_held.push(rec.clone());
        let frames: Value = serde_json::from_str(&self.flush_records(keeper, now)?).map_err(js)?;
        Ok(json!({"record": rec, "frames": frames}).to_string())
    }

    /// The held call records, sent to the direct conversation with `keeper` when there is one (C§9: the record-keeper
    /// opens it, spec-gap 123); frames to send, `[]` while there is none.
    pub fn flush_records(&mut self, keeper: &str, now: f64) -> Result<String, JsValue> {
        let Some(gid) = self.convs.iter().find(|(_, c)| c.kind == "direct" && c.peer.as_deref() == Some(keeper)).map(|(g, _)| g.clone()) else {
            return Ok("[]".into());
        };
        let gid = self.live(&gid);
        let mut frames = vec![];
        while let Some(rec) = self.records_held.first().cloned() {
            let f = self.send_object(&gid, &rec, now as i64)?;
            self.records_held.remove(0);
            if !f.is_empty() {
                frames.push(f);
            }
        }
        Ok(json!(frames).to_string())
    }

    /// Leave the conversation `gid` for this identity (M§7.3 "Leaving", spec-gap 125): a Remove proposal for each of
    /// its leaves goes to the hub, another member commits them, and until then nothing is sent there and it is not
    /// listed. The personal group is never left. Returns the frames to send.
    pub fn leave(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        let gid = self.live(gid);
        if !self.convs.contains_key(&gid) {
            return Err(JsValue::from_str("not a member of that group"));
        }
        if self.personal.as_deref() == Some(gid.as_str()) {
            return Err(JsValue::from_str("the personal group is not left (M§7.1)"));
        }
        self.leaving.insert(gid.clone());
        Ok(json!(self.propose_leave(&gid, now as i64)).to_string())
    }

    /// The Remove proposals for every leaf of this identity in `gid`, deposited: this device's own by `leave_group`
    /// (MLS lets a member propose, never commit, its own removal), a sibling's by `propose_remove_member`.
    fn propose_leave(&mut self, gid: &str, now: i64) -> Vec<Value> {
        let ctx = Context::new(now, &self.resolver);
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let me = self.keys.identity.clone();
        let mut bytes = vec![];
        let mut errors = vec![];
        if let Some(c) = self.convs.get_mut(gid) {
            let own = c.group.own_leaf_index();
            let mine: Vec<LeafNodeIndex> = c.group.members().filter(|m| member_identity(&c.group, m.index, &ctx).ok().is_some_and(|w| w.identity == me))
                .map(|m| m.index).collect();
            for idx in mine {
                let msg = if idx == own {
                    c.group.leave_group(provider, &signer).map_err(|e| format!("{e:?}"))
                } else {
                    c.group.propose_remove_member(provider, &signer, idx).map(|(m, _)| m).map_err(|e| format!("{e:?}"))
                };
                match msg.and_then(|m| m.tls_serialize_detached().map_err(|e| format!("{e:?}"))) {
                    Ok(b) => bytes.push(b),
                    Err(e) => errors.push(e),
                }
            }
        }
        let mut out: Vec<Value> = errors.into_iter().map(|e| json!({"error": format!("leave proposal in {gid}: {e}")})).collect();
        for b in bytes {
            let frame = self.hub_deposit(gid, "handshake", json!({"mls": b64(&b)}), now);
            let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
            self.pending.insert(id, Pending::Proposal { gid: gid.to_string() });
            out.push(json!({"send": frame}));
        }
        out
    }

    /// The user accepted the recording of `gid` (C§5): every recorder now in it is accepted for this conversation, and
    /// a `recording-acceptance` goes to the personal group so this identity's other devices accept them too. Returns
    /// `{accepted: [device], frames}`; content may then be sent there. A recorder that joins later asks again.
    ///
    /// Spec: C§5 "Acceptance is the person's, not one device's".
    pub fn accept_recording(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        let rec = self.recording_of(&self.leaves_of(gid, now_i), &conversation);
        let devices: Vec<String> = rec["pending"].as_array().into_iter().flatten().filter_map(|r| r["device"].as_str().map(String::from)).collect();
        if devices.is_empty() {
            return Err(JsValue::from_str("no recorder to accept in this conversation"));
        }
        self.recording_accepted.entry(conversation.clone()).or_default().extend(devices.iter().cloned());
        let mut frames = vec![];
        if let Some(personal) = self.personal.clone() {
            let obj = json!({"object": "recording-acceptance", "conversation": conversation, "recorders": devices, "accepted_at": now_i});
            let f = self.send_object(&personal, &obj, now_i)?;
            if !f.is_empty() {
                frames.push(f);
            }
        }
        Ok(json!({"accepted": devices, "frames": frames}).to_string())
    }

    /// How many of this device's call records wait for the conversation with the record-keeper (C§9).
    pub fn held_records(&self) -> usize {
        self.records_held.len()
    }

    /// As a record-keeper: the records received (C§9), `[{group, from, device, received_at, record}]`.
    pub fn records(&self) -> String {
        json!(self.records).to_string()
    }

    /// Whether this device is a recorder (its delegation carries `dsip.record`, C§5).
    pub fn is_recorder(&self) -> bool {
        self.recorder
    }

    /// The call log, one entry per session (M§13.3).
    pub fn calls(&self) -> String {
        json!(self.calls).to_string()
    }

    /// One conversation's timeline (M§13.3, the pinned `peer_timeline`): its messages with this identity's call events
    /// for the peer interleaved — `{"call": {…}}` or the message as [`Messenger::thread`] gives it.
    pub fn timeline(&self, gid: &str) -> String {
        let thread: Vec<Value> = serde_json::from_str(&self.thread(gid)).unwrap_or_default();
        let peer = self.convs.get(gid).and_then(|c| c.peer.clone());
        let calls: Vec<Value> = self.calls.iter().filter(|c| peer.as_deref().is_some_and(|p| c["peer"] == p)).cloned().collect();
        if calls.is_empty() {
            return json!(thread).to_string();
        }
        let content: Vec<Value> = thread.iter().enumerate().map(|(i, m)| json!({"id": i.to_string(), "at": m["object"]["sent_at"]})).collect();
        let order = dsip_messaging::client::peer_timeline(&json!({"content": content, "calls": calls}));
        let out: Vec<Value> = order["timeline"].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(|e| {
            if let Some(i) = e.strip_prefix("content:") {
                i.parse::<usize>().ok().and_then(|i| thread.get(i).cloned())
            } else {
                let sess = e.strip_prefix("call:").unwrap_or("");
                calls.iter().find(|c| c["session"] == sess).map(|c| json!({"call": c}))
            }
        }).collect();
        json!(out).to_string()
    }

    /// Whether this device can send to `peer` (M§13.2 condition 2): a direct conversation exists, or a grant from them
    /// is held that would let one be created (M§14.2).
    pub fn can_send(&self, peer: &str) -> bool {
        self.convs.values().any(|c| c.kind == "direct" && c.peer.as_deref() == Some(peer)) || self.grants_held.contains_key(peer)
    }

    /// Seal a payload for upload (M§8.4 rule 1): a fresh single-use 32-byte key, AES-256-GCM, no AAD, stored as
    /// `nonce ‖ ciphertext ‖ tag`. Returns `{"sealed": b64url, "key": b64url, "sha256": hex, "size": n}`.
    pub fn seal_blob(&self, plain_b64: &str) -> String {
        let plain = dsip_core::b64::decode(plain_b64).unwrap_or_default();
        let key = KeyPair::generate().seed();
        let nonce: [u8; 12] = KeyPair::generate().seed()[..12].try_into().expect("12 bytes");
        let sealed = seal(&key, &nonce, &plain, SealUse::Blob);
        json!({"sealed": b64(&sealed), "key": b64(&key), "sha256": digest(&sealed), "size": sealed.len()}).to_string()
    }

    /// The `blob-put` that authorizes one upload of `sha256`/`size` to this identity's mailbox (M§5.6), as the compact
    /// envelope for `Authorization: DSIP …`, carrying the device's delegation (M§5.1).
    pub fn blob_put(&self, sha256: &str, size: f64, now: f64) -> String {
        let env = wire::message_delegated(&self.keys.device, vec![self.keys.delegation.clone()], "blob-put", &self.mailbox.0, now as i64,
            wire::TTL_S, json!({"sha256": sha256, "size": size as u64}));
        compact(&env)
    }

    /// An `audio` content object (M§8.2) for a blob already uploaded: `blob_json` is `{uri, sha256, size, key, content_type}`
    /// from [`Messenger::seal_blob`] and the upload; `purpose` `voice-message` or `voicemail` (with `session`). The deposit
    /// carries the manifest without the key (M§8.4 rule 4). The frame to send.
    pub fn send_audio(&mut self, gid: &str, blob_json: &str, duration_ms: f64, purpose: &str, session: Option<String>, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let b: Value = serde_json::from_str(blob_json).map_err(js)?;
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        self.may_send_content(gid, now_i)?;
        let mut obj = json!({"object": "content", "id": self.fresh_id(now_i), "conversation": conversation, "sender": self.keys.identity,
            "sent_at": now_i, "kind": "audio", "purpose": purpose, "duration_ms": duration_ms as i64,
            "blob": {"uri": b["uri"], "sha256": b["sha256"], "size": b["size"], "key": b["key"], "alg": "A256GCM",
                     "content_type": b["content_type"]}});
        if let Some(sid) = session {
            obj["session"] = json!(sid);
        }
        self.send_object(gid, &obj, now_i)
    }

    /// Where to fetch a content's blob from, in order (M§8.4 rules 6–7, the pinned `blob_sources`): the manifest's copy
    /// at another `uri` for the same `sha256` and `size`, then the content's own. `object_json` is the content object,
    /// `manifest_json` the item's `blobs` (or null).
    pub fn blob_sources(&self, object_json: &str, manifest_json: &str) -> String {
        let object: Value = serde_json::from_str(object_json).unwrap_or(Value::Null);
        let manifest: Value = serde_json::from_str(manifest_json).unwrap_or(Value::Null);
        dsip_messaging::client::blob_sources(&json!({"blob": object["blob"], "manifest": manifest}))["sources"].to_string()
    }

    /// Open a fetched blob for a content object (M§8.4 rule 7): the size and SHA-256 must match the content's `blob`
    /// before it is decrypted under the key the content carries. The plaintext, base64url, or the refusal code.
    pub fn open_blob(&self, object_json: &str, stored_b64: &str) -> Result<String, JsValue> {
        let object: Value = serde_json::from_str(object_json).map_err(js)?;
        let b = &object["blob"];
        let key: [u8; 32] = unb64(&b["key"]).try_into().map_err(|_| JsValue::from_str("blob key"))?;
        let stored = dsip_core::b64::decode(stored_b64).unwrap_or_default();
        let plain = open_blob(&key, &stored, b["size"].as_u64().unwrap_or(0) as usize, b["sha256"].as_str().unwrap_or("")).map_err(JsValue::from_str)?;
        Ok(b64(&plain))
    }

    /// What a device does after its blob sources answered (`tried`: `[{uri, status, sha256?, size?}]`; the pinned
    /// `blob_fetch`, spec-gap 106): `{"action": "retry"|"give-up", "reason"}`.
    pub fn blob_fetch_decision(&self, object_json: &str, tried_json: &str, attempt: f64) -> String {
        let object: Value = serde_json::from_str(object_json).unwrap_or(Value::Null);
        let tried: Value = serde_json::from_str(tried_json).unwrap_or(Value::Null);
        dsip_messaging::client::blob_fetch(&json!({"blob": {"sha256": object["blob"]["sha256"], "size": object["blob"]["size"]}, "tried": tried,
            "attempt": attempt as i64})).to_string()
    }

    /// The user played an `audio` or `video` content (M§10.4): a `played` receipt under the same opt-in as `read`
    /// (M§10.5). Frames and events, as `inbound` returns them.
    pub fn played(&mut self, gid: &str, content_id: &str, now: f64) -> String {
        let now_i = now as i64;
        let Some(c) = self.convs.get_mut(gid) else { return "[]".into() };
        c.receipts.step(&json!({"advance": (now_i - c.receipts.now()).max(0)}));
        let emissions = c.receipts.step(&json!({"play": {"id": content_id}}));
        json!(self.receipt_sends(gid, emissions, now_i)).to_string()
    }

    /// A DID document to hold (§8.1), for `did:web` peers.
    pub fn add_document(&mut self, doc_json: &str) -> bool {
        match serde_json::from_str::<dsip_core::did::DidDocument>(doc_json) {
            Ok(d) => {
                self.resolver.insert(d);
                true
            }
            Err(_) => false,
        }
    }

    /// The client `hello` to send first on a connection to a mailbox (§13.2, M§4.3); one per connection.
    pub fn hello_frame(&mut self, now: f64) -> String {
        let id = self.fresh_id(now as i64);
        self.hello_ids.insert(id.clone());
        client_hello(&self.keys, &self.supported, &id, now as i64).frame()
    }

    /// Verify a service's `hello` (must echo one of ours, §20.5). Returns `{"ok":true,"did":…,"capabilities":…}` or
    /// `{"ok":false,"code":…}`. Named as the relay host expects, so one connection class serves both.
    pub fn relay_hello(&mut self, frame: &str, now: f64) -> String {
        let answered = Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["in_reply_to"])).unwrap_or_default();
        if !self.hello_ids.remove(&answered) {
            return json!({"ok": false, "code": "hello-not-ours"}).to_string();
        }
        match verify_relay_hello(frame, &answered, now as i64, &self.resolver, &mut self.seen, &self.supported) {
            Ok(h) => json!({"ok": true, "did": h.did, "capabilities": h.capabilities}).to_string(),
            Err(v) => json!({"ok": false, "code": v.code.and_then(|c| serde_json::to_value(c).ok()).and_then(|c| c.as_str().map(String::from)).unwrap_or_default()}).to_string(),
        }
    }

    /// A `sync` for this identity's mailbox (M§5.4): `since`/`ack_through` from the durable state, `live` once asked.
    pub fn sync_frame(&mut self, live: bool, now: f64) -> String {
        self.want_live |= live;
        let mut fields = self.resume.sync_fields();
        fields["live"] = json!(self.want_live);
        wire::message(&self.keys.device, "sync", &self.mailbox.0, now as i64, wire::TTL_S, fields).frame()
    }

    /// A `key-packages` upload of `n` fresh KeyPackages and a last-resort one (M§5.5, M§6.7).
    pub fn key_packages_frame(&mut self, n: usize, now: f64) -> Result<String, JsValue> {
        let mut packages = vec![];
        for _ in 0..n {
            packages.push(json!(b64(&self.mls.key_package().map_err(|e| js(e.0))?)));
        }
        let last = b64(&self.mls.key_package().map_err(|e| js(e.0))?);
        let env = wire::message(&self.keys.device, "key-packages", &self.mailbox.0, now as i64, wire::TTL_S,
            json!({"subject": self.keys.identity, "key_packages": packages, "last_resort": last}));
        self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::KeyPackages { count: n + 1 });
        Ok(env.frame())
    }

    /// What to send on a fresh binding: pending application items again (M§9.3, the same bytes), then a sync.
    pub fn on_bound(&mut self, now: f64) -> String {
        let mut frames = vec![];
        let moved = self.moved_from.is_some();
        if let Some(old) = self.moved_from.take() {
            // spec-gap 122: a mailbox this identity moved to learns its groups, so hubs' fan-out is admitted (M§6.6)
            let groups: Vec<Value> = self.convs.iter().map(|(g, c)| json!({"group": g, "state": "joined", "hub": c.hub.0, "hub_uri": c.hub.1})).collect();
            if !groups.is_empty() {
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": groups}), now as i64);
                frames.push(env.frame());
            }
            let _ = old;
        }
        frames.extend(self.redeposit_pending(moved, now as i64));
        for (gid, items) in self.outbox.clone() {
            if self.outages.get(&gid).is_some_and(|o| o.is_down() || o.is_abandoned()) {
                continue; // M§9.4: the outage's own backoff re-deposits the head (tick)
            }
            for it in items {
                frames.push(self.deposit_item(&gid, &it, now as i64));
            }
        }
        frames.push(self.sync_frame(true, now));
        json!(frames).to_string()
    }

    /// Deposits whose answer a binding that ended took with it, sent again under fresh envelopes: a GroupInfo as a new
    /// export, a commit as the same MLS bytes (the hub answers a duplicate digest with its seq, M§6.5), a
    /// `mailbox-config` or archive record with the same fields. Application items go again from the outbox.
    ///
    /// Spec: M§9.3; M§4.1 step 3 (v0.13, spec-gap 122): after a move the new mailbox's registration of every group
    /// supersedes a pending `mailbox-config` at the old one. Impl: an archive record goes to the new mailbox, the
    /// identity's mailbox now; key packages are uploaded afresh by the host at every binding.
    fn redeposit_pending(&mut self, moved: bool, now: i64) -> Vec<String> {
        let mut frames = vec![];
        for (id, p) in self.pending.clone() {
            let frame = match &p {
                Pending::GroupInfo { gid, .. } if self.convs.contains_key(gid) && !self.outages.get(gid).is_some_and(|o| o.is_down() || o.is_abandoned()) => {
                    self.group_info_frame(gid, now).ok()
                }
                Pending::Commit { gid, fields, .. } if self.convs.contains_key(gid) => Some(self.hub_deposit(gid, "handshake", fields.clone(), now)),
                Pending::Config { fields } if !moved => Some(wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S, fields.clone()).frame()),
                Pending::Archive { fields } => {
                    let gid = s_of(&fields["ref_group"]);
                    Some(wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &self.mailbox.0, now, &gid, "archive", fields.clone()).frame())
                }
                Pending::GroupInfo { .. } | Pending::Commit { .. } | Pending::Config { .. } | Pending::KeyPackages { .. } | Pending::Proposal { .. } => None,
                Pending::Application { .. } | Pending::PersonalReady { .. } => continue,
            };
            self.pending.remove(&id);
            if let Some(f) = frame {
                let nid = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                self.pending.insert(nid, p);
                frames.push(f);
            }
        }
        frames
    }

    /// A `mailbox-config` to this device's mailbox (M§6.6), pending until answered.
    fn config_env(&mut self, fields: Value, now: i64) -> Envelope {
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S, fields.clone());
        self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Config { fields });
        env
    }

    /// Create this identity's personal group at its mailbox (M§7.1): the `mailbox-config` that registers it and the
    /// GroupInfo deposit; the first archive key follows once the hub holds the group (M§12.1). Frames to send.
    pub fn create_personal(&mut self, now: f64) -> Result<String, JsValue> {
        if self.personal.is_some() {
            return Err(JsValue::from_str("this identity already has a personal group here"));
        }
        let (gid, frames) = self.new_group("personal", now as i64)?;
        self.personal = Some(gid.clone());
        // the GroupInfo deposit is the last frame: its accepted leads to the archive key
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid: gid.clone(), then: None });
            self.pending.insert(format!("personal:{gid}"), Pending::PersonalReady { gid });
        }
        Ok(json!(frames).to_string())
    }

    /// A `key-package-fetch` for `target` to send on a connection to `to_mailbox` (M§5.5), presenting the grant
    /// held from `target` if any (M§14.2).
    /// `successor_of` names the dead group a successor is created for: the target's mailbox serves it without a
    /// grant when that group is registered for the target (M§7.5, spec-gap 61).
    pub fn fetch_frame(&mut self, to_mailbox: &str, target: &str, now: f64, successor_of: Option<String>) -> String {
        let mut fields = json!({"target": target});
        if let Some(g) = successor_of {
            fields["successor_of"] = json!(g);
        }
        if let Some(g) = self.grants_held.get(target) {
            fields["grant"] = json!(g);
        }
        wire::message(&self.keys.device, "key-package-fetch", to_mailbox, now as i64, wire::TTL_S, fields).frame()
    }

    /// Create a direct conversation with `target` from its mailbox's `key-packages` answer (M§7.2): every device of
    /// the target the vector-pinned rule picks (C§5), plus this identity's own other devices from `own_json` (the
    /// same answer shape, or null), in one commit once the group is hubbed. Returns the frames to send, or the refusal.
    pub fn create_direct(&mut self, target: &str, key_packages_json: &str, own_json: Option<String>, now: f64) -> Result<String, JsValue> {
        if let Some(gid) = self.convs.iter().find(|(_, c)| c.kind == "direct" && c.peer.as_deref() == Some(target)).map(|(g, _)| g.clone()) {
            return Err(JsValue::from_str(&format!("a conversation with {target} exists: {gid}")));
        }
        let now_i = now as i64;
        let mut kps = self.pick_key_packages(target, key_packages_json, now_i)?;
        if let Some(own) = own_json {
            let me = self.keys.identity.clone();
            kps.extend(self.pick_key_packages(&me, &own, now_i).unwrap_or_default());
        }
        let (gid, frames) = self.new_group("direct", now_i)?;
        if let Some(c) = self.convs.get_mut(&gid) {
            c.peer = Some(target.to_string());
        }
        let grants: Vec<String> = self.grants_held.get(target).cloned().into_iter().collect();
        let op = Op::Add { peer: target.to_string(), kps, grants, device: None };
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid, then: Some(op) });
        }
        Ok(json!(frames).to_string())
    }

    /// Create a group conversation (M§7.3, `kind: group`) with the identities of `targets_json`, `{identity: its
    /// mailbox's key-packages answer}`, plus this identity's own other devices from `own_json` (or null): every device
    /// the vector-pinned rule picks, added in one commit once the group is hubbed at this identity's mailbox, with the
    /// grants held from them (M§14.2). Returns the frames to send.
    pub fn create_group(&mut self, targets_json: &str, own_json: Option<String>, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let targets: serde_json::Map<String, Value> = serde_json::from_str(targets_json).map_err(js)?;
        if targets.is_empty() {
            return Err(JsValue::from_str("a group needs at least one other identity"));
        }
        let (mut kps, mut grants) = (vec![], vec![]);
        for (target, answer) in &targets {
            kps.extend(self.pick_key_packages(target, &answer.to_string(), now_i)?);
            grants.extend(self.grants_held.get(target).cloned());
        }
        if let Some(own) = own_json {
            let me = self.keys.identity.clone();
            kps.extend(self.pick_key_packages(&me, &own, now_i).unwrap_or_default());
        }
        let (gid, frames) = self.new_group("group", now_i)?;
        let peer = targets.keys().next().cloned().unwrap_or_default();
        let op = Op::Add { peer, kps, grants, device: None };
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid, then: Some(op) });
        }
        Ok(json!(frames).to_string())
    }

    /// Add `target`'s devices to the group conversation `gid` from its mailbox's `key-packages` answer (M§7.3: any
    /// member identity MAY add another, holding its grant, M§14.2): the commit to deposit.
    pub fn add_member(&mut self, gid: &str, target: &str, key_packages_json: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        if self.member_identities(gid, now_i).iter().any(|i| i == target) {
            return Err(JsValue::from_str(&format!("{target} is a member already")));
        }
        let kps = self.pick_key_packages(target, key_packages_json, now_i)?;
        let grants: Vec<String> = self.grants_held.get(target).cloned().into_iter().collect();
        self.propose(gid, &Op::Add { peer: target.to_string(), kps, grants, device: None }, now_i)
    }

    /// Remove the member identity `target` from the conversation `gid`, every leaf of it (M§7.3: any member identity
    /// MAY remove another; this identity leaves with [`Messenger::leave`] instead): the commit to deposit.
    pub fn remove_member(&mut self, gid: &str, target: &str, now: f64) -> Result<String, JsValue> {
        if target == self.keys.identity {
            return Err(JsValue::from_str("this identity leaves instead (M§7.3: no commit removes its committer)"));
        }
        if self.personal.as_deref() == Some(gid) {
            return Err(JsValue::from_str("the personal group holds this identity's devices only (M§7.1)"));
        }
        self.propose(gid, &Op::Remove { identity: target.to_string() }, now as i64)
    }

    /// Move the conversation `gid` to this identity's own mailbox as its hub (M§7.4: while the hub is alive, any member
    /// MAY move the group): the commit to deposit at the current hub. On `accepted` this device's mailbox follows and
    /// the new hub is bootstrapped with the GroupInfo and `handover_seq`.
    pub fn move_hub(&mut self, gid: &str, now: f64) -> Result<String, JsValue> {
        let gid = self.live(gid);
        let c = self.convs.get(&gid).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        if c.hub.0 == self.mailbox.0 {
            return Err(JsValue::from_str("the conversation is already hubbed at this identity's mailbox"));
        }
        let hub = json!({"did": self.mailbox.0, "uri": self.mailbox.1});
        self.propose(&gid, &Op::MoveHub { hub }, now as i64)
    }

    /// The roster changes of a conversation and its predecessors, oldest first: `[{group, seq, epoch, by, added,
    /// removed, left}]` (M§7.3: rendered, attributed to the committing identity).
    pub fn roster_log(&self, gid: &str) -> String {
        let groups = self.lineage(gid);
        let list: Vec<Value> = self.roster_log.iter().filter(|(g, _)| groups.contains(*g))
            .flat_map(|(g, es)| es.iter().map(move |e| { let mut e = e.clone(); e["group"] = json!(g); e })).collect();
        json!(list).to_string()
    }

    /// A text message to a conversation (M§8.1 `content`, kind `text`): the deposit to send, pending until the hub's
    /// `accepted` (M§9.2).
    pub fn send_text(&mut self, gid: &str, text: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        self.may_send_content(gid, now_i)?;
        let obj = json!({"object": "content", "id": self.fresh_id(now_i), "conversation": conversation, "sender": self.keys.identity,
            "sent_at": now_i, "kind": "text", "purpose": "message", "content_type": "text/plain", "text": text});
        self.send_object(gid, &obj, now_i)
    }

    /// Conversations: `[{group, conversation, kind, peer, members, epoch, hub, pending, recorded, recorders, may_send,
    /// recorders_pending}]`; members are the leaves that authenticate at `now` (M§6.2); `pending` counts items not yet
    /// accepted by the hub; `recorders_pending` lists the recorders the user has still to accept (C§5).
    pub fn conversations(&self, now: f64) -> String {
        let ctx = Context::new(now as i64, &self.resolver);
        let list: Vec<Value> = self.convs.iter().filter(|(g, _)| !self.leaving.contains(*g))
            .filter(|(g, _)| !self.successors.successor(g).is_some_and(|w| self.convs.contains_key(w) && w != g.as_str())).map(|(g, c)| {
            let leaves: Vec<_> = c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).collect();
            let recording = self.recording_of(&leaves, &c.conversation);
            let mut members: Vec<String> = leaves.into_iter().map(|w| w.identity).collect();
            members.sort();
            members.dedup();
            json!({"group": g, "conversation": c.conversation, "kind": c.kind, "peer": c.peer, "members": members, "epoch": c.group.epoch().as_u64(),
                   "recorded": recording["recorded"], "recorders": recording["recorders"], "may_send": recording["may_send"],
                   "recorders_pending": recording["pending"],
                   "hub": {"did": c.hub.0, "uri": c.hub.1}, "pending": self.outbox.get(g).map_or(0, Vec::len) + self.handover.get(g).map_or(0, Vec::len),
                   "hub_down": self.outages.get(g).is_some_and(HubOutage::is_down),
                   "predecessors": self.lineage(g).into_iter().filter(|x| x != g).collect::<Vec<_>>()})
        }).collect();
        json!(list).to_string()
    }

    /// The thread of one group in `seq` order (M§8.5): `[{key, sender, sender_device, object, seq, mine, delivered,
    /// from_archive}]`; `read_through` of the whole thread is `{identity: content id}` (M§10.3), in
    /// [`Messenger::read_marks`].
    pub fn thread(&self, gid: &str) -> String {
        let snap = self.convs.get(gid).map(|c| c.receipts.snapshot()).unwrap_or(Value::Null);
        let groups = self.lineage(gid);
        let mut list: Vec<Value> = self.messages.iter().filter(|m| m["group"].as_str().is_some_and(|g| groups.contains(g))).map(|m| {
            let mut m = m.clone();
            m["delivered"] = snap["delivered"][s_of(&m["object"]["id"])].clone();
            m["played"] = snap["played"][s_of(&m["object"]["id"])].clone();
            m
        }).collect();
        // predecessors first, each in seq order (a successor's numbering starts afresh)
        let order: Vec<String> = { let mut v: Vec<String> = groups.iter().cloned().collect(); v.sort_by_key(|g| (g == gid, self.lineage(g).len())); v };
        list.sort_by_key(|m| (order.iter().position(|g| m["group"] == g.as_str()).unwrap_or(0), m["seq"].as_i64().unwrap_or(i64::MAX), s_of(&m["key"])));
        json!(list).to_string()
    }

    /// Each identity's read watermark in a conversation, `{identity: content id}` (M§10.3; a sibling's undisclosed
    /// one reaches us through the personal group, M§10.5).
    pub fn read_marks(&self, gid: &str) -> String {
        self.convs.get(gid).map(|c| c.receipts.snapshot()["read_through"].to_string()).unwrap_or_else(|| "{}".into())
    }

    /// Introductions delivered through the mailbox and not yet answered (M§14.1), `{id: payload}`.
    pub fn requests(&self) -> String {
        json!(self.requests).to_string()
    }

    /// The personal group's id, once created.
    pub fn personal(&self) -> Option<String> {
        self.personal.clone()
    }

    /// Process one frame from the mailbox. Returns the emissions: `{send: frame}` (to the mailbox), `{ui: …}`
    /// events, `{sync: true}` when a refused commit asks for one (spec-gap 58), `{refused: …}`, `{error: …}`.
    pub fn inbound(&mut self, frame: &str, now: f64) -> String {
        let now_i = now as i64;
        let mut out = vec![];
        self.seen.sweep(now_i);
        let inb = {
            let mut ctx = Context::new(now_i, &self.resolver);
            ctx.seen_ids = self.seen.set();
            ctx.supported = self.supported.clone();
            match verify_frame(frame, &ctx) {
                Ok(i) => i,
                Err(r) => return json!([{"rejected": {"code": r.code, "reason": r.reason}}]).to_string(),
            }
        };
        let p = inb.payload().clone();
        self.seen.insert(&s_of(&p["id"]), now_i, now_i);
        let answers_ours = p["in_reply_to"].as_str().is_some_and(|id| self.pending.contains_key(id));
        if inb.device() != self.mailbox.0 && !(matches!(inb.msg_type(), "key-packages" | "error") || (inb.msg_type() == "accepted" && answers_ours)) {
            // Everything on this binding is the mailbox's (M§4.1), except what it relays unchanged: a hub's `accepted`
            // or `error` to a deposit it forwarded (M§5.2), and a peer mailbox's answer to a key-package-fetch (M§5.5).
            out.push(json!({"drop": format!("frame from {}, not the mailbox", inb.device())}));
            return json!(out).to_string();
        }
        match inb.msg_type() {
            "items" => {
                for item in p["items"].as_array().into_iter().flatten() {
                    match self.item(item, now_i) {
                        Ok(more) => out.extend(more),
                        Err(e) => out.push(json!({"error": format!("item {}: {}", item["cursor"], e.0)})),
                    }
                }
                out.extend(self.receipts_batch(now_i));
                out.extend(self.apply_restored(now_i));
                if p["next"].is_string() {
                    out.push(json!({"send": self.sync_frame(false, now)}));
                } else if p["in_reply_to"].is_string() {
                    // caught up: membership changes refused for a conflict are re-proposed while still needed, and what a
                    // moved group's old hub refused goes to the new one (M§7.4). Only the answer to a sync says so: a live
                    // push (no in_reply_to, M§5.4) can arrive first, from before the winning commit or the move
                    out.extend(self.after_sync(now_i));
                }
            }
            "accepted" => out.extend(self.accepted(&p, now_i)),
            "error" if p["reason"] == "mailbox.cursor-invalid" => {
                // M§5.4: re-sync from null; seq positions make the redelivery collapse (M§8.5)
                self.resume.cursor_invalid();
                out.push(json!({"ui": "resync"}));
                out.push(json!({"send": self.sync_frame(false, now)}));
            }
            "error" => out.extend(self.refused(&p, now_i)),
            "key-packages" => out.push(json!({"key_packages": p})),
            other => out.push(json!({"drop": format!("no handler for {other}")})),
        }
        json!(out).to_string()
    }

    /// A fresh ULID (§12.9: timestamp-consistent with `now`).
    pub fn new_id(&mut self, now: f64) -> String {
        self.fresh_id(now as i64)
    }
}

impl Messenger {
    fn fresh_id(&mut self, now: i64) -> String {
        self.counter += 1;
        dsip_core::ulid::Ulid::generate_at((now.max(0) as u64) * 1000 + self.counter % 1000).as_str().to_string()
    }

    fn ctx(&self, now: i64) -> Context<'_> {
        Context::new(now, &self.resolver)
    }

    fn new_receipts(&self, now: i64) -> Client {
        Client::new(&json!({"now": now, "me": self.keys.identity, "member_identities": 2,
            "policy": {"delivered": true, "read": self.read_disclosed, "played": self.read_disclosed}}))
    }


    /// Authenticate a `key-packages` answer and pick the devices to add for `target` (M§5.5, M§6.2, C§5).
    fn pick_key_packages(&self, target: &str, payload_json: &str, now: i64) -> Result<Vec<Vec<u8>>, JsValue> {
        let payload: Value = serde_json::from_str(payload_json).map_err(js)?;
        if payload["type"] != "key-packages" {
            return Err(JsValue::from_str(&format!("key-package-fetch refused: {} {}", payload["reason"], payload["detail"])));
        }
        let ctx = self.ctx(now);
        let mut found: Vec<(Vec<u8>, dsip_messaging::mls_wire::LeafIdentity)> = vec![];
        let candidates = payload["key_packages"].as_array().cloned().unwrap_or_default().into_iter().chain(payload.get("last_resort").cloned());
        for c in candidates {
            let bytes = unb64(&c);
            if let Ok((_, who)) = authenticate_key_package(&bytes, self.mls.provider(), &ctx) {
                found.push((bytes, who));
            }
        }
        let listed: Vec<Value> = found.iter().map(|(_, w)| json!({"device": w.device, "identity": w.identity, "capabilities": w.capabilities})).collect();
        let pick = dsip_recording::add_devices(&json!({"target": target, "self_identity": self.keys.identity, "self_device": self.keys.device.did(),
            "purpose": "conversation", "key_packages": listed}));
        if let Some(why) = pick["refused"].as_str() {
            return Err(JsValue::from_str(&format!("no device of {target} to add: {why} (C§5)")));
        }
        let mut out = vec![];
        for d in pick["add"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if let Some(i) = found.iter().position(|(_, w)| w.device == d) {
                out.push(found.swap_remove(i).0);
            }
        }
        Ok(out)
    }

    /// A group of `kind` hubbed at this identity's mailbox (M§6.5 rule 6, M§6.6): registered with `mailbox-config`,
    /// its GroupInfo deposited. Returns the group id and the frames, GroupInfo last.
    fn new_group(&mut self, kind: &str, now: i64) -> Result<(String, Vec<String>), JsValue> {
        self.new_group_for(None, kind, None, now)
    }

    /// As [`Self::new_group`], for an existing `conversation` and with `successor_of` (M§7.5).
    fn new_group_for(&mut self, conversation: Option<String>, kind: &str, successor_of: Option<&str>, now: i64) -> Result<(String, Vec<String>), JsValue> {
        let conversation = conversation.unwrap_or_else(|| self.fresh_id(now));
        let group_id = self.fresh_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": kind, "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": successor_of});
        let group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv).map_err(js)?).map_err(|e| js(e.0))?;
        let gid = b64(group.group_id().as_slice());
        let epoch = group.epoch().as_u64();
        self.convs.insert(gid.clone(), Conv {
            group, conversation, kind: kind.to_string(), hub: (self.mailbox.0.clone(), self.mailbox.1.clone()), peer: None,
            receipts: self.new_receipts(now), joined_epoch: epoch, batch: vec![],
        });
        let config = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "joined", "hub": self.mailbox.0}]}), now);
        let gi = self.group_info_frame(&gid, now)?;
        Ok((gid, vec![config.frame(), gi]))
    }

    /// The GroupInfo deposit for the hub (M§6.5 rule 6).
    fn group_info_frame(&mut self, gid: &str, now: i64) -> Result<String, JsValue> {
        self.group_info_frame_at(gid, None, now)
    }

    /// As [`Self::group_info_frame`]; `handover_seq` bootstraps a group's new hub, which continues the numbering after
    /// the seq the old hub gave the moving commit (M§7.4).
    fn group_info_frame_at(&mut self, gid: &str, handover_seq: Option<i64>, now: i64) -> Result<String, JsValue> {
        let c = self.convs.get(gid).ok_or_else(|| JsValue::from_str("group"))?;
        let gi = c.group.export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true).map_err(|e| js(format!("{e:?}")))?;
        let bytes = gi.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?;
        let mut fields = json!({"mls": b64(&bytes)});
        if let Some(h) = handover_seq {
            fields["handover_seq"] = json!(h);
        }
        Ok(self.hub_deposit(gid, "group-info", fields, now))
    }

    /// The group moved to `hub` (`{did, uri}`) by the commit at `seq`: deposits go there from now on, and this
    /// identity's mailbox is told, so it admits the new hub's fan-out and forwards to it (M§7.4 "Member mailboxes follow
    /// their owner's devices"). The same `did` at a new `uri` is not a move: no `handover_seq`, nothing logged.
    fn hub_moved(&mut self, gid: &str, hub: &Value, (seq, epoch): (i64, u64), by: &str, now: i64) -> Vec<Value> {
        let (did, uri) = (s_of(&hub["did"]), s_of(&hub["uri"]));
        let Some(c) = self.convs.get_mut(gid) else { return vec![] };
        let moved = c.hub.0 != did;
        c.hub = (did.clone(), uri.clone());
        let mut g = json!({"group": gid, "state": "joined", "hub": did});
        if uri.starts_with("wss://") {
            g["hub_uri"] = json!(uri);
        }
        let mut out = vec![];
        if moved {
            g["handover_seq"] = json!(seq);
            // rendered in the thread like a roster change, attributed to the committing identity
            let entry = json!({"seq": seq, "epoch": epoch, "by": by, "added": [], "removed": [], "left": [], "hub": did});
            self.roster_log.entry(gid.to_string()).or_default().push(entry.clone());
            let mut ui = entry;
            ui["ui"] = json!("hub_moved");
            ui["group"] = json!(gid);
            out.push(ui);
        }
        let env = self.config_env(json!({"subject": self.keys.identity, "groups": [g]}), now);
        out.insert(0, json!({"send": env.frame()}));
        out
    }

    /// A deposit to a group's hub through this device's mailbox, the delegation in the header (M§5.1, M§5.2).
    fn hub_deposit(&mut self, gid: &str, class: &str, fields: Value, now: i64) -> String {
        let hub = self.convs.get(gid).map(|c| c.hub.0.clone()).unwrap_or_default();
        if let Some(bytes) = fields["mls"].as_str().and_then(dsip_core::b64::decode) {
            self.own.insert(digest(&bytes));
        }
        wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &hub, now, gid, class, fields).frame()
    }

    /// Stage a commit for `op` and deposit it (M§6.5); merged on `accepted`.
    fn propose(&mut self, gid: &str, op: &Op, now: i64) -> Result<String, JsValue> {
        let ctx = Context::new(now, &self.resolver);
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        if matches!(op, Op::Rejoin) {
            return self.external_commit(gid, now);
        }
        let c = self.convs.get_mut(gid).ok_or_else(|| JsValue::from_str("group"))?;
        if let Op::Leave { .. } = op {
            // M§7.3 "Leaving": the leaver's Remove proposals, committed by reference
            let (commit, _, _) = c.group.commit_to_pending_proposals(provider, &signer).map_err(|e| js(format!("{e:?}")))?;
            let fields = json!({"mls": b64(&commit.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?)});
            let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
            let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
            self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()), fields });
            return Ok(frame);
        }
        if let Op::Remove { identity } = op {
            // M§7.3: another identity is removed whole, every leaf of it (the rule every member checks, spec-gap 126)
            let leaves: Vec<LeafNodeIndex> = c.group.members()
                .filter(|m| member_identity(&c.group, m.index, &ctx).ok().is_some_and(|w| &w.identity == identity)).map(|m| m.index).collect();
            if leaves.is_empty() {
                return Err(JsValue::from_str(&format!("{identity} is not a member")));
            }
            let (commit, _, _) = c.group.remove_members(provider, &signer, &leaves).map_err(|e| js(format!("{e:?}")))?;
            let fields = json!({"mls": b64(&commit.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?)});
            let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
            let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
            self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()), fields });
            return Ok(frame);
        }
        if let Op::MoveHub { hub } = op {
            // M§7.4: a GroupContextExtensions commit changing the hub and nothing else, ordered by the old hub
            let commit = self.mls.move_hub_commit(&mut c.group, hub).map_err(|e| js(e.0))?;
            let fields = json!({"mls": b64(&commit.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?)});
            let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
            let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
            self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()), fields });
            return Ok(frame);
        }
        let Op::Add { kps, grants, .. } = op else { unreachable!("Rejoin, Leave, Remove and MoveHub are handled above") };
        let mut packages = vec![];
        for bytes in kps {
            let (kp, _) = authenticate_key_package(bytes, provider, &ctx).map_err(|e| js(e.0))?;
            packages.push(kp);
        }
        let (commit, welcome, _) = c.group.add_members(provider, &signer, &packages).map_err(|e| js(format!("{e:?}")))?;
        let mut fields = json!({"mls": b64(&commit.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?)});
        fields["welcome"] = json!(b64(&welcome.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?));
        if !grants.is_empty() {
            fields["grants"] = json!(grants);
        }
        let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()), fields });
        Ok(frame)
    }

    /// Whether a conversation is recorded and by whom, from its members' leaves (C§5, the pinned `conversation`
    /// check), with the recorders accepted: this identity's own (C§5: they need none) and those its devices accepted
    /// for this conversation. `pending` lists the recorders still to accept: a new one asks again.
    fn recording_of(&self, leaves: &[dsip_messaging::mls_wire::LeafIdentity], conversation: &str) -> Value {
        let leaves_json: Vec<Value> = leaves.iter().map(|w| json!({"device": w.device, "subject": w.identity, "capabilities": w.capabilities})).collect();
        let mine = self.recording_accepted.get(conversation);
        let accepted: Vec<&str> = leaves.iter().filter(|w| w.is_recorder())
            .filter(|w| w.identity == self.keys.identity || mine.is_some_and(|m| m.contains(&w.device))).map(|w| w.device.as_str()).collect();
        let mut out = dsip_recording::conversation(&json!({"leaves": leaves_json, "accepted": accepted}));
        let pending: Vec<Value> = out["recorders"].as_array().into_iter().flatten()
            .filter(|r| !r["device"].as_str().is_some_and(|d| accepted.contains(&d))).cloned().collect();
        out["pending"] = json!(pending);
        out
    }

    /// The members' leaves of a group this device is in, authenticated at `now` (M§6.2).
    fn leaves_of(&self, gid: &str, now: i64) -> Vec<dsip_messaging::mls_wire::LeafIdentity> {
        let ctx = Context::new(now, &self.resolver);
        self.convs.get(gid).map(|c| c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).collect()).unwrap_or_default()
    }

    /// Content may go to `gid` (C§5): this device is not a recorder, which never speaks, and every recorder in the
    /// conversation is accepted.
    fn may_send_content(&self, gid: &str, now: i64) -> Result<(), JsValue> {
        if self.recorder {
            return Err(JsValue::from_str("this device is a recorder: it never sends content (C§5)"));
        }
        if self.leaving.contains(gid) {
            return Err(JsValue::from_str("this identity has left the conversation (M§7.3)"));
        }
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        if self.recording_of(&self.leaves_of(gid, now), &conversation)["may_send"] != json!(true) {
            return Err(JsValue::from_str("this conversation is recorded and a recorder is not accepted: no content is sent (C§5)"));
        }
        Ok(())
    }

    /// Encrypt an application object and deposit it; pending until accepted (M§9.2).
    fn send_object(&mut self, gid: &str, obj: &Value, now: i64) -> Result<String, JsValue> {
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let c = self.convs.get_mut(gid).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        let bytes = c.group.create_message(provider, &signer, &serde_json::to_vec(obj).map_err(js)?)
            .map_err(|e| js(format!("{e:?}")))?.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?;
        let mut item = json!({"id": self.fresh_id(now), "mls": b64(&bytes), "obj": obj});
        if let Some(b) = obj.get("blob") {
            // M§8.4 rule 4: the deposit's manifest names the blob without its key
            item["blobs"] = json!([{"uri": b["uri"], "sha256": b["sha256"], "size": b["size"]}]);
        }
        if self.outages.get(gid).is_some_and(HubOutage::is_abandoned) {
            // M§9.4: the dead group takes no more content; it goes to the successor once there is one
            self.handover.entry(gid.to_string()).or_default().push(obj.clone());
            return Ok(String::new());
        }
        self.outbox.entry(gid.to_string()).or_default().push(item.clone());
        let item_id = s_of(&item["id"]);
        let queued = self.outages.get_mut(gid).is_some_and(|o| o.deposit(&item_id).iter().any(|e| e.get("queued").is_some()));
        if obj["object"] == "content" {
            // shown at once as ours; its seq is filled in by the hub's accepted (M§8.5)
            let key = format!("{}:{}", obj["conversation"].as_str().unwrap_or(""), obj["id"].as_str().unwrap_or(""));
            self.shown.insert(key.clone());
            self.messages.push(json!({"group": gid, "key": key, "sender": self.keys.identity, "sender_device": self.keys.device.did(),
                "object": obj, "seq": null, "mine": true, "item": item["id"]}));
        }
        if queued {
            return Ok(String::new()); // M§9.4: queued behind the pending head while the hub is down
        }
        Ok(self.deposit_item(gid, &item, now))
    }

    /// The deposit of a pending item, under a fresh envelope but the same item id and bytes (M§9.3).
    fn deposit_item(&mut self, gid: &str, item: &Value, now: i64) -> String {
        let mut fields = json!({"mls": item["mls"]});
        if let Some(b) = item.get("blobs") {
            fields["blobs"] = b.clone();
        }
        let frame = self.hub_deposit(gid, "application", fields, now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.sent_at.insert(id.clone(), now);
        self.pending.insert(id, Pending::Application { gid: gid.to_string(), item: s_of(&item["id"]) });
        frame
    }

    /// The hub or mailbox accepted a deposit of ours (M§5.3).
    fn accepted(&mut self, p: &Value, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let Some(pending) = self.pending.remove(&s_of(&p["in_reply_to"])) else { return out };
        match pending {
            Pending::Proposal { gid } => {
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                out.push(json!({"ui": "leave_proposed", "group": gid, "seq": p["seq"]}));
            }
            Pending::Commit { gid, op: Some(Op::Rejoin), .. } => {
                // M§6.8: the external commit is already applied locally (OpenMLS stores it merged)
                let Some(c) = self.convs.get(&gid) else { return out };
                let (epoch, kind, conversation) = (c.group.epoch().as_u64(), c.kind.clone(), c.conversation.clone());
                let members = self.member_identities(&gid, now);
                if kind == "personal" {
                    self.personal = Some(gid.clone());
                }
                self.history.step(&json!({"joined": {"group": gid, "epoch": epoch}}));
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                self.retries.remove(&gid);
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "joined"}]}), now);
                out.push(json!({"send": env.frame()}));
                out.push(json!({"ui": "joined", "group": gid, "conversation": conversation, "kind": kind, "members": members, "epoch": epoch,
                    "external": true, "seq": p["seq"]}));
                // M§6.5 rule 6: the hub gets the GroupInfo of the new epoch
                if let Ok(f) = self.group_info_frame(&gid, now) {
                    let id = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                    self.pending.insert(id, Pending::GroupInfo { gid, then: None });
                    out.push(json!({"send": f}));
                }
            }
            Pending::Commit { gid, op, .. } => {
                let before_ids = self.member_identities(&gid, now);
                let left: Vec<String> = match &op {
                    Some(Op::Leave { identity }) => vec![identity.clone()],
                    _ => vec![],
                };
                if let Some(c) = self.convs.get_mut(&gid) {
                    if let Err(e) = c.group.merge_pending_commit(self.mls.provider()) {
                        out.push(json!({"error": format!("merge commit: {e:?}")}));
                        return out;
                    }
                    let epoch = c.group.epoch().as_u64();
                    let (added, device) = match &op { Some(Op::Add { peer, device, .. }) => (Some(peer.clone()), device.clone()), _ => (None, None) };
                    out.push(json!({"ui": "committed", "group": gid, "epoch": epoch, "seq": p["seq"], "added": added, "device": device,
                        "personal": self.personal.as_deref() == Some(gid.as_str())}));
                }
                if let Some(epoch) = self.convs.get(&gid).map(|c| c.group.epoch().as_u64()) {
                    let me = self.keys.identity.clone();
                    out.extend(self.log_roster(&gid, (p["seq"].clone(), epoch), &me, &before_ids, &left, now));
                }
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                self.retries.remove(&gid);
                self.unknown_at.remove(&gid);
                // M§7.4: the committer's mailbox follows on `accepted`, and the new hub is bootstrapped by the GroupInfo
                // carrying the seq the old hub gave the moving commit
                let mut handover_seq = None;
                if let (Some(Op::MoveHub { hub }), Some(seq), Some(epoch)) = (&op, p["seq"].as_i64(), self.convs.get(&gid).map(|c| c.group.epoch().as_u64())) {
                    let me = self.keys.identity.clone();
                    out.extend(self.hub_moved(&gid, hub, (seq, epoch), &me, now));
                    handover_seq = Some(seq);
                }
                out.extend(self.flush_handover(&gid, now)); // M§9.4: the successor holds its members: the pending items go in
                match self.group_info_frame_at(&gid, handover_seq, now) {
                    Ok(f) => {
                        let id = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                        self.pending.insert(id, Pending::GroupInfo { gid, then: None });
                        out.push(json!({"send": f}));
                    }
                    Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
                }
            }
            Pending::GroupInfo { gid, then } => {
                if then.is_none() {
                    out.extend(self.flush_handover(&gid, now)); // a successor with nobody to add (M§9.4)
                }
                if let Some(op) = then {
                    match self.propose(&gid, &op, now) {
                        Ok(f) => out.push(json!({"send": f})),
                        Err(e) => out.push(json!({"refused": format!("add: {}", e.as_string().unwrap_or_default())})),
                    }
                }
                if let Some(Pending::PersonalReady { gid: g }) = self.pending.remove(&format!("personal:{gid}")) {
                    // M§7.1, M§12.1: the first archive key, sent to the personal group as an object
                    let akid = self.fresh_id(now);
                    let key = KeyPair::generate().seed(); // 32 random bytes (M§12.1)
                    self.archive_keys.insert(akid.clone(), (key.to_vec(), now));
                    self.history.step(&json!({"archive_key": {"akid": akid, "created_at": now}})); // the current key, from now on
                    let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": now});
                    match self.send_object(&g, &obj, now) {
                        Ok(f) => out.push(json!({"send": f})),
                        Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
                    }
                    out.push(json!({"ui": "personal", "group": g}));
                }
            }
            Pending::Application { gid, item } => {
                let obj = self.outbox.get(&gid).and_then(|items| items.iter().find(|i| i["id"] == item)).map(|i| i["obj"].clone());
                if let Some(items) = self.outbox.get_mut(&gid) {
                    items.retain(|i| i["id"] != item);
                }
                if let (Some(obj), Some(seq)) = (obj.clone().filter(|o| o["object"] == "content"), p["seq"].as_i64()) {
                    if let Some(c) = self.convs.get_mut(&gid) {
                        // M§10.2: our own content enters the receipts machine at its hub seq, so receipts for it are booked
                        c.receipts.step(&json!({"advance": (now - c.receipts.now()).max(0)}));
                        c.receipts.step(&json!({"sync": {"items": [{"seq": seq, "object": obj}]}}));
                    }
                    // M§12.2 (spec-gap 51): our own content is archived under the seq of its accepted
                    let key = format!("{}:{}", obj["conversation"].as_str().unwrap_or(""), obj["id"].as_str().unwrap_or(""));
                    let emissions = self.history.step(&json!({"sent": {"group": gid, "seq": seq, "id": key, "object": "content"}}));
                    let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                    out.extend(self.archive_requests(&gid, &emissions, &obj, &me, &dev, seq, now));
                } else if let (Some(obj), Some(seq)) = (obj.clone().filter(|o| o["object"] == "call-event"), p["seq"].as_i64()) {
                    // spec-gap 63: a call event is archived like a read watermark, state for a device added later
                    let emissions = self.history.step(&json!({"sent": {"group": gid, "seq": seq, "id": object_key(&obj), "object": "call-event"}}));
                    let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                    out.extend(self.archive_requests(&gid, &emissions, &obj, &me, &dev, seq, now));
                } else if let (Some(obj), Some(seq)) = (obj.filter(|o| o["object"] == "receipt" && o["kind"] == "read"), p["seq"].as_i64()) {
                    // spec-gap 68: our own read watermark is history too, under the group it went to
                    let key = format!("{}:{}", obj["conversation"].as_str().unwrap_or(""), obj["id"].as_str().unwrap_or(""));
                    let emissions = self.history.step(&json!({"sent": {"group": gid, "seq": seq, "id": key, "object": "receipt"}}));
                    let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                    out.extend(self.archive_requests(&gid, &emissions, &obj, &me, &dev, seq, now));
                }
                if let Some(seq) = p["seq"].as_i64() {
                    // spec-gap 47: our own copy is processed by its accepted seq
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": "application"}}));
                    for m in self.messages.iter_mut().filter(|m| m["item"] == item) {
                        m["seq"] = json!(seq);
                    }
                }
                out.push(json!({"ui": "sent", "group": gid, "item": item, "seq": p["seq"], "duplicate": p["duplicate"]}));
                // M§9.4: an accepted ends an outage and flushes the queue in order
                let ems = self.outages.get_mut(&gid).map(|o| o.answer(&item, None)).unwrap_or_default();
                if ems.iter().any(|e| e.get("forward").is_some()) {
                    out.push(json!({"ui": "hub_back", "group": gid}));
                }
                out.extend(self.outage_emissions(&gid, ems, now));
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { count } => out.push(json!({"ui": "key_packages_uploaded", "count": count})),
            Pending::Config { .. } => {}
            Pending::Archive { .. } => out.push(json!({"ui": "archived", "duplicate": p["duplicate"]})),
        }
        out
    }

    /// The hub or mailbox refused a deposit of ours (M§16): a commit as `CommitRetry` decides (spec-gap 58).
    fn refused(&mut self, p: &Value, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let reason = s_of(&p["reason"]);
        let Some(pending) = self.pending.remove(&s_of(&p["in_reply_to"])) else {
            out.push(json!({"error": format!("{reason} {}", p["detail"])}));
            return out;
        };
        match pending {
            Pending::Commit { gid, op, .. } => {
                let mut retry = self.retries.remove(&gid).map(|(r, _)| r).unwrap_or_else(|| CommitRetry::new(&json!({})));
                for action in retry.answer(Some(&reason)) {
                    if action.get("discard").is_some() {
                        if matches!(op, Some(Op::Rejoin)) {
                            // M§6.8: the joined state from a GroupInfo that was not the latest is discarded
                            if let Some(mut c) = self.convs.remove(&gid) {
                                let _ = c.group.delete(self.mls.provider().storage());
                            }
                        } else if let Some(c) = self.convs.get_mut(&gid) {
                            let _ = c.group.clear_pending_commit(self.mls.provider().storage());
                        }
                    } else if let Some(r) = action.get("surface") {
                        out.push(json!({"refused": format!("commit in {gid}: {}", r.as_str().unwrap_or(""))}));
                    } else if action.get("sync").is_some() {
                        if reason == "mailbox.unknown-group" {
                            // M§7.4: the group may have moved; the sync shows whether it did
                            if let Some(c) = self.convs.get(&gid) {
                                self.unknown_at.insert(gid.clone(), c.hub.0.clone());
                            }
                        }
                        out.push(json!({"ui": "conflict", "group": gid, "reason": reason}));
                        if let Some(op) = op.clone() {
                            self.retries.insert(gid.clone(), (retry.clone(), op));
                        }
                        out.push(json!({"sync": true}));
                    }
                }
            }
            Pending::GroupInfo { gid, .. } => out.push(json!({"refused": format!("group-info for {gid}: {reason}")})),
            // M§7.3: a refused proposal (a stale epoch) is proposed again at the next epoch
            Pending::Proposal { gid } => out.push(json!({"ui": "leave_proposal_refused", "group": gid, "reason": reason})),
            Pending::Application { gid, item } if reason == "mailbox.unknown-group" && self.convs.contains_key(&gid) => {
                // M§7.4 "A member that missed the move": sync; re-encrypted and re-sent to the new hub if the group moved
                let hub = self.convs.get(&gid).map(|c| c.hub.0.clone()).unwrap_or_default();
                self.unknown_at.insert(gid.clone(), hub);
                self.moved_items.entry(gid.clone()).or_default().push(item.clone());
                out.push(json!({"ui": "moved_check", "group": gid, "item": item}));
                out.push(json!({"sync": true}));
            }
            Pending::Application { gid, item } => {
                let down = is_outage(&reason);
                if !down {
                    // M§9.4: unreachable keeps it pending; any other refusal is final
                    if let Some(items) = self.outbox.get_mut(&gid) {
                        items.retain(|i| i["id"] != item);
                    }
                    self.messages.retain(|m| m["item"] != item);
                    if let Some(o) = self.outages.get_mut(&gid) {
                        o.answer(&item, Some(&reason));
                    }
                } else {
                    out.extend(self.hub_unreachable(&gid, &item, false, now));
                }
                out.push(json!({"refused": format!("message {item}: {reason}"), "group": gid, "item": item, "pending": down}));
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { .. } => out.push(json!({"refused": format!("key packages: {reason}")})),
            Pending::Config { .. } => out.push(json!({"refused": format!("mailbox-config: {reason}")})),
            Pending::Archive { .. } => out.push(json!({"refused": format!("archive record: {reason}")})),
        }
        out
    }

    /// After a sync caught up: re-propose membership changes that lost a conflict and are still needed (M§6.5).
    fn after_sync(&mut self, now: i64) -> Vec<Value> {
        let mut out = vec![];
        for gid in self.retries.keys().cloned().collect::<Vec<_>>() {
            let (mut retry, op) = self.retries.remove(&gid).expect("present");
            let needed = match &op {
                // M§6.8: still needed while this device is not in the group
                Op::Rejoin => !self.convs.contains_key(&gid),
                // M§7.3: the proposals lapsed with the epoch the conflict moved past; the leaver proposes again
                Op::Leave { .. } => false,
                // M§7.3: still needed while any leaf of the identity remains
                Op::Remove { identity } => self.member_identities(&gid, now).contains(identity),
                // M§7.4: still needed while the group is hubbed elsewhere
                Op::MoveHub { hub } => self.convs.get(&gid).is_some_and(|c| c.hub.0 != s_of(&hub["did"])),
                Op::Add { peer, device, .. } => {
                    let ctx = self.ctx(now);
                    self.convs.get(&gid).is_some_and(|c| !c.group.members().any(|m| member_identity(&c.group, m.index, &ctx).ok()
                        .is_some_and(|w| &w.identity == peer && device.as_ref().is_none_or(|d| &w.device == d))))
                }
            };
            let moved = self.hub_moved_since(&gid);
            for action in retry.synced(needed, moved) {
                if action.get("done").is_some() {
                    out.push(json!({"ui": "no_longer_needed", "group": gid}));
                } else if let Some(r) = action.get("surface") {
                    out.push(json!({"refused": format!("commit in {gid}: {}", r.as_str().unwrap_or(""))}));
                } else if action.get("repropose").is_some() {
                    match self.propose(&gid, &op, now) {
                        Ok(f) => {
                            self.retries.insert(gid.clone(), (retry.clone(), op.clone()));
                            out.push(json!({"send": f}));
                        }
                        Err(e) => out.push(json!({"refused": e.as_string().unwrap_or_default()})),
                    }
                }
            }
        }
        for (gid, items) in std::mem::take(&mut self.moved_items) {
            let moved = self.hub_moved_since(&gid);
            for item in items {
                if moved {
                    // M§7.4: re-encrypted at the current epoch and re-sent to the new hub
                    match self.reencrypt_item(&gid, &item, now) {
                        Some(f) => out.push(json!({"send": f})),
                        None => out.push(json!({"refused": format!("message {item}: no longer in the outbox"), "group": gid, "item": item})),
                    }
                } else {
                    // spec-gap 60: no move, so mailbox.unknown-group is final
                    if let Some(items) = self.outbox.get_mut(&gid) {
                        items.retain(|i| i["id"] != item);
                    }
                    self.messages.retain(|m| m["item"] != item);
                    out.push(json!({"refused": format!("message {item}: mailbox.unknown-group"), "group": gid, "item": item, "pending": false}));
                }
            }
        }
        let waiting: BTreeSet<String> = self.retries.keys().cloned().collect();
        self.unknown_at.retain(|g, _| waiting.contains(g));
        out
    }

    /// Whether the group's hub is no longer the one that answered `mailbox.unknown-group` (M§7.4, spec-gap 60).
    fn hub_moved_since(&self, gid: &str) -> bool {
        match (self.unknown_at.get(gid), self.convs.get(gid)) {
            (Some(at), Some(c)) => c.hub.0 != *at,
            _ => false,
        }
    }

    /// An outbox item encrypted afresh at the group's current epoch and deposited to its current hub (M§7.4).
    fn reencrypt_item(&mut self, gid: &str, item_id: &str, now: i64) -> Option<String> {
        let obj = self.outbox.get(gid)?.iter().find(|i| i["id"] == item_id)?["obj"].clone();
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let c = self.convs.get_mut(gid)?;
        let bytes = c.group.create_message(provider, &signer, &serde_json::to_vec(&obj).ok()?).ok()?.tls_serialize_detached().ok()?;
        let item = self.outbox.get_mut(gid)?.iter_mut().find(|i| i["id"] == item_id)?;
        item["mls"] = json!(b64(&bytes));
        let item = item.clone();
        Some(self.deposit_item(gid, &item, now))
    }

    fn gap_of_from(&mut self, gid: &str, first_seq: i64) -> &mut GapTracker {
        let committed = self.resume.snapshot()["groups"][gid]["contiguous"].as_i64().unwrap_or(0);
        let contiguous = if committed == 0 { (first_seq - 1).max(0) } else { committed };
        let timeout = self.gap_timeout;
        self.gaps.entry(gid.to_string()).or_insert_with(|| GapTracker::new(&json!({"now": 0, "contiguous": contiguous, "gap_timeout": timeout})))
    }

    /// One `items[]` element (M§5.4): committed with the MLS change it caused (spec-gap 44).
    fn item(&mut self, item: &Value, now: i64) -> Result<Vec<Value>, MlsError> {
        let mut out = vec![];
        let class = s_of(&item["class"]);
        if class == "ephemeral" {
            return Ok(out);
        }
        if self.resume.is_duplicate(item) {
            self.resume.commit(item, true);
            out.push(json!({"ui": "duplicate", "class": class, "cursor": item["cursor"]}));
            return Ok(out);
        }
        if matches!(class.as_str(), "introduction" | "grant") {
            out.extend(self.first_contact_in(item, now));
            self.resume.commit(item, false);
            return Ok(out);
        }
        let gid = s_of(&item["group"]);
        if class == "archive" {
            out.extend(self.archive_in(item, now));
            self.resume.commit(item, false);
            return Ok(out);
        }
        if class == "group-info" {
            self.group_info.insert(gid, s_of(&item["mls"]));
            self.resume.commit(item, false);
            return Ok(out);
        }
        if !matches!(class.as_str(), "welcome" | "handshake" | "application") {
            self.resume.commit(item, false);
            return Ok(out);
        }
        let bytes = unb64(&item["mls"]);
        if class != "welcome" && self.own.contains(&digest(&bytes)) {
            // our own deposit fanned back (M§6.5 rule 5), arriving before its accepted (spec-gap 47)
            self.resume.commit(item, false);
            out.push(json!({"ui": "self", "class": class, "seq": item["seq"]}));
            return Ok(out);
        }
        if class != "welcome" {
            // M§12.3: items from before this device joined are history; a group it is not in is skipped
            let pre = match message_header(&bytes) {
                Ok((_, epoch, _)) => self.convs.get(&gid).is_none_or(|c| epoch < c.joined_epoch),
                Err(_) => false,
            };
            if pre {
                self.resume.commit(item, false);
                out.push(json!({"ui": "prejoin", "class": class, "seq": item["seq"]}));
                return Ok(out);
            }
        }
        // M§6.5 (spec-gap 69): a handshake beyond a seq gap, and anything after a held item, waits for the gap
        let mut released = vec![];
        if class != "welcome" && item["held_release"] != json!(true) && self.convs.contains_key(&gid) {
            let seq = item["seq"].as_i64().unwrap_or(0);
            let decisions = self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": class}}));
            if decisions.iter().any(|d| d["hold"] == json!(seq)) {
                let mut held = item.clone();
                held["held_release"] = json!(true);
                self.held_items.entry(gid.clone()).or_default().push(held);
                self.resume.commit(item, true);
                out.push(json!({"ui": "hold", "class": class, "seq": seq}));
                return Ok(out);
            }
            for d in &decisions {
                if let Some(s) = d["process"].as_i64().filter(|s| *s != seq) {
                    if let Some(items) = self.held_items.get_mut(&gid) {
                        if let Some(i) = items.iter().position(|h| h["seq"] == json!(s)) {
                            released.push(items.remove(i));
                        }
                    }
                }
            }
        }
        let before_ids = self.member_identities(&gid, now);
        let outcome = {
            let ctx = Context::new(now, &self.resolver);
            let me = self.keys.identity.clone();
            let target = self.convs.get_mut(&gid).filter(|_| class != "welcome").map(|c| (&mut c.group, c.conversation.as_str(), c.kind.as_str()));
            process(&self.mls, target, &class, &bytes, &ctx, &me)?
        };
        // committed: the delivery state records the item with its MLS effect (the host saves both together)
        self.resume.commit(item, matches!(outcome, Outcome::NotForDevice));
        match outcome {
            Outcome::Joined { members, group, conv, epoch, by } => {
                let joined = self.mls.load_group(&dsip_core::b64::decode(&group).unwrap_or_default())?.ok_or_else(|| MlsError("joined group not stored".into()))?;
                let kind = s_of(&conv["kind"]);
                let peer = members.iter().find(|m| **m != self.keys.identity).cloned();
                self.convs.insert(group.clone(), Conv {
                    group: joined, conversation: s_of(&conv["conversation"]), kind: kind.clone(),
                    hub: (s_of(&conv["hub"]["did"]), s_of(&conv["hub"]["uri"])), peer: if kind == "direct" { peer } else { None },
                    receipts: self.new_receipts(now), joined_epoch: epoch, batch: vec![],
                });
                if kind == "personal" {
                    self.personal = Some(group.clone());
                }
                self.history.step(&json!({"joined": {"group": group, "epoch": epoch}}));
                // M§6.6: confirm the pending registration
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": group, "state": "joined"}]}), now);
                out.push(json!({"send": env.frame()}));
                out.push(json!({"ui": "joined", "group": group, "conversation": conv["conversation"], "kind": kind, "members": members, "epoch": epoch,
                    "successor_of": conv["successor_of"]}));
                if kind != "personal" && by != self.keys.identity {
                    // M§7.3: the joiner renders its own add, attributed to the identity whose commit added it
                    let entry = json!({"seq": item["seq"], "epoch": epoch, "by": by, "added": [self.keys.identity], "removed": [], "left": []});
                    self.roster_log.entry(group.clone()).or_default().push(entry.clone());
                    let mut ui = entry;
                    ui["ui"] = json!("roster");
                    ui["group"] = json!(group);
                    out.push(ui);
                }
                if let Some(pred) = conv["successor_of"].as_str().map(String::from) {
                    out.extend(self.successor_welcome(&group, &pred, now));
                }
            }
            Outcome::Object { sender, sender_device, object } => out.extend(self.object_in(&gid, item, &sender, &sender_device, object, now)),
            Outcome::Dropped(why) => out.push(json!({"ui": "dropped", "why": why})),
            Outcome::Unauthenticated(what) => out.push(json!({"ui": "unauthenticated", "what": what})),
            Outcome::NotForDevice => out.push(json!({"ui": "sibling_welcome", "cursor": item["cursor"]})),
            Outcome::Epoch { epoch, by, added, removed, left, hub } => {
                if let Some(h) = hub {
                    // M§7.4: a device that processes the moving commit tells its mailbox
                    out.extend(self.hub_moved(&gid, &h, (item["seq"].as_i64().unwrap_or(0), epoch), &by, now));
                }
                out.extend(self.log_roster(&gid, (item["seq"].clone(), epoch), &by, &before_ids, &left, now));
                out.push(json!({"ui": "epoch", "group": gid, "epoch": epoch, "by": by, "added": added, "removed": removed}));
                if self.leaving.contains(&gid) {
                    // M§7.3: a proposal lapses with its epoch; still a member, the leave is proposed again
                    out.extend(self.propose_leave(&gid, now));
                }
            }
            Outcome::Removed { by, remaining } => {
                let was_leaving = self.leaving.remove(&gid);
                self.resume.removed(&gid); // spec-gap 127: a member may add this identity back with a new welcome
                let mut c = self.convs.remove(&gid);
                if let Some(c) = c.as_mut() {
                    // spec-gap 127: the group's MLS state goes too, so a welcome back into the same group id can be joined
                    let _ = c.group.delete(self.mls.provider().storage());
                }
                // and the seq gaps it tracked there: a welcome back starts counting afresh from its own seq (spec-gap 83)
                self.gaps.remove(&gid);
                self.held_items.remove(&gid);
                if self.personal.as_deref() == Some(gid.as_str()) {
                    self.personal = None;
                }
                out.push(json!({"ui": "removed", "group": gid, "by": by, "conversation": c.map(|c| c.conversation), "left": was_leaving}));
                let decision = registration_on_removal(&json!({"me": self.keys.identity, "remaining_identities": remaining}));
                if decision["left"] == json!(true) {
                    let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "left"}]}), now);
                    out.push(json!({"send": env.frame()}));
                }
            }
            Outcome::Proposal { proposer, removes, others, roster } => {
                let d = dsip_messaging::checks::leave_proposals(&json!({"me": self.keys.identity, "proposer": proposer, "removes": removes,
                    "others": others, "roster": roster}));
                let who = s_of(&proposer["identity"]);
                match d["action"].as_str() {
                    Some("commit") => match self.propose(&gid, &Op::Leave { identity: who.clone() }, now) {
                        Ok(f) => {
                            out.push(json!({"send": f}));
                            out.push(json!({"ui": "leave_committing", "group": gid, "identity": who}));
                        }
                        Err(e) => out.push(json!({"error": format!("committing the leave of {who}: {}", e.as_string().unwrap_or_default())})),
                    },
                    Some("left") => {
                        // a sibling device left for this identity: nothing more is sent; the commit removing us follows
                        self.leaving.insert(gid.clone());
                        out.push(json!({"ui": "left", "group": gid, "by_device": proposer["device"]}));
                    }
                    _ => out.push(json!({"ui": "leave_proposals", "group": gid, "identity": who, "decision": d})),
                }
            }
            Outcome::Nothing => {}
        }
        for held in released {
            out.push(json!({"ui": "released", "class": held["class"], "seq": held["seq"]}));
            out.extend(self.item(&held, now)?);
        }
        Ok(out)
    }

    /// A decrypted application object, already committed (M§8.1).
    fn object_in(&mut self, gid: &str, item: &Value, sender: &str, sender_device: &str, object: Value, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let seq = item["seq"].as_i64().unwrap_or(0);
        match object["object"].as_str() {
            Some("archive-key") => {
                let akid = s_of(&object["akid"]);
                let created = object["created_at"].as_i64().unwrap_or(0);
                let fresh = !self.archive_keys.contains_key(&akid);
                self.archive_keys.entry(akid.clone()).or_insert((unb64(&object["key"]), created));
                // M§12.3 step 5 (spec-gap 51): records kept for this key open now
                let decisions = self.history.step(&json!({"archive_key": {"akid": akid, "created_at": created}}));
                let _ = decisions;
                let release: Vec<String> = self.held_archive.iter().filter(|(_, h)| h["akid"] == json!(akid)).map(|(c, _)| c.clone()).collect();
                for c in release {
                    if let Some(h) = self.held_archive.remove(&c) {
                        out.extend(self.open_archive(&h, now));
                    }
                }
                out.push(json!({"ui": "archive_key", "akid": akid, "from": sender, "fresh": fresh}));
            }
            Some("call-event") => {
                // M§13.3: every device of the identity shows one entry per call, whichever device sent it
                let key = object_key(&object);
                let epoch = self.convs.get(gid).map(|c| c.group.epoch().as_u64()).unwrap_or(0);
                let emissions = self.history.step(&json!({"mls": {"group": gid, "seq": seq, "epoch": epoch, "id": key}}));
                out.extend(self.archive_requests(gid, &emissions, &object, sender, sender_device, seq, now));
                let fresh = self.record_call(&object);
                out.push(json!({"ui": "call_event", "session": object["session"], "peer": object["peer"], "outcome": object["outcome"],
                    "from_device": sender_device, "collapsed": !fresh}));
            }
            Some("recording-acceptance") => {
                // C§5: each device accepts the union of its own acceptances and those in its personal group
                let conv = s_of(&object["conversation"]);
                let devices: Vec<String> = object["recorders"].as_array().into_iter().flatten().filter_map(|d| d.as_str().map(String::from)).collect();
                self.recording_accepted.entry(conv.clone()).or_default().extend(devices.iter().cloned());
                out.push(json!({"ui": "recording_accepted", "conversation": conv, "recorders": devices, "from_device": sender_device}));
            }
            Some("call-record") if self.recorder => {
                // C§9: a record-keeper keeps one record per session leg (the sending device's)
                let fresh = !self.records.iter().any(|r| r["record"]["session"] == object["session"] && r["device"] == sender_device);
                if fresh {
                    self.records.push(json!({"group": gid, "from": sender, "device": sender_device, "received_at": now, "record": object}));
                }
                out.push(json!({"ui": "call_record", "from": sender, "session": object["session"], "outcome": object["outcome"], "fresh": fresh}));
            }
            Some("receipt") => {
                if let Some(c) = self.convs.get_mut(gid) {
                    let batch = json!({"seq": seq, "object": object, "src": gid, "sender_device": sender_device});
                    c.receipts.step(&json!({"advance": (now - c.receipts.now()).max(0)}));
                    let emissions = c.receipts.step(&json!({"sync": {"items": [batch]}}));
                    out.extend(emissions.into_iter().filter_map(|e| e.get("send").cloned()).map(|s| json!({"receipt_send": {"group": gid, "send": s}})));
                }
                out.push(json!({"ui": "receipt", "group": gid, "from": sender, "kind": object["kind"], "targets": object["targets"], "through": object["through"]}));
            }
            Some("content") => {
                let key = format!("{}:{}", object["conversation"].as_str().unwrap_or(""), object["id"].as_str().unwrap_or(""));
                if !self.shown.insert(key.clone()) {
                    out.push(json!({"ui": "duplicate_content", "seq": seq}));
                    return out;
                }
                // a sibling device's content is this identity's own (M§12.3: sent messages reach every device)
                self.messages.push(json!({"group": gid, "key": key, "sender": sender, "sender_device": sender_device, "object": object,
                    "seq": seq, "mine": sender == self.keys.identity, "item": null, "blobs": item["blobs"]}));
                if let Some(c) = self.convs.get_mut(gid) {
                    c.pending_batch_push(json!({"seq": seq, "object": object.clone()}));
                }
                // M§12.2: what is shown from MLS is archived under the current key
                let epoch = self.convs.get(gid).map(|c| c.group.epoch().as_u64()).unwrap_or(0);
                let emissions = self.history.step(&json!({"mls": {"group": gid, "seq": seq, "epoch": epoch, "id": key}}));
                out.extend(self.archive_requests(gid, &emissions, &object, sender, sender_device, seq, now));
                out.push(json!({"ui": "message", "group": gid, "from": sender, "seq": seq, "kind": object["kind"], "text": object["text"], "sent_at": object["sent_at"],
                    "id": object["id"], "blobs": item["blobs"]}));
            }
            _ => {}
        }
        out
    }

    /// Build the external commit from the latest GroupInfo held for `gid` and deposit it at the group's hub (M§6.8).
    fn external_commit(&mut self, gid: &str, now: i64) -> Result<String, JsValue> {
        let gi = self.group_info.get(gid).cloned().ok_or_else(|| JsValue::from_str("no GroupInfo for that group from this mailbox; sync first"))?;
        if let Some(mut old) = self.convs.remove(gid) {
            let _ = old.group.delete(self.mls.provider().storage()); // superseded: the resync removes the old leaf
        }
        let (group, commit) = self.mls.external_join(&unb64(&json!(gi))).map_err(|e| js(e.0))?;
        let conv: Value = conversation_extension(&group).and_then(|b| serde_json::from_slice(&b).ok()).ok_or_else(|| JsValue::from_str("no dsip_conversation"))?;
        let epoch = group.epoch().as_u64();
        let kind = s_of(&conv["kind"]);
        self.convs.insert(gid.to_string(), Conv {
            group, conversation: s_of(&conv["conversation"]), kind: kind.clone(), hub: (s_of(&conv["hub"]["did"]), s_of(&conv["hub"]["uri"])),
            peer: None, receipts: self.new_receipts(now), joined_epoch: epoch, batch: vec![],
        });
        if kind == "direct" {
            let me = self.keys.identity.clone();
            let peer = self.member_identities(gid, now).into_iter().find(|m| *m != me);
            if let Some(c) = self.convs.get_mut(gid) {
                c.peer = peer;
            }
        }
        let bytes = commit.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?;
        let fields = json!({"mls": b64(&bytes)});
        let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(Op::Rejoin), fields });
        Ok(frame)
    }

    /// The identities with a verified leaf in `gid`, sorted.
    /// Record a merged commit's roster change by identity, from the member identities before it, and say so to the UI
    /// (M§7.3: every roster change rendered, attributed to the committing identity). Nothing when no identity came or
    /// went (a device of a member added or removed, a path update).
    fn log_roster(&mut self, gid: &str, (seq, epoch): (Value, u64), by: &str, before: &[String], left: &[String], now: i64) -> Vec<Value> {
        let after = self.member_identities(gid, now);
        let added: Vec<&String> = after.iter().filter(|i| !before.contains(i)).collect();
        let gone: Vec<&String> = before.iter().filter(|i| !after.contains(i)).collect();
        if added.is_empty() && gone.is_empty() {
            return vec![];
        }
        let (left, removed): (Vec<&String>, Vec<&String>) = gone.into_iter().partition(|i| left.contains(i));
        let entry = json!({"seq": seq, "epoch": epoch, "by": by, "added": added, "removed": removed, "left": left});
        self.roster_log.entry(gid.to_string()).or_default().push(entry.clone());
        let mut ui = entry;
        ui["ui"] = json!("roster");
        ui["group"] = json!(gid);
        vec![ui]
    }

    fn member_identities(&self, gid: &str, now: i64) -> Vec<String> {
        let ctx = Context::new(now, &self.resolver);
        let mut ids: Vec<String> = self.convs.get(gid).map(|c| c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok())
            .map(|w| w.identity).collect()).unwrap_or_default();
        ids.sort();
        ids.dedup();
        ids
    }

    /// A deposit for `gid` met an unreachable hub (or no answer): the outage starts or continues (M§9.4).
    fn hub_unreachable(&mut self, gid: &str, item: &str, silent: bool, now: i64) -> Vec<Value> {
        let timeout = self.hub_timeout;
        let pending: Vec<Value> = self.outbox.get(gid).into_iter().flatten().map(|i| i["id"].clone()).collect();
        let o = self.outages.entry(gid.to_string()).or_insert_with(|| HubOutage::new(&json!({"now": now, "hub_timeout": timeout, "pending": pending})));
        let started = !o.is_down();
        let ems = if silent { o.no_answer(item) } else { o.answer(item, Some("mailbox.hub-unreachable")) };
        let mut out = vec![];
        if started && o.is_down() {
            out.push(json!({"ui": "hub_down", "group": gid, "hub_timeout": timeout}));
        }
        out.extend(self.outage_emissions(gid, ems, now));
        out
    }

    /// Act on the outbox's emissions (M§9.4): re-deposit the head, or hand the group to its successor at the threshold.
    fn outage_emissions(&mut self, gid: &str, ems: Vec<Value>, now: i64) -> Vec<Value> {
        let mut out = vec![];
        for e in ems {
            if let Some(id) = e["forward"].as_str() {
                if let Some(item) = self.outbox.get(gid).and_then(|v| v.iter().find(|i| i["id"] == id).cloned()) {
                    out.push(json!({"send": self.deposit_item(gid, &item, now)}));
                }
            } else if let Some(d) = e["retry_in"].as_i64() {
                out.push(json!({"ui": "hub_retry", "group": gid, "in": d}));
            } else if e.get("successor").is_some() || e.get("handover").is_some() {
                // M§9.4: the threshold passed: the dead group takes no more content; its pending items are re-encrypted
                // for the successor, which the host creates once it has the members' KeyPackages (M§7.5)
                let items = self.outbox.remove(gid).unwrap_or_default();
                let ids: Vec<Value> = items.iter().map(|i| i["id"].clone()).collect();
                self.messages.retain(|m| !ids.contains(&m["item"]));
                for i in &items {
                    self.shown.remove(&object_key(&i["obj"]));
                }
                self.handover.entry(gid.to_string()).or_default().extend(items.into_iter().map(|i| i["obj"].clone()));
                self.track_rosters(now);
                let me = self.keys.identity.clone();
                let roster: Vec<String> = self.member_identities(gid, now).into_iter().filter(|i| *i != me).collect();
                out.push(json!({"successor_due": {"group": gid, "peers": roster, "kind": self.convs.get(gid).map(|c| c.kind.clone()),
                    "existing": self.successors.successor(gid)}}));
            }
        }
        out
    }

    /// A welcome to a successor group (M§7.5): the pinned check (its creator, leaf 0, was in the predecessor's last
    /// roster this device processed, and it adds nobody who was not) and convergence on the lowest `group_id`.
    fn successor_welcome(&mut self, group: &str, pred: &str, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let roster = self.member_identities(group, now);
        let creator = {
            let ctx = Context::new(now, &self.resolver);
            self.convs.get(group).and_then(|c| member_identity(&c.group, LeafNodeIndex::new(0), &ctx).ok()).map(|w| w.identity).unwrap_or_default()
        };
        // the predecessor's roster as this device last processed it; the new group itself is not tracked yet
        for gid in self.convs.keys().filter(|g| g.as_str() != group).cloned().collect::<Vec<_>>() {
            let ids = self.member_identities(&gid, now);
            if !ids.is_empty() {
                self.successors.member_of(&gid, &ids);
            }
        }
        let ems = self.successors.step(&json!({"welcome": {"group": group, "successor_of": pred, "creator": creator, "roster": roster}}));
        for e in ems {
            if e.get("join").is_some() {
                out.push(json!({"ui": "successor", "group": group, "of": pred, "creator": creator}));
                // M§9.4: what this device still had pending for the dead group goes to the successor, re-encrypted
                let items = self.outbox.remove(pred).unwrap_or_default();
                let ids: Vec<Value> = items.iter().map(|i| i["id"].clone()).collect();
                self.messages.retain(|m| !ids.contains(&m["item"]));
                for i in &items {
                    self.shown.remove(&object_key(&i["obj"]));
                }
                let mut waiting = self.handover.remove(pred).unwrap_or_default();
                waiting.extend(items.into_iter().map(|i| i["obj"].clone()));
                self.handover.entry(group.to_string()).or_default().extend(waiting);
                self.outages.remove(pred);
                out.extend(self.flush_handover(group, now));
            } else if let Some(g) = e["decline"].as_str().or(e["first_contact"].as_str()) {
                let why = if e.get("first_contact").is_some() { "not a valid successor: first contact (M§7.5)" } else { "a lower successor exists (M§7.5)" };
                out.push(json!({"ui": "successor_declined", "group": g, "of": pred, "why": why}));
                out.extend(self.leave_group(g, now).into_iter().map(|f| json!({"send": f})));
            } else if let Some(g) = e["leave"].as_str() {
                out.push(json!({"ui": "successor_left", "group": g, "of": pred}));
                out.extend(self.leave_group(g, now).into_iter().map(|f| json!({"send": f})));
            }
        }
        out
    }

    /// The group a conversation lives in now: `gid`, or the successor this device converged on (M§7.5).
    fn live(&self, gid: &str) -> String {
        let mut g = gid.to_string();
        for _ in 0..8 {
            match self.successors.successor(&g) {
                Some(w) if self.convs.contains_key(w) && w != g => g = w.to_string(),
                _ => break,
            }
        }
        g
    }

    /// Send what waits for `gid` (a successor) as new objects (M§9.4: re-encrypted, never the dead group's bytes).
    fn flush_handover(&mut self, gid: &str, now: i64) -> Vec<Value> {
        let objs = self.handover.remove(gid).unwrap_or_default();
        let mut out = vec![];
        for obj in objs {
            match self.send_object(gid, &obj, now) {
                Ok(f) if !f.is_empty() => out.push(json!({"send": f})),
                Ok(_) => {}
                Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
            }
        }
        if !out.is_empty() {
            out.push(json!({"ui": "handed_over", "group": gid, "items": out.len()}));
        }
        out
    }

    /// Record every group's roster by identity for the successor checks (M§7.5: the last roster this device processed).
    fn track_rosters(&mut self, now: i64) {
        for gid in self.convs.keys().cloned().collect::<Vec<_>>() {
            let ids = self.member_identities(&gid, now);
            if !ids.is_empty() {
                self.successors.member_of(&gid, &ids);
            }
        }
    }

    /// Stop using a group (M§7.5: a higher successor, or one that fails the check): `mailbox-config` `left`. Frames.
    fn leave_group(&mut self, gid: &str, now: i64) -> Vec<String> {
        if self.convs.remove(gid).is_none() {
            return vec![];
        }
        self.outbox.remove(gid);
        self.outages.remove(gid);
        let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "left"}]}), now);
        vec![env.frame()]
    }

    /// The groups whose messages make up `gid`'s thread: it and the predecessors it succeeds (M§7.5: the dead group
    /// stays readable and the conversation continues in the successor).
    fn lineage(&self, gid: &str) -> BTreeSet<String> {
        let mut set: BTreeSet<String> = [gid.to_string()].into();
        loop {
            let more: Vec<String> = self.convs.keys().filter(|g| !set.contains(*g) && self.successors.successor(g).is_some_and(|w| set.contains(w))).cloned().collect();
            if more.is_empty() {
                return set;
            }
            set.extend(more);
        }
    }

    /// Keep a call event unless one for its session is held (spec-gap 63: collapsed by `session`, the first kept).
    fn record_call(&mut self, obj: &Value) -> bool {
        if self.calls.iter().any(|c| c["session"] == obj["session"]) {
            return false;
        }
        self.calls.push(obj.clone());
        true
    }

    /// M§10.2: delivered receipts are decided once per sync batch, per conversation; each is sent as an object.
    fn receipts_batch(&mut self, now: i64) -> Vec<Value> {
        let mut out = vec![];
        for gid in self.convs.keys().cloned().collect::<Vec<_>>() {
            let items = self.convs.get_mut(&gid).map(|c| c.take_batch()).unwrap_or_default();
            if items.is_empty() {
                continue;
            }
            let emissions = {
                let c = self.convs.get_mut(&gid).expect("group");
                c.receipts.step(&json!({"advance": (now - c.receipts.now()).max(0)}));
                c.receipts.step(&json!({"sync": {"items": items}}))
            };
            // M§12.2 (spec-gap 64): a receipt that changed rendering is archived under the group it arrived in
            for e in emissions.iter().filter_map(|e| e.get("archive")) {
                if let Some(seq) = e["seq"].as_i64() {
                    let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                    for it in items.iter().filter(|it| it["seq"] == json!(seq) && it["object"]["object"] == "receipt") {
                        let src = it["src"].as_str().unwrap_or(&gid).to_string();
                        let sender = s_of(&it["object"]["sender"]);
                        let sender_device = it["sender_device"].as_str().unwrap_or("").to_string();
                        let (sender, sender_device) = if sender.is_empty() { (me.clone(), dev.clone()) } else { (sender, sender_device) };
                        let decisions = vec![json!({"archive": {"group": src, "seq": seq, "akid": self.history.current_akid()}})];
                        if self.history.current_akid().is_some() {
                            out.extend(self.archive_requests(&src, &decisions, &it["object"], &sender, &sender_device, seq, now));
                        }
                    }
                }
            }
            out.extend(self.receipt_sends(&gid, emissions, now));
        }
        out
    }

    /// Send what a conversation's receipts machine asked for: a receipt object to the conversation, or — an
    /// undisclosed read watermark — to the personal group (M§10.5, spec-gap 52).
    fn receipt_sends(&mut self, gid: &str, emissions: Vec<Value>, now: i64) -> Vec<Value> {
        let mut out = vec![];
        for e in emissions {
            let Some(send) = e.get("send") else { continue };
            let Some(kind) = send["receipt"].as_str() else { continue };
            let target = if send["to"] == "personal" {
                match self.personal.clone() {
                    Some(p) => p,
                    None => { out.push(json!({"ui": "read_private_kept", "group": gid})); continue; }
                }
            } else {
                gid.to_string()
            };
            if target == gid && self.may_send_content(gid, now).is_err() {
                // C§5: no receipts into a recorded conversation until its recorders are accepted (nor ever from a recorder)
                out.push(json!({"ui": "receipt_withheld", "group": gid, "kind": kind}));
                continue;
            }
            let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).unwrap_or_default();
            let mut obj = json!({"object": "receipt", "id": self.fresh_id(now), "conversation": conversation, "sender": self.keys.identity,
                "sent_at": now, "kind": kind});
            for k in ["targets", "through"] {
                if let Some(v) = send.get(k) {
                    obj[k] = v.clone();
                }
            }
            match self.send_object(&target, &obj, now) {
                Ok(f) => {
                    out.push(json!({"send": f}));
                    out.push(json!({"ui": "receipt_sent", "group": gid, "kind": kind, "targets": send["targets"], "through": send["through"],
                        "via": if target == gid { "conversation" } else { "personal group" }}));
                }
                Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
            }
        }
        out
    }

    /// Archive records the history machine asked for (M§12.2): each sealed under its key, AAD `group_id ‖ seq`, and
    /// deposited to this identity's mailbox as `class: archive`.
    #[allow(clippy::too_many_arguments)] // the record's fields, named as M§12.2 names them
    fn archive_requests(&mut self, gid: &str, emissions: &[Value], obj: &Value, sender: &str, sender_device: &str, seq: i64, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let Some(conversation) = self.convs.get(gid).map(|c| c.conversation.clone()) else { return out };
        for a in emissions.iter().filter_map(|e| e.get("archive")) {
            let akid = s_of(&a["akid"]);
            let Some((key, _)) = self.archive_keys.get(&akid).cloned() else { continue };
            let record = json!({"object": "archive-record", "conversation": conversation, "group": gid, "seq": seq,
                "sender": sender, "sender_device": sender_device, "received_at": now, "payload": obj});
            let key: [u8; 32] = match key.as_slice().try_into() { Ok(k) => k, Err(_) => continue };
            let nonce: [u8; 12] = KeyPair::generate().seed()[..12].try_into().expect("12 bytes");
            let group_bytes = dsip_core::b64::decode(gid).unwrap_or_default();
            let sealed = seal(&key, &nonce, &serde_json::to_vec(&record).unwrap_or_default(), SealUse::Archive { group: &group_bytes, seq: seq as u64 });
            let fields = json!({"archive": b64(&sealed), "akid": akid, "ref_group": gid, "ref_seq": seq});
            let env = wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &self.mailbox.0, now, gid, "archive", fields.clone());
            self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Archive { fields });
            out.push(json!({"send": env.frame()}));
            out.push(json!({"ui": "archive", "group": gid, "seq": seq, "akid": akid, "object": obj["object"]}));
        }
        out
    }

    /// An archive item (M§12.2, M§12.3 step 5): opened and shown as history, or kept sealed until its key arrives.
    fn archive_in(&mut self, item: &Value, now: i64) -> Vec<Value> {
        let akid = s_of(&item["akid"]);
        if !self.archive_keys.contains_key(&akid) {
            let cursor = s_of(&item["cursor"]);
            self.held_archive.insert(cursor.clone(), item.clone());
            self.history.step(&json!({"archive": {"cursor": cursor, "akid": akid, "group": item["group"], "seq": item["seq"]}}));
            return vec![json!({"ui": "archive_held", "cursor": cursor, "akid": akid})];
        }
        self.open_archive(item, now)
    }

    /// Open one archive record under a held key; content becomes a timeline entry once, a receipt is applied as
    /// history (nothing sent, nothing archived again — spec-gap 64).
    fn open_archive(&mut self, item: &Value, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let akid = s_of(&item["akid"]);
        let Some((key, _)) = self.archive_keys.get(&akid).cloned() else { return out };
        let key: [u8; 32] = match key.as_slice().try_into() { Ok(k) => k, Err(_) => return out };
        let gid = s_of(&item["group"]);
        let seq = item["seq"].as_i64().unwrap_or(0);
        let group_bytes = dsip_core::b64::decode(&gid).unwrap_or_default();
        let Ok(plain) = open_sealed(&key, &unb64(&item["archive"]), SealUse::Archive { group: &group_bytes, seq: seq as u64 }) else {
            out.push(json!({"ui": "dropped", "why": format!("archive {}: does not open for its group and seq", item["cursor"])}));
            return out;
        };
        let Ok(record) = serde_json::from_slice::<Value>(&plain) else { return out };
        let obj = record["payload"].clone();
        let key_id = object_key(&obj);
        let decisions = self.history.step(&json!({"archive": {"cursor": item["cursor"], "akid": akid, "group": gid, "seq": seq, "id": key_id,
            "object": obj["object"]}}));
        let sender = s_of(&record["sender"]);
        if decisions.iter().any(|d| d.get("show").is_some()) && self.shown.insert(key_id.clone()) {
            self.messages.push(json!({"group": gid, "key": key_id, "sender": sender, "sender_device": record["sender_device"], "object": obj,
                "seq": seq, "mine": sender == self.keys.identity, "item": null, "from_archive": true}));
            self.restored.push(json!({"seq": seq, "object": obj, "conversation": obj["conversation"]}));
            out.push(json!({"ui": "history", "group": gid, "seq": seq, "from": sender, "kind": obj["kind"], "text": obj["text"]}));
        } else if decisions.iter().any(|d| d.get("apply").is_some()) {
            if obj["object"] == "call-event" {
                // spec-gap 63: an archived call event goes to the call log, not the timeline's content
                if self.record_call(&obj) {
                    out.push(json!({"ui": "call_event", "session": obj["session"], "peer": obj["peer"], "outcome": obj["outcome"], "from_archive": true}));
                }
            } else {
                self.restored.push(json!({"seq": seq, "object": obj, "conversation": obj["conversation"]}));
                out.push(json!({"ui": "history_receipt", "group": gid, "seq": seq, "from": sender, "kind": obj["kind"]}));
            }
        }
        out.extend(self.apply_restored(now));
        out
    }

    /// Restored content and receipts are applied to their conversation's receipt state as history once this device
    /// is in that conversation (spec-gap 64); the rest wait.
    fn apply_restored(&mut self, now: i64) -> Vec<Value> {
        let mut by_group: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        let mut waiting = vec![];
        for r in std::mem::take(&mut self.restored) {
            let conversation = r["conversation"].clone();
            let target = self.convs.iter().filter(|(_, c)| json!(c.conversation) == conversation)
                .min_by_key(|(_, c)| c.kind == "personal").map(|(g, _)| g.clone());
            match target {
                Some(g) => by_group.entry(g).or_default().push(r),
                None => waiting.push(r),
            }
        }
        self.restored = waiting;
        let mut out = vec![];
        for (g, items) in by_group {
            let Some(c) = self.convs.get_mut(&g) else { continue };
            c.receipts.step(&json!({"advance": (now - c.receipts.now()).max(0)}));
            let n = items.len();
            let _ = c.receipts.step(&json!({"restore": {"items": items}}));
            out.push(json!({"ui": "history_applied", "group": g, "items": n}));
        }
        out
    }

    /// A signed introduction or grant delivered through the mailbox (M§14.1, spec-gap 54), verified as a credential.
    fn first_contact_in(&mut self, item: &Value, now: i64) -> Vec<Value> {
        let class = s_of(&item["class"]);
        let ctx = self.ctx(now);
        let mut parts = item["envelope"].as_str().unwrap_or("").split('.');
        let mut next = || parts.next().unwrap_or("").to_string();
        let env = Envelope { protected: next(), payload: next(), signature: next() };
        let checked = envelope::verify_raw(&env, &ctx, false).ok().filter(|ver| {
            let from = ver.payload["from"].as_str().unwrap_or("");
            ver.payload["type"] == class
                && ver.payload["to"] == json!(self.keys.identity)
                && ver.payload[if class == "grant" { "valid_until" } else { "expires_at" }].as_i64().unwrap_or(0) >= now
                && dsip_core::delegation::check_binding(from, &ver.signer_did, &ver.header.delegations, &ctx).ok()
        });
        let Some(ver) = checked else {
            return vec![json!({"ui": "dropped", "why": format!("{class} {}: does not verify", item["cursor"])})];
        };
        let p = ver.payload;
        let from = s_of(&p["from"]);
        if class == "introduction" {
            // sealed purposes (M§6.9) open with the identity's key agreement key, derived from the identity key (spec-gap 55)
            let purpose = match (p.get("sealed"), self.controller_seed) {
                (Some(_), Some(seed)) => {
                    let opened = dsip_messaging::first_contact::open_sealed_introduction(&p, &seed);
                    if opened["verdict"] != "accept" {
                        return vec![json!({"ui": "dropped", "why": format!("introduction {}: {}", p["id"], opened["code"])})];
                    }
                    s_of(&opened["purpose"])
                }
                (Some(_), None) => "(sealed: this device holds no key agreement key)".to_string(),
                (None, _) => s_of(&p["purpose"]),
            };
            let id = s_of(&p["id"]);
            self.requests.insert(id.clone(), json!({"from": from, "purpose": purpose, "sealed": p.get("sealed").is_some(), "expires_at": p["expires_at"]}));
            vec![json!({"ui": "request", "id": id, "from": from, "purpose": purpose})]
        } else {
            let scope = p["scope"].clone();
            if !scope.as_array().is_some_and(|s| s.iter().any(|x| x == "dsip.message")) {
                return vec![json!({"ui": "dropped", "why": format!("grant {} from {from}: no dsip.message scope", p["id"])})];
            }
            self.grants_held.insert(from.clone(), compact(&env));
            vec![json!({"ui": "granted", "by": from, "scope": scope, "request": p["session"]})]
        }
    }
}

impl Conv {
    fn pending_batch_push(&mut self, v: Value) {
        self.batch_store().push(v);
    }

    fn take_batch(&mut self) -> Vec<Value> {
        std::mem::take(self.batch_store())
    }

    fn batch_store(&mut self) -> &mut Vec<Value> {
        // the batch lives beside the receipts machine: content of the sync batch being processed (M§10.2)
        &mut self.batch
    }
}

/// Process one MLS item against a group (a welcome needs none), exactly as the console does: the welcome joined and
/// every member authenticated (M§6.2); a commit's sender, adds, removes and conversation change checked, then merged
/// (M§6.5, M§7.3, M§7.4, M§6.8/spec-gap 62 for an external join); an application message's object checked (M§8.1).
fn process(mls: &Device<BrowserProvider>, group: Option<(&mut MlsGroup, &str, &str)>, class: &str, bytes: &[u8], ctx: &Context, me: &str) -> Result<Outcome, MlsError> {
    if class == "welcome" {
        let (joined, adder) = match mls.join_from(bytes) {
            Ok(g) => g,
            Err(e) if e.0.contains("NoMatchingKeyPackage") => return Ok(Outcome::NotForDevice),
            Err(e) => return Err(e),
        };
        let members: Vec<String> = authenticate_members(&joined, ctx)?.into_iter().map(|m| m.identity).collect();
        let conv: Value = serde_json::from_slice(&conversation_extension(&joined).ok_or_else(|| MlsError("no dsip_conversation".into()))?)
            .map_err(mls_err("dsip_conversation"))?;
        let by = member_identity(&joined, adder, ctx).map(|w| w.identity).unwrap_or_default();
        return Ok(Outcome::Joined { members, group: b64(joined.group_id().as_slice()), conv, epoch: joined.epoch().as_u64(), by });
    }
    let Some((group, conversation, kind)) = group else { return Ok(Outcome::Nothing) };
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_err("mls bytes"))?;
    let pm = msg.try_into_protocol_message().map_err(mls_err("protocol message"))?;
    let processed = group.process_message(mls.provider(), pm).map_err(mls_err("undecryptable"))?;
    let who = match processed.sender() {
        Sender::Member(idx) => member_identity(group, *idx, ctx).ok(),
        _ => None,
    };
    let lapsed_leaf = match processed.sender() {
        Sender::Member(idx) if who.is_none() => Some(
            group.public_group().leaf(*idx).and_then(|l| BasicCredential::try_from(l.credential().clone()).ok())
                .map(|b| String::from_utf8_lossy(b.identity()).into_owned()).unwrap_or_default(),
        ),
        _ => None,
    };
    let external = matches!(processed.sender(), Sender::NewMemberCommit);
    let from_recorder = who.as_ref().is_some_and(|w| w.is_recorder());
    let (mut sender, sender_device) = who.map(|w| (w.identity, w.device)).unwrap_or_default();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let obj: Value = serde_json::from_slice(&app.into_bytes()).map_err(mls_err("content json"))?;
            if let Some(device) = lapsed_leaf {
                return Ok(Outcome::Unauthenticated(format!("{} from {device}: its delegation no longer verifies", obj["id"])));
            }
            let octx = json!({"conversation": conversation, "conversation_kind": kind, "leaf_identity": sender, "leaf_device": sender_device});
            let verdict = check_object(&obj, &octx);
            if verdict["verdict"] != "accept" {
                return Ok(Outcome::Dropped(format!("{} {}", verdict["code"], obj["id"])));
            }
            if from_recorder && obj["object"] == "content" {
                // C§5: content from a recorder leaf is treated as from an unauthenticated leaf: not rendered, not archived
                return Ok(Outcome::Unauthenticated(format!("{} from recorder {sender_device}", obj["id"])));
            }
            if verdict["effective"]["store"] == "call-record" {
                return Ok(Outcome::Object { sender, sender_device, object: obj }); // C§9: kept, never rendered
            }
            if verdict["effective"]["render"] == "ignore" {
                return Ok(Outcome::Nothing);
            }
            Ok(Outcome::Object { sender, sender_device, object: obj })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let mut joined_externally = vec![];
            if external {
                let described = match external_commit(group, &staged, ctx) {
                    Ok(d) => d,
                    Err(e) => return Ok(Outcome::Dropped(format!("external commit: {e}"))),
                };
                let mut roster: Vec<String> = group.members().filter_map(|m| member_identity(group, m.index, ctx).ok()).map(|w| w.identity).collect();
                roster.sort();
                roster.dedup();
                let mut inp = described.clone();
                inp["kind"] = json!(kind);
                inp["owner"] = json!(if kind == "personal" { me } else { "" });
                inp["roster"] = json!(roster);
                let v = dsip_messaging::checks::check_external_join(&inp);
                if v["verdict"] != "accept" {
                    return Ok(Outcome::Dropped(format!("external join refused: {}", v["code"])));
                }
                sender = s_of(&described["joiner"]["identity"]);
                joined_externally.push(format!("{}#{}", sender, described["joiner"]["device"].as_str().unwrap_or("")));
            }
            let rc = dsip_messaging::checks::check_roster_change(&dsip_mls::roster_change(group, &staged, ctx, &sender));
            if rc["verdict"] != "accept" {
                // M§7.3 (spec-gap 126): every member enforces the roster rules itself; a commit failing them is not merged
                return Ok(Outcome::Dropped(format!("commit refused: {}", rc["code"])));
            }
            let added: Vec<String> = joined_externally.into_iter().chain(staged.add_proposals()
                .filter_map(|a| dsip_mls::authenticate_leaf_node(a.add_proposal().key_package().leaf_node(), ctx).ok())
                .map(|w| format!("{}#{}", w.identity, w.device))).collect();
            let removed_leaves: Vec<LeafNodeIndex> = staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
            let left = left_identities(group, &staged, ctx);
            let removed: Vec<String> = removed_leaves.iter().map(|i| match member_identity(group, *i, ctx) {
                Ok(w) => format!("{}#{}", w.identity, w.device),
                Err(_) => format!("unverified#{}", group.public_group().leaf(*i).and_then(|l| BasicCredential::try_from(l.credential().clone()).ok())
                    .map(|b| String::from_utf8_lossy(b.identity()).into_owned()).unwrap_or_default()),
            }).collect();
            let remaining: Vec<String> = group.members().filter(|m| !removed_leaves.contains(&m.index))
                .filter_map(|m| member_identity(group, m.index, ctx).ok()).map(|w| w.identity).collect();
            let before = conversation_extension(group);
            let mut hub = None;
            if let Some(update) = conversation_update(before.as_deref(), &staged) {
                if update["verdict"] != "accept" {
                    return Ok(Outcome::Dropped(format!("commit {} dsip_conversation", update["code"])));
                }
                hub = Some(update["effective"]["hub"].clone());
            }
            group.merge_staged_commit(mls.provider(), *staged).map_err(mls_err("merge commit"))?;
            if !group.is_active() {
                return Ok(Outcome::Removed { by: sender, remaining });
            }
            Ok(Outcome::Epoch { epoch: group.epoch().as_u64(), by: sender, added, removed, left, hub })
        }
        ProcessedMessageContent::ProposalMessage(qp) => {
            // M§7.3 "Leaving" (spec-gap 125): stored for the commit that covers it; the decision is the caller's
            group.store_pending_proposal(mls.provider().storage(), *qp).map_err(mls_err("store proposal"))?;
            let leaf = |idx: LeafNodeIndex| member_identity(group, idx, ctx).ok().map(|w| json!({"identity": w.identity, "device": w.device}));
            let (mut removes, mut others) = (vec![], 0);
            for q in group.pending_proposals() {
                let by = match q.sender() {
                    Sender::Member(i) => member_identity(group, *i, ctx).ok().map(|w| w.identity),
                    _ => None,
                };
                if sender.is_empty() || by.as_deref() != Some(sender.as_str()) {
                    continue;
                }
                match q.proposal() {
                    Proposal::Remove(r) => removes.push(leaf(r.removed()).unwrap_or(json!({"identity": "", "device": ""}))),
                    _ => others += 1,
                }
            }
            let roster: Vec<Value> = group.members().filter_map(|m| leaf(m.index)).collect();
            Ok(Outcome::Proposal { proposer: json!({"identity": sender, "device": sender_device}), removes, others, roster })
        }
        _ => Ok(Outcome::Nothing),
    }
}

/// The identities a staged commit removes by their own Remove proposals: a leave (M§7.3 "Leaving"), told apart from a
/// removal by another member when the roster change is rendered.
fn left_identities(group: &MlsGroup, staged: &StagedCommit, ctx: &Context) -> Vec<String> {
    let mut out: Vec<String> = staged.remove_proposals().filter_map(|q| {
        let removed = member_identity(group, q.remove_proposal().removed(), ctx).ok()?.identity;
        let Sender::Member(by) = q.sender() else { return None };
        (member_identity(group, *by, ctx).ok()?.identity == removed).then_some(removed)
    }).collect();
    out.sort();
    out.dedup();
    out
}

/// Seconds after which a deposit with no answer at all counts as the hub unreachable (M§9.4). Impl (spec-gap 72):
/// the device's own answer timeout.
const NO_ANSWER_S: i64 = 60;

/// Whether a refusal of a deposit to the hub is an outage (M§9.4): unreachable, or unable to store (spec-gap 99).
fn is_outage(reason: &str) -> bool {
    matches!(reason, "mailbox.hub-unreachable" | "mailbox.quota-exceeded")
}

/// The key an object is shown and archived under (M§8.5): `conversation:id`, or `call:session` for a call event,
/// which has no `id` (M§13.3).
fn object_key(obj: &Value) -> String {
    if obj["object"] == "call-event" {
        return format!("call:{}", obj["session"].as_str().unwrap_or(""));
    }
    format!("{}:{}", obj["conversation"].as_str().unwrap_or(""), obj["id"].as_str().unwrap_or(""))
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
