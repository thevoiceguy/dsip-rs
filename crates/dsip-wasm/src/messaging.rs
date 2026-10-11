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
//! M§14.2 (a grant presented to the peer's mailbox).
//!
//! Impl: MLS state lives in OpenMLS's memory storage and is exported with the delivery state in one `save()`, which
//! the host writes as one record after each step — the atomic commit of spec-gap 44 in a browser. A reload restores
//! both. Pending deposits (not yet `accepted`) are kept with their bytes and re-deposited on the next bind (M§9.3:
//! idempotent at the hub by digest). What this device does not do yet: archive records and history for a second
//! device (M§12.2–M§12.3), read receipts, voice and blobs, successor groups; and a seq gap that does not fill is
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
use dsip_messaging::client::{registration_on_removal, Client, CommitRetry, GapTracker, Resume};
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
    /// authorize the add (M§14.2).
    Add { peer: String, kps: Vec<Vec<u8>>, grants: Vec<String> },
}

/// A deposit awaiting the hub's answer, by deposit id (M§9.2).
#[derive(Clone)]
enum Pending {
    /// A commit staged in the group: merged on `accepted`, discarded on refusal (M§6.5).
    Commit { gid: String, op: Option<Op> },
    /// A GroupInfo for the hub (M§6.5 rule 6); `then` is proposed once it is accepted.
    GroupInfo { gid: String, then: Option<Op> },
    /// An application message of this device's own, in the outbox until accepted (M§9.2).
    Application { gid: String, item: String },
    /// The archive key is sent to the personal group once its GroupInfo is accepted (M§7.1).
    PersonalReady { gid: String },
    /// A KeyPackage upload (M§5.5).
    KeyPackages { count: usize },
    /// A `mailbox-config` (M§6.6).
    Config,
}

/// What processing one inbound item produced.
enum Outcome {
    Joined { members: Vec<String>, group: String, conv: Value, epoch: u64 },
    NotForDevice,
    Object { sender: String, sender_device: String, object: Value },
    Dropped(String),
    Unauthenticated(String),
    Epoch { epoch: u64, by: String, added: Vec<String>, removed: Vec<String>, hub: Option<Value> },
    Removed { by: String, remaining: Vec<String> },
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
    /// Seq gaps per group (M§6.5, spec-gap 69), and the items held behind them.
    gaps: BTreeMap<String, GapTracker>,
    held_items: BTreeMap<String, Vec<Value>>,
    /// Membership changes refused by the hub and waiting for a sync before re-proposal (spec-gap 58).
    retries: BTreeMap<String, (CommitRetry, Op)>,
    /// Introductions delivered through the mailbox, by id (M§14.1: requests, never messages).
    requests: BTreeMap<String, Value>,
    want_live: bool,
    gap_timeout: i64,
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
            pending: BTreeMap::new(),
            outbox: serde_json::from_value(st["outbox"].clone()).unwrap_or_default(),
            messages: st["messages"].as_array().cloned().unwrap_or_default(),
            shown: st["messages"].as_array().into_iter().flatten().map(|m| s_of(&m["key"])).collect(),
            grants_held: serde_json::from_value(st["grants_held"].clone()).unwrap_or_default(),
            archive_keys: st["archive_keys"].as_object().into_iter().flatten()
                .map(|(a, v)| (a.clone(), (unb64(&v["key"]), v["created_at"].as_i64().unwrap_or(0)))).collect(),
            group_info: serde_json::from_value(st["group_info"].clone()).unwrap_or_default(),
            gaps: BTreeMap::new(),
            held_items: serde_json::from_value(st["held_items"].clone()).unwrap_or_default(),
            retries: BTreeMap::new(),
            requests: serde_json::from_value(st["requests"].clone()).unwrap_or_default(),
            want_live: false,
            gap_timeout: 60,
        };
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
            "held_items": self.held_items, "requests": self.requests,
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
        for (gid, items) in self.outbox.clone() {
            for it in items {
                frames.push(self.deposit_item(&gid, &it, now as i64));
            }
        }
        frames.push(self.sync_frame(true, now));
        json!(frames).to_string()
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
    pub fn fetch_frame(&mut self, to_mailbox: &str, target: &str, now: f64) -> String {
        let mut fields = json!({"target": target});
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
        let op = Op::Add { peer: target.to_string(), kps, grants };
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid, then: Some(op) });
        }
        Ok(json!(frames).to_string())
    }

    /// A text message to a conversation (M§8.1 `content`, kind `text`): the deposit to send, pending until the hub's
    /// `accepted` (M§9.2).
    pub fn send_text(&mut self, gid: &str, text: &str, now: f64) -> Result<String, JsValue> {
        let now_i = now as i64;
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        let obj = json!({"object": "content", "id": self.fresh_id(now_i), "conversation": conversation, "sender": self.keys.identity,
            "sent_at": now_i, "kind": "text", "purpose": "message", "content_type": "text/plain", "text": text});
        self.send_object(gid, &obj, now_i)
    }

    /// Conversations: `[{group, conversation, kind, peer, members, epoch, hub, pending}]`; members are the leaves
    /// that authenticate at `now` (M§6.2).
    pub fn conversations(&self, now: f64) -> String {
        let ctx = Context::new(now as i64, &self.resolver);
        let list: Vec<Value> = self.convs.iter().map(|(g, c)| {
            let mut members: Vec<String> = c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).map(|w| w.identity).collect();
            members.sort();
            members.dedup();
            json!({"group": g, "conversation": c.conversation, "kind": c.kind, "peer": c.peer, "members": members, "epoch": c.group.epoch().as_u64(),
                   "hub": {"did": c.hub.0, "uri": c.hub.1}, "pending": self.outbox.get(g).map_or(0, Vec::len)})
        }).collect();
        json!(list).to_string()
    }

    /// The thread of one group, in arrival order: `[{key, sender, sender_device, object, seq, mine, delivered}]`.
    pub fn thread(&self, gid: &str) -> String {
        let delivered = self.convs.get(gid).map(|c| c.receipts.snapshot()["delivered"].clone()).unwrap_or(Value::Null);
        let list: Vec<Value> = self.messages.iter().filter(|m| m["group"] == gid).map(|m| {
            let mut m = m.clone();
            m["delivered"] = delivered[s_of(&m["object"]["id"])].clone();
            m
        }).collect();
        json!(list).to_string()
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
                if p["next"].is_string() {
                    out.push(json!({"send": self.sync_frame(false, now)}));
                } else {
                    // caught up: membership changes refused for a conflict are re-proposed while still needed
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
        Client::new(&json!({"now": now, "me": self.keys.identity, "member_identities": 2, "policy": {"delivered": true}}))
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
        let conversation = self.fresh_id(now);
        let group_id = self.fresh_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": kind, "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": null});
        let group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv).map_err(js)?).map_err(|e| js(e.0))?;
        let gid = b64(group.group_id().as_slice());
        let epoch = group.epoch().as_u64();
        self.convs.insert(gid.clone(), Conv {
            group, conversation, kind: kind.to_string(), hub: (self.mailbox.0.clone(), self.mailbox.1.clone()), peer: None,
            receipts: self.new_receipts(now), joined_epoch: epoch, batch: vec![],
        });
        let config = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
            json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "joined", "hub": self.mailbox.0}]}));
        self.pending.insert(wire::payload_of(&config).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Config);
        let gi = self.group_info_frame(&gid, now)?;
        Ok((gid, vec![config.frame(), gi]))
    }

    /// The GroupInfo deposit for the hub (M§6.5 rule 6).
    fn group_info_frame(&mut self, gid: &str, now: i64) -> Result<String, JsValue> {
        let c = self.convs.get(gid).ok_or_else(|| JsValue::from_str("group"))?;
        let gi = c.group.export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true).map_err(|e| js(format!("{e:?}")))?;
        let bytes = gi.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?;
        Ok(self.hub_deposit(gid, "group-info", json!({"mls": b64(&bytes)}), now))
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
        let c = self.convs.get_mut(gid).ok_or_else(|| JsValue::from_str("group"))?;
        let Op::Add { kps, grants, .. } = op;
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
        let frame = self.hub_deposit(gid, "handshake", fields, now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()) });
        Ok(frame)
    }

    /// Encrypt an application object and deposit it; pending until accepted (M§9.2).
    fn send_object(&mut self, gid: &str, obj: &Value, now: i64) -> Result<String, JsValue> {
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let c = self.convs.get_mut(gid).ok_or_else(|| JsValue::from_str("not a member of that group"))?;
        let bytes = c.group.create_message(provider, &signer, &serde_json::to_vec(obj).map_err(js)?)
            .map_err(|e| js(format!("{e:?}")))?.tls_serialize_detached().map_err(|e| js(format!("{e:?}")))?;
        let item = json!({"id": self.fresh_id(now), "mls": b64(&bytes), "obj": obj});
        self.outbox.entry(gid.to_string()).or_default().push(item.clone());
        if obj["object"] == "content" {
            // shown at once as ours; its seq is filled in by the hub's accepted (M§8.5)
            let key = format!("{}:{}", obj["conversation"].as_str().unwrap_or(""), obj["id"].as_str().unwrap_or(""));
            self.shown.insert(key.clone());
            self.messages.push(json!({"group": gid, "key": key, "sender": self.keys.identity, "sender_device": self.keys.device.did(),
                "object": obj, "seq": null, "mine": true, "item": item["id"]}));
        }
        Ok(self.deposit_item(gid, &item, now))
    }

    /// The deposit of a pending item, under a fresh envelope but the same item id and bytes (M§9.3).
    fn deposit_item(&mut self, gid: &str, item: &Value, now: i64) -> String {
        let frame = self.hub_deposit(gid, "application", json!({"mls": item["mls"]}), now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Application { gid: gid.to_string(), item: s_of(&item["id"]) });
        frame
    }

    /// The hub or mailbox accepted a deposit of ours (M§5.3).
    fn accepted(&mut self, p: &Value, now: i64) -> Vec<Value> {
        let mut out = vec![];
        let Some(pending) = self.pending.remove(&s_of(&p["in_reply_to"])) else { return out };
        match pending {
            Pending::Commit { gid, op } => {
                if let Some(c) = self.convs.get_mut(&gid) {
                    if let Err(e) = c.group.merge_pending_commit(self.mls.provider()) {
                        out.push(json!({"error": format!("merge commit: {e:?}")}));
                        return out;
                    }
                    let epoch = c.group.epoch().as_u64();
                    out.push(json!({"ui": "committed", "group": gid, "epoch": epoch, "seq": p["seq"],
                        "added": op.as_ref().map(|Op::Add { peer, .. }| peer.clone())}));
                }
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                self.retries.remove(&gid);
                match self.group_info_frame(&gid, now) {
                    Ok(f) => {
                        let id = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                        self.pending.insert(id, Pending::GroupInfo { gid, then: None });
                        out.push(json!({"send": f}));
                    }
                    Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
                }
            }
            Pending::GroupInfo { gid, then } => {
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
                if let (Some(obj), Some(seq), Some(c)) = (obj.filter(|o| o["object"] == "content"), p["seq"].as_i64(), self.convs.get_mut(&gid)) {
                    // M§10.2: our own content enters the receipts machine at its hub seq, so receipts for it are booked
                    c.receipts.step(&json!({"advance": (now - c.receipts.now()).max(0)}));
                    c.receipts.step(&json!({"sync": {"items": [{"seq": seq, "object": obj}]}}));
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
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { count } => out.push(json!({"ui": "key_packages_uploaded", "count": count})),
            Pending::Config => {}
        }
        out
    }

    /// The hub or mailbox refused a deposit of ours (M§16): a commit as `CommitRetry` decides (spec-gap 58).
    fn refused(&mut self, p: &Value, _now: i64) -> Vec<Value> {
        let mut out = vec![];
        let reason = s_of(&p["reason"]);
        let Some(pending) = self.pending.remove(&s_of(&p["in_reply_to"])) else {
            out.push(json!({"error": format!("{reason} {}", p["detail"])}));
            return out;
        };
        match pending {
            Pending::Commit { gid, op } => {
                let mut retry = self.retries.remove(&gid).map(|(r, _)| r).unwrap_or_else(|| CommitRetry::new(&json!({})));
                for action in retry.answer(Some(&reason)) {
                    if action.get("discard").is_some() {
                        if let Some(c) = self.convs.get_mut(&gid) {
                            let _ = c.group.clear_pending_commit(self.mls.provider().storage());
                        }
                    } else if let Some(r) = action.get("surface") {
                        out.push(json!({"refused": format!("commit in {gid}: {}", r.as_str().unwrap_or(""))}));
                    } else if action.get("sync").is_some() {
                        out.push(json!({"ui": "conflict", "group": gid, "reason": reason}));
                        if let Some(op) = op.clone() {
                            self.retries.insert(gid.clone(), (retry.clone(), op));
                        }
                        out.push(json!({"sync": true}));
                    }
                }
            }
            Pending::GroupInfo { gid, .. } => out.push(json!({"refused": format!("group-info for {gid}: {reason}")})),
            Pending::Application { gid, item } => {
                if reason != "mailbox.hub-unreachable" {
                    // M§9.4: unreachable keeps it pending; any other refusal is final
                    if let Some(items) = self.outbox.get_mut(&gid) {
                        items.retain(|i| i["id"] != item);
                    }
                    self.messages.retain(|m| m["item"] != item);
                }
                out.push(json!({"refused": format!("message {item}: {reason}"), "group": gid, "item": item, "pending": reason == "mailbox.hub-unreachable"}));
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { .. } => out.push(json!({"refused": format!("key packages: {reason}")})),
            Pending::Config => out.push(json!({"refused": format!("mailbox-config: {reason}")})),
        }
        out
    }

    /// After a sync caught up: re-propose membership changes that lost a conflict and are still needed (M§6.5).
    fn after_sync(&mut self, now: i64) -> Vec<Value> {
        let mut out = vec![];
        for gid in self.retries.keys().cloned().collect::<Vec<_>>() {
            let (mut retry, op) = self.retries.remove(&gid).expect("present");
            let Op::Add { peer, .. } = &op;
            let ctx = self.ctx(now);
            let needed = self.convs.get(&gid).is_some_and(|c| !c.group.members().any(|m| member_identity(&c.group, m.index, &ctx).ok().is_some_and(|w| &w.identity == peer)));
            for action in retry.synced(needed, false) {
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
        out
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
        let outcome = {
            let ctx = Context::new(now, &self.resolver);
            let me = self.keys.identity.clone();
            let target = self.convs.get_mut(&gid).filter(|_| class != "welcome").map(|c| (&mut c.group, c.conversation.as_str(), c.kind.as_str()));
            process(&self.mls, target, &class, &bytes, &ctx, &me)?
        };
        // committed: the delivery state records the item with its MLS effect (the host saves both together)
        self.resume.commit(item, matches!(outcome, Outcome::NotForDevice));
        match outcome {
            Outcome::Joined { members, group, conv, epoch } => {
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
                // M§6.6: confirm the pending registration
                let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
                    json!({"subject": self.keys.identity, "groups": [{"group": group, "state": "joined"}]}));
                self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Config);
                out.push(json!({"send": env.frame()}));
                out.push(json!({"ui": "joined", "group": group, "conversation": conv["conversation"], "kind": kind, "members": members, "epoch": epoch}));
            }
            Outcome::Object { sender, sender_device, object } => out.extend(self.object_in(&gid, item, &sender, &sender_device, object, now)),
            Outcome::Dropped(why) => out.push(json!({"ui": "dropped", "why": why})),
            Outcome::Unauthenticated(what) => out.push(json!({"ui": "unauthenticated", "what": what})),
            Outcome::NotForDevice => out.push(json!({"ui": "sibling_welcome", "cursor": item["cursor"]})),
            Outcome::Epoch { epoch, by, added, removed, hub } => {
                if let (Some(h), Some(c)) = (hub, self.convs.get_mut(&gid)) {
                    c.hub = (s_of(&h["did"]), s_of(&h["uri"]));
                }
                out.push(json!({"ui": "epoch", "group": gid, "epoch": epoch, "by": by, "added": added, "removed": removed}));
            }
            Outcome::Removed { by, remaining } => {
                let c = self.convs.remove(&gid);
                if self.personal.as_deref() == Some(gid.as_str()) {
                    self.personal = None;
                }
                out.push(json!({"ui": "removed", "group": gid, "by": by, "conversation": c.map(|c| c.conversation)}));
                let decision = registration_on_removal(&json!({"me": self.keys.identity, "remaining_identities": remaining}));
                if decision["left"] == json!(true) {
                    let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
                        json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "left"}]}));
                    self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Config);
                    out.push(json!({"send": env.frame()}));
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
                self.archive_keys.entry(akid.clone()).or_insert((unb64(&object["key"]), object["created_at"].as_i64().unwrap_or(0)));
                out.push(json!({"ui": "archive_key", "akid": akid, "from": sender}));
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
                self.messages.push(json!({"group": gid, "key": key, "sender": sender, "sender_device": sender_device, "object": object,
                    "seq": seq, "mine": false, "item": null}));
                if let Some(c) = self.convs.get_mut(gid) {
                    c.pending_batch_push(json!({"seq": seq, "object": object}));
                }
                out.push(json!({"ui": "message", "group": gid, "from": sender, "seq": seq, "kind": object["kind"], "text": object["text"], "sent_at": object["sent_at"]}));
            }
            _ => {}
        }
        out
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
            for e in emissions {
                let Some(send) = e.get("send") else { continue };
                if send["to"] != "conversation" {
                    continue; // a private read watermark goes to the personal group (M§10.5): not sent by this client yet
                }
                let conversation = self.convs.get(&gid).map(|c| c.conversation.clone()).unwrap_or_default();
                let mut obj = json!({"object": "receipt", "id": self.fresh_id(now), "conversation": conversation, "sender": self.keys.identity,
                    "sent_at": now, "kind": send["receipt"]});
                for k in ["targets", "through"] {
                    if let Some(v) = send.get(k) {
                        obj[k] = v.clone();
                    }
                }
                match self.send_object(&gid, &obj, now) {
                    Ok(f) => {
                        out.push(json!({"send": f}));
                        out.push(json!({"ui": "receipt_sent", "group": gid, "kind": send["receipt"], "targets": send["targets"]}));
                    }
                    Err(e) => out.push(json!({"error": e.as_string().unwrap_or_default()})),
                }
            }
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
        let joined = match mls.join(bytes) {
            Ok(g) => g,
            Err(e) if e.0.contains("NoMatchingKeyPackage") => return Ok(Outcome::NotForDevice),
            Err(e) => return Err(e),
        };
        let members: Vec<String> = authenticate_members(&joined, ctx)?.into_iter().map(|m| m.identity).collect();
        let conv: Value = serde_json::from_slice(&conversation_extension(&joined).ok_or_else(|| MlsError("no dsip_conversation".into()))?)
            .map_err(mls_err("dsip_conversation"))?;
        return Ok(Outcome::Joined { members, group: b64(joined.group_id().as_slice()), conv, epoch: joined.epoch().as_u64() });
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
    let (mut sender, sender_device) = who.map(|w| (w.identity, w.device)).unwrap_or_default();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let obj: Value = serde_json::from_slice(&app.into_bytes()).map_err(mls_err("content json"))?;
            if let Some(device) = lapsed_leaf {
                return Ok(Outcome::Unauthenticated(format!("{} from {device}: its delegation no longer verifies", obj["id"])));
            }
            let octx = json!({"conversation": conversation, "conversation_kind": kind, "leaf_identity": sender});
            let verdict = check_object(&obj, &octx);
            if verdict["verdict"] != "accept" {
                return Ok(Outcome::Dropped(format!("{} {}", verdict["code"], obj["id"])));
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
            let added: Vec<String> = joined_externally.into_iter().chain(staged.add_proposals()
                .filter_map(|a| dsip_mls::authenticate_leaf_node(a.add_proposal().key_package().leaf_node(), ctx).ok())
                .map(|w| format!("{}#{}", w.identity, w.device))).collect();
            let removed_leaves: Vec<LeafNodeIndex> = staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
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
            Ok(Outcome::Epoch { epoch: group.epoch().as_u64(), by: sender, added, removed, hub })
        }
        _ => Ok(Outcome::Nothing),
    }
}

/// Re-issue this identity's delegation to its device with `dsip.messaging` beside the capabilities it has (M§4.3,
/// §7.4), signed by the identity key this browser holds. The identity JSON with the new delegation, or an error
/// when the identity key is not here (a device enrolled from a file holds only its own key).
pub fn redelegate(identity_json: &str, now: i64) -> Result<String, JsValue> {
    let mut id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().ok_or_else(|| JsValue::from_str("no identity key on this device"))?)?);
    let old = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
    let mut caps = dsip_core::delegation::capabilities(&old);
    if !caps.iter().any(|c| c == "dsip.messaging") {
        caps.push("dsip.messaging".into());
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
