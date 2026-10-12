//! The mailbox/hub service.
//!
//! Spec: M§4.3 (bind with `hello`, advertise mailbox capabilities), M§5 (the profile message set),
//! M§6.5–M§6.6 (hub ordering, fan-out, group registration), M§9.1 (deposit once, push to bound
//! devices), M§14.2 (first-contact authorization).
//!
//! Impl: every decision comes from `dsip_messaging::{mailbox::Mailbox, hub::Hub}` and, for commits,
//! `dsip_mls::HubView`; this binary only moves bytes and keeps the payloads the cursors name.
//! One instance serves the owner identities it is configured with (`--owner`, repeatable) and, with
//! `--serve-any N`, up to N more that enrol by binding with a verified `hello` — how a `did:key` identity with no
//! document comes to have a mailbox (spec-gap 115); it hubs the groups whose deposits name it. A member whose
//! identity has no document is reached through its DHT reachability hint's `DSIPMailbox` endpoint (M§4.2), looked
//! up on the hints nodes given with `--hints-node`. An owner
//! device's deposit for a group hubbed elsewhere is forwarded unchanged to the hub registered for that
//! group, and the hub's answer comes back on the same path (M§5.2, spec-gap 45); the hub takes the
//! acting identity of a forwarded deposit from the delegation in its header, since the connection it
//! arrived on belongs to a mailbox. Welcomes a hub fans out carry the adder's deposit as `origin`,
//! which the receiving mailbox verifies (M§14.2, spec-gap 46).
//!
//! Impl (spec-gap 59): everything but live connections is saved to `<state>/mailbox-state.json` after each change
//! and reloaded at startup — the machines' full state, the hub's public MLS views, stored payloads and KeyPackages,
//! fan-out payloads still queued, hub references, revocations and the seen-id window. A restarted hub re-sends the
//! head of every unacknowledged fan-out queue at once, and after that any head left unacknowledged is re-sent with
//! backoff; a member mailbox acknowledges a redelivery as a duplicate.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::did::StaticResolver;
use dsip_core::version::Supported;
use dsip_mailbox::store::{write_atomically, Item, Store};
use dsip_mailbox::verify::{delegated_identity, verify_frame};
use dsip_mailbox::{http, wire, HELLO_TIMEOUT_S};
use dsip_messaging::client::select_mailbox;
use dsip_messaging::hub::Hub;
use dsip_messaging::mailbox::Mailbox;
use dsip_mls::{digest, message_header, HubView};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::verify::SeenIds;
use dsip_transport::{now_s, tls};

#[derive(Parser)]
#[command(name = "dsip-mailbox", about = "DSIP mailbox and hub service (Messaging Profile 1.0)")]
struct Args {
    /// State directory: service key, TLS certificate.
    #[arg(long)]
    state: PathBuf,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    /// An identity this mailbox serves (repeatable; its DID document, or its reachability hint, names this service).
    #[arg(long = "owner")]
    owners: Vec<String>,
    /// Serve up to this many further identities that enrol by binding here with a verified `hello` (spec-gap 115):
    /// an operator's mailbox open to `did:key` identities, as the browser client's are. Unset: only `--owner`.
    #[arg(long)]
    serve_any: Option<usize>,
    /// Hints nodes (`https://host:port`, repeatable) asked for the `DSIPMailbox` hint of a member identity that has no
    /// DID document (M§4.2; DHT Hints Profile §10), when fanning out to it.
    #[arg(long = "hints-node")]
    hints_nodes: Vec<String>,
    /// TLS certificate chain (PEM) to serve under instead of the self-signed one; with `--key`.
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// The certificate's private key (PEM).
    #[arg(long)]
    key: Option<PathBuf>,
    /// DID document files (re-read when resolving, so documents may be written after startup).
    #[arg(long = "resolver-file")]
    resolver_files: Vec<PathBuf>,
    /// Trust anchor for dialling peer mailboxes.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Admit policy (M§5.7): `grant` (default) or `open`.
    #[arg(long, default_value = "grant")]
    admit: String,
    /// Introductions (and grants) allowed per sender identity and per recipient inbox within `--intro-window` (§19.4).
    #[arg(long, default_value_t = 5)]
    intro_limit: usize,
    /// Rate-limit window for introductions, seconds (§19.4).
    #[arg(long, default_value_t = 3600)]
    intro_window: i64,
    /// Introductions held per recipient inbox (§19.4, RECOMMENDED 16).
    #[arg(long, default_value_t = 16)]
    inbox_cap: usize,
    /// Largest blob accepted on the blob endpoint, bytes (M§4.3 `max_blob_bytes`).
    #[arg(long, default_value_t = 16_777_216)]
    max_blob_bytes: i64,
    /// The owner's storage quota, bytes: stored items plus blobs (M§4.3 `quota_bytes`; spec-gap 99). Deposits and
    /// uploads that would exceed it are refused `mailbox.quota-exceeded`.
    #[arg(long, default_value_t = 10_737_418_240)]
    quota_bytes: i64,
    /// How long a moved group's new hub is held off while the old hub's last items are missing, seconds
    /// (M§7.4, RECOMMENDED 300; spec-gap 71).
    #[arg(long, default_value_t = dsip_messaging::mailbox::HANDOVER_WAIT_S)]
    handover_wait: i64,
    /// Fault injection for demos: never deliver hub fan-out to this peer mailbox (a hub that dies before delivering).
    #[arg(long)]
    drop_fanout_to: Option<String>,
    /// Extra hostnames or addresses for the self-signed certificate (a mailbox dialled across hosts; same as the
    /// relay's). The first one is also the host of the advertised `blob_endpoint` (M§4.3), since a wildcard
    /// `--listen` address is not one a peer can dial.
    #[arg(long)]
    host: Vec<String>,
}

/// The advertised `blob_endpoint` (M§4.3): the listen port on the first `--host`, else on the listen address.
fn blob_endpoint(listen: &SocketAddr, host: Option<&str>) -> String {
    let port = listen.port();
    match host {
        Some(h) if h.contains(':') => format!("https://[{h}]:{port}/blobs"),
        Some(h) => format!("https://{h}:{port}/blobs"),
        None => format!("https://{listen}/blobs"),
    }
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// The saved service state, in the state directory.
const STATE_FILE: &str = "mailbox-state.json";
/// `retry_after` on a deposit refused because the state could not be saved (spec-gap 99).
const SAVE_RETRY_AFTER_S: i64 = 60;
/// How long a mailbox found through a hint is used before the hint is looked up again, seconds: a member that moves
/// publishes a newer hint (§8.3), and its deliveries must follow it soon after.
const HINT_REUSE_S: i64 = 60;
/// Seconds between checks for unacknowledged fan-out.
const RETRY_TICK_S: u64 = 2;
/// First and largest delay before re-sending a fan-out head that stays unacknowledged, seconds.
const RETRY_FIRST_S: i64 = 4;
const RETRY_MAX_S: i64 = 60;

/// What a handled message produces.
enum Out {
    /// To a bound device of the owner, if connected.
    Device(String, Envelope),
    /// To another identity's mailbox (federation, M§6.5 rule 5).
    Identity(String, Envelope),
}

/// What this service keeps for one served owner: its mailbox machine and the payloads behind its cursors.
struct Owned {
    mailbox: Mailbox,
    store: Store,
}

struct Service {
    key: KeyPair,
    /// Owners from `--owner`, in order; the first is the one a format-1 saved state belongs to.
    configured: Vec<String>,
    /// `--serve-any`: how many identities may enrol beyond the configured owners (spec-gap 115).
    serve_any: Option<usize>,
    /// Identities that enrolled by binding (spec-gap 115), in order; saved with the state.
    enrolled: Vec<String>,
    /// The served owners' state, by identity.
    owned: BTreeMap<String, Owned>,
    /// The mailbox machine that answers for recipients this service does not serve: first contact for them is
    /// accepted and dropped exactly as a held one (§19.4 anti-enumeration), rate-limited the same way.
    drop_box: Mailbox,
    /// The `Mailbox::new` context every owner starts from (the operator's limits).
    mailbox_ctx: Value,
    /// Hints nodes asked for a `DSIPMailbox` hint when an identity has no document (M§4.2).
    hints_nodes: Vec<String>,
    /// Mailboxes found through hints, by identity: `(mailbox DID, uri, expires_at)` — a hint, re-looked-up when
    /// it expires (§8.1 rule 6: never authority).
    hinted: HashMap<String, (String, String, i64)>,
    resolver_files: Vec<PathBuf>,
    ca: Option<PathBuf>,
    seen: SeenIds,
    supported: Supported,
    hubs: HashMap<String, Hub>,
    views: HashMap<String, HubView>,
    /// Items the hub has sequenced but whose fan-out is still in flight, by (group, seq).
    fanout: HashMap<(String, i64), Item>,
    /// `dsip_conversation` of each hubbed group: its kind and the hub reference welcomes carry.
    conversations: HashMap<String, Value>,
    /// Hub `{did, uri}` of each group registered for the owner, from its welcome (M§6.6): where to forward.
    hub_refs: HashMap<String, Value>,
    bound: HashMap<String, mpsc::UnboundedSender<String>>,
    /// A device's second connection while its binding is still open (a KeyPackage fetch at its own mailbox, or a
    /// reconnection whose predecessor has not closed yet): answered on itself, and promoted to the binding when the
    /// first one closes.
    standby: HashMap<String, mpsc::UnboundedSender<String>>,
    /// Connections to other identities' mailboxes, by the member identity they were resolved for.
    peers: HashMap<String, mpsc::UnboundedSender<PeerMsg>>,
    /// `delegation-revocation` records from the owner identities (spec-gap 57).
    revocations: Vec<Envelope>,
    /// Ciphertext blobs, one file per SHA-256 (M§8.4).
    blob_dir: PathBuf,
    /// `https://…/blobs` as advertised (M§4.3).
    blob_endpoint: String,
    max_blob_bytes: i64,
    /// Each owner's quota, bytes (spec-gap 99).
    quota_bytes: i64,
    /// Where [`STATE_FILE`] lives.
    state_dir: PathBuf,
    /// Unacknowledged fan-out heads by (group, member identity, class): (seq, next retry at, current delay). A welcome
    /// has its own queue (spec-gap 66), so it is tracked apart from the identity's sequenced items.
    retry: HashMap<(String, String, String), (i64, i64, i64)>,
    /// Manifest blobs of newly stored items, waiting to be replicated, with the owner they were stored for (M§8.4
    /// rule 6, spec-gap 65).
    replicate: Vec<(String, Value)>,
    /// Blobs whose replication is still to be tried again: `(owner, entry, attempts so far, next attempt at)`
    /// (spec-gap 67).
    replicate_later: Vec<(String, Value, i64, i64)>,
    /// Welcome deposits in flight, by deposit id: `(group, added identity, the commit's seq)` (spec-gap 66). A welcome
    /// carries no `seq` on the wire (M§5.2), so its acknowledgement is matched here to release the hub's queue.
    welcomes_sent: HashMap<String, (String, String, i64)>,
    /// Fault injection: peer mailbox DID whose fan-out is dropped (`--drop-fanout-to`).
    drop_fanout_to: Option<String>,
}

/// What goes out on a connection to a peer service.
enum PeerMsg {
    /// Hub fan-out we originate; its `accepted` releases the next queued item (M§6.5 rule 5).
    Fanout(Envelope),
    /// An owner device's deposit, forwarded unchanged; the answer goes back to that device (M§5.2).
    Forward(Envelope, String),
}

fn ctx_of<'a>(resolver: &'a StaticResolver, seen: &SeenIds, supported: &Supported, revocations: &[Envelope]) -> Context<'a> {
    let mut ctx = Context::new(now_s(), resolver);
    ctx.seen_ids = seen.set();
    ctx.supported = supported.clone();
    // spec-gap 57: revocations the owner sent are applied to every binding, beside those in DID documents
    ctx.revocations = revocations.to_vec();
    ctx
}

/// Sent down a bound device's channel to end its connection (spec-gap 57).
const CLOSE_SENTINEL: &str = "\u{0}close";

impl Service {
    /// Save everything that must survive a restart (spec-gap 59). A failed write is logged, not fatal: the
    /// in-memory state is still correct and the next change writes again.
    fn persist(&mut self) -> bool {
        let now = now_s();
        self.seen.sweep(now);
        let queued: HashMap<&String, std::collections::BTreeSet<i64>> = self.hubs.iter().map(|(g, h)| (g, h.queued_seqs())).collect();
        // A fan-out payload is kept while its seq is queued for some mailbox; group-info and ephemeral (-1) are the latest.
        self.fanout.retain(|(g, seq), _| *seq < 0 || queued.get(g).is_some_and(|q| q.contains(seq)));
        let compact = |e: &Envelope| format!("{}.{}.{}", e.protected, e.payload, e.signature);
        let owners: serde_json::Map<String, Value> = self.owned.iter()
            .map(|(id, o)| (id.clone(), json!({"mailbox": o.mailbox.full_state(), "store": serde_json::to_value(&o.store).unwrap_or(Value::Null)})))
            .collect();
        let state = json!({
            "format": 2,
            "service": self.key.did(),
            "owners": owners,
            "enrolled": self.enrolled,
            "drop_box": self.drop_box.full_state(),
            "hubs": self.hubs.iter().map(|(g, h)| (g.clone(), h.full_state())).collect::<serde_json::Map<_, _>>(),
            "views": self.views.iter().map(|(g, v)| (g.clone(), serde_json::from_slice(&v.save()).unwrap_or(Value::Null)))
                .collect::<serde_json::Map<_, _>>(),
            "fanout": self.fanout.iter().map(|((g, seq), it)| json!([g, seq, it])).collect::<Vec<_>>(),
            "conversations": self.conversations,
            "hub_refs": self.hub_refs,
            "revocations": self.revocations.iter().map(compact).collect::<Vec<_>>(),
            "welcomes_sent": self.welcomes_sent.iter().map(|(id, (g, i, s))| json!([id, g, i, s])).collect::<Vec<_>>(),
            "replicate_later": self.replicate_later.iter().map(|(o, e, n, at)| json!([o, e, n, at])).collect::<Vec<_>>(),
            "seen": self.seen.entries(),
        });
        let bytes = serde_json::to_vec(&state).unwrap_or_default();
        if let Err(e) = write_atomically(&self.state_dir.join(STATE_FILE), &bytes) {
            tracing::warn!("saving state failed: {e}");
            return false;
        }
        true
    }

    /// Absorb a storing step's emissions, then make the new item durable before acknowledging it.
    ///
    /// Spec: M§9 — `accepted` is where the sender stops retrying. Impl (spec-gap 99): a deposit that stored a new
    /// item is acknowledged only once the state is written. If the write fails (a full disk), the step is rolled
    /// back — machine and payload — and the deposit is refused `mailbox.quota-exceeded` with `retry_after`, so the
    /// sender keeps it pending and retries instead of losing it at the next restart.
    /// `before` is the machine as it was before the step — a clone, not a saved state: restoring a saved state is a
    /// restart and would also drop the live device bindings, so a rolled-back mailbox would stop pushing to them.
    fn commit(&mut self, owner: &str, before: Mailbox, emissions: Vec<Value>, item: Item) -> Vec<Value> {
        let stored = emissions
            .iter()
            .find_map(|e| e.get("accepted"))
            .filter(|a| a["cursor"].is_string() && a["duplicate"] != json!(true))
            .cloned();
        self.absorb(owner, &emissions, item);
        let Some(acc) = stored else { return emissions };
        if self.persist() {
            return emissions;
        }
        if let Some(o) = self.owned.get_mut(owner) {
            o.mailbox = before;
            if let Some(c) = acc["cursor"].as_str() {
                o.store.remove(c);
            }
        }
        tracing::warn!("refusing deposit {}: its state could not be saved", acc["in_reply_to"]);
        vec![json!({"error": {"to": acc["to"], "in_reply_to": acc["in_reply_to"], "reason": "mailbox.quota-exceeded",
            "retry_after": SAVE_RETRY_AFTER_S}})]
    }

    /// Reload what [`Service::persist`] saved. Returns false when there is nothing to reload.
    fn restore(&mut self) -> Result<bool> {
        let path = self.state_dir.join(STATE_FILE);
        if !path.exists() {
            return Ok(false);
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&path)?).context("reading saved state")?;
        anyhow::ensure!(v["format"] == 1 || v["format"] == 2, "unknown state format {}", v["format"]);
        if v["format"] == 1 {
            // one owner, one store: the state a single-owner mailbox saved
            let owner = s_of(&v["owner"]);
            anyhow::ensure!(self.configured.first() == Some(&owner), "saved state is for {owner}, not {:?}", self.configured.first());
            let mailbox = Mailbox::from_full_state(&v["mailbox"]).context("saved mailbox")?;
            let store: Store = serde_json::from_value(v["store"].clone()).context("saved store")?;
            self.owned.insert(owner, Owned { mailbox, store });
        } else {
            for (id, o) in v["owners"].as_object().into_iter().flatten() {
                let mailbox = Mailbox::from_full_state(&o["mailbox"]).with_context(|| format!("saved mailbox of {id}"))?;
                let store: Store = serde_json::from_value(o["store"].clone()).with_context(|| format!("saved store of {id}"))?;
                self.owned.insert(id.clone(), Owned { mailbox, store });
            }
            self.enrolled = v["enrolled"].as_array().into_iter().flatten().map(s_of).collect();
            if let Some(d) = Mailbox::from_full_state(&v["drop_box"]) {
                self.drop_box = d;
            }
        }
        // the configured quota wins over a saved one (or a state saved before quotas existed; spec-gap 99)
        for o in self.owned.values_mut() {
            o.mailbox.set_quota(Some(self.quota_bytes));
        }
        // a configured owner with no saved state starts fresh
        for id in self.configured.clone() {
            self.ensure_owner(&id);
        }
        for (g, h) in v["hubs"].as_object().into_iter().flatten() {
            self.hubs.insert(g.clone(), Hub::from_full_state(h).context("saved hub")?);
        }
        for (g, view) in v["views"].as_object().into_iter().flatten() {
            let view = HubView::load(&serde_json::to_vec(view)?).map_err(|e| anyhow::anyhow!("saved view of {g}: {e}"))?;
            self.views.insert(g.clone(), view);
        }
        for f in v["fanout"].as_array().into_iter().flatten() {
            let item: Item = serde_json::from_value(f[2].clone()).context("saved fan-out")?;
            self.fanout.insert((f[0].as_str().unwrap_or("").to_string(), f[1].as_i64().unwrap_or(-1)), item);
        }
        let map = |x: &Value| x.as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
        self.conversations = map(&v["conversations"]);
        self.hub_refs = map(&v["hub_refs"]);
        self.revocations = v["revocations"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter_map(|c| {
                let mut parts = c.split('.');
                Some(Envelope { protected: parts.next()?.into(), payload: parts.next()?.into(), signature: parts.next()?.into() })
            })
            .collect();
        for r in v["replicate_later"].as_array().into_iter().flatten() {
            if r[0].is_string() {
                self.replicate_later.push((s_of(&r[0]), r[1].clone(), r[2].as_i64().unwrap_or(1), r[3].as_i64().unwrap_or(0)));
            } else if let Some(owner) = self.configured.first().cloned() {
                self.replicate_later.push((owner, r[0].clone(), r[1].as_i64().unwrap_or(1), r[2].as_i64().unwrap_or(0)));
            }
        }
        for w in v["welcomes_sent"].as_array().into_iter().flatten() {
            self.welcomes_sent.insert(s_of(&w[0]), (s_of(&w[1]), s_of(&w[2]), w[3].as_i64().unwrap_or(0)));
        }
        self.seen = SeenIds::from_entries(serde_json::from_value(v["seen"].clone()).unwrap_or_default());
        Ok(true)
    }

    /// Re-send fan-out heads nobody has acknowledged (M§6.5 rule 5, spec-gap 59): all of them at once after a restart,
    /// then each head that stays unacknowledged, with doubling delay. Our own owner's queue is filled in-process and
    /// never waits.
    fn retry_fanout(&mut self, service: &Arc<Mutex<Service>>, restarted: bool) {
        let now = now_s();
        let heads: Vec<(String, Value)> =
            self.hubs.iter().flat_map(|(g, h)| h.resend_heads().into_iter().map(move |e| (g.clone(), e))).collect();
        let mut live = std::collections::HashSet::new();
        for (group, e) in heads {
            let (to, seq) = (e["fanout"]["to"].as_str().unwrap_or("").to_string(), e["fanout"]["seq"].as_i64().unwrap_or(-1));
            let class = e["fanout"]["class"].as_str().unwrap_or("").to_string();
            let key = (group.clone(), to.clone(), class.clone());
            live.insert(key.clone());
            let due = match self.retry.get(&key) {
                _ if restarted => Some(RETRY_FIRST_S),
                Some((s, at, delay)) if *s == seq => (now >= *at).then_some((delay * 2).min(RETRY_MAX_S)),
                _ => {
                    self.retry.insert(key.clone(), (seq, now + RETRY_FIRST_S, RETRY_FIRST_S)); // just sent: wait before retrying
                    None
                }
            };
            let Some(delay) = due else { continue };
            self.retry.insert(key, (seq, now + delay, delay));
            tracing::info!("re-sending {} seq {seq} in {group} to {to}", if class == "welcome" { "welcome" } else { "fan-out" });
            for out in self.hub_out(&group, vec![e], now) {
                match out {
                    Out::Identity(id, env) => federate(service, self, &id, env),
                    Out::Device(..) => {}
                }
            }
        }
        self.retry.retain(|k, _| live.contains(k));
    }

    /// Advance the mailbox machine's clock to `now`. It keeps its own (timers: §19.4 holds, M§6.6 pending groups, the
    /// M§7.4 handover wait), advanced before every message and on the retry tick, and catching up from the saved clock
    /// after a restart.
    fn catch_up(&mut self, now: i64) {
        for owner in self.owned.keys().cloned().collect::<Vec<_>>() {
            let behind = now - self.owned[&owner].mailbox.now();
            if behind > 0 {
                let emissions = self.owned.get_mut(&owner).expect("owner").mailbox.step(&json!({"advance": behind}));
                let outs = self.mailbox_out(&owner, emissions, now);
                self.send_local(outs);
            }
        }
        let behind = now - self.drop_box.now();
        if behind > 0 {
            self.drop_box.step(&json!({"advance": behind}));
        }
    }

    /// Whether this service serves `identity`: configured, or enrolled (spec-gap 115).
    fn serves(&self, identity: &str) -> bool {
        self.owned.contains_key(identity)
    }

    /// The owner's mailbox machine, created from the operator's context if it is served for the first time.
    fn ensure_owner(&mut self, identity: &str) -> &mut Owned {
        if !self.owned.contains_key(identity) {
            let mut ctx = self.mailbox_ctx.clone();
            ctx["now"] = json!(now_s());
            ctx["owner"] = json!(identity);
            ctx["serves"] = json!([identity]);
            self.owned.insert(identity.to_string(), Owned { mailbox: Mailbox::new(&ctx), store: Store::default() });
        }
        self.owned.get_mut(identity).expect("owner")
    }

    /// spec-gap 115: an identity this service does not serve enrols with its first owner operation (`sync`,
    /// `key-packages`, `mailbox-config`) on a verified binding — a device delegated by it with `dsip.messaging`
    /// (M§4.3) — while the operator's cap has room; a service identity (bound as itself) never does. Returns whether
    /// `identity` is served afterwards.
    fn enrol_if_room(&mut self, identity: &str, device: &str) -> bool {
        if self.serves(identity) {
            return true;
        }
        if identity == device || !self.serve_any.is_some_and(|cap| self.enrolled.len() < cap) {
            return false;
        }
        self.enrolled.push(identity.to_string());
        let o = self.ensure_owner(identity);
        let mut devices: Vec<String> = o.mailbox.devices().to_vec();
        devices.push(device.to_string());
        o.mailbox.register_devices(&devices);
        tracing::info!("enrolled {identity} (serve-any {}/{})", self.enrolled.len(), self.serve_any.unwrap_or(0));
        true
    }

    /// The mailbox machine that answers for `recipient`: its own if served, else the drop box (§19.4 anti-enumeration:
    /// an introduction for an identity not served here is accepted like a held one, then dropped).
    fn mailbox_for(&mut self, recipient: &str) -> &mut Mailbox {
        match self.owned.get_mut(recipient) {
            Some(o) => &mut o.mailbox,
            None => &mut self.drop_box,
        }
    }

    /// Send what is addressed to bound devices of our owner; nothing else arises outside a connection handler.
    fn send_local(&self, outs: Vec<Out>) {
        for out in outs {
            if let Out::Device(to, env) = out {
                if let Some(tx) = self.bound.get(&to) {
                    let _ = tx.send(env.frame());
                }
            }
        }
    }

    fn resolver(&self) -> StaticResolver {
        let mut r = StaticResolver::default();
        for f in &self.resolver_files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
            if v.get("id").is_some() {
                if let Ok(doc) = serde_json::from_value(v) {
                    r.insert(doc);
                }
            }
        }
        r
    }

    /// An item as `items` carries it, with blobs this mailbox holds named at its own blob endpoint (M§8.4 rule 6).
    fn item_value(&self, it: &Item, cursor: &str) -> Value {
        let mut v = it.to_value(cursor);
        if let Some(manifest) = v.get("blobs").cloned() {
            let stored: Vec<Value> = manifest.as_array().into_iter().flatten()
                .filter_map(|e| e["sha256"].as_str())
                .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) && self.blob_dir.join(h).exists())
                .map(|h| json!(h)).collect();
            v["blobs"] = dsip_messaging::mailbox::items_blobs(&json!({"blob_endpoint": self.blob_endpoint, "stored": stored,
                "manifest": manifest}))["blobs"].clone();
        }
        v
    }

    /// Mailbox emissions of `owner`'s machine → envelopes (M§5.3, M§5.4, M§5.5).
    fn mailbox_out(&mut self, owner: &str, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({});
                    for k in ["cursor", "duplicate", "seq"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    let env = wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra);
                    out.push(Out::Device(to, env));
                }
                "handover_expired" => {
                    // spec-gap 71: the old hub never delivered its last items; the new hub is admitted regardless and
                    // the owner's devices treat the missing seqs as a gap (M§6.5)
                    tracing::info!("handover wait expired for group {}: admitting the new hub without the old hub {}'s seqs {}",
                        body["group"], body["hub"], body["missing"]);
                }
                "error" => {
                    let mut fields = json!({"reason": body["reason"]});
                    for k in ["in_reply_to", "retry_after"] {
                        if let Some(v) = body.get(k) {
                            fields[k] = v.clone(); // §19.4: policy.rate-limited carries retry_after
                        }
                    }
                    out.push(Out::Device(to.clone(), wire::message(&self.key, "error", &to, now, wire::TTL_S, fields)));
                }
                "items" => {
                    let list: Vec<Value> = body["cursors"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c.as_str())
                        .filter_map(|c| self.owned.get(owner).and_then(|o| o.store.get(c)).map(|it| self.item_value(it, c)))
                        .collect();
                    let env = wire::items(&self.key, &to, now, body["in_reply_to"].as_str(), list, body["next"].clone());
                    out.push(Out::Device(to, env));
                }
                "push" => {
                    if let Some(c) = body["cursor"].as_str() {
                        if let Some(it) = self.owned.get(owner).and_then(|o| o.store.get(c)) {
                            let env = wire::items(&self.key, &to, now, None, vec![self.item_value(it, c)], Value::Null);
                            out.push(Out::Device(to, env));
                        }
                    }
                }
                "key_packages" => {
                    let mut packages = vec![];
                    let mut last_resort = None;
                    for (device, kind) in body["devices"].as_object().into_iter().flatten() {
                        let Some(o) = self.owned.get_mut(owner) else { continue };
                        if let Some(bytes) = o.store.take_key_package(device, kind.as_str().unwrap_or("")) {
                            if kind == "last-resort" {
                                last_resort = Some(bytes);
                            } else {
                                packages.push(json!(bytes));
                            }
                        }
                    }
                    let mut fields = json!({"in_reply_to": body["in_reply_to"], "subject": owner, "key_packages": packages});
                    if let Some(lr) = last_resort {
                        fields["last_resort"] = json!(lr);
                    }
                    out.push(Out::Device(to.clone(), wire::message(&self.key, "key-packages", &to, now, wire::TTL_S, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Hub emissions → envelopes, with fan-out routed locally or federated (M§6.5 rule 5).
    fn hub_out(&mut self, group: &str, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        let batch_seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({"group": group});
                    for k in ["seq", "duplicate"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    out.push(Out::Device(to.clone(), wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra)));
                }
                "error" => {
                    let env = wire::error(&self.key, &to, now, body["in_reply_to"].as_str(), body["reason"].as_str().unwrap_or(""), None);
                    out.push(Out::Device(to, env));
                }
                "fanout" if body["class"] == "welcome" => {
                    // M§6.5 rule 5, M§14.2: the welcome the commit carried, with the grants and the
                    // committer's own deposit as `origin`, so the new member's mailbox can verify the adder.
                    let seq = body["seq"].as_i64().or(batch_seq);
                    let Some(item) = seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) else { continue };
                    let Some(welcome) = item.welcome else { continue };
                    let mut fields = json!({"recipient": to, "mls": welcome,
                        "hub": self.conversations.get(group).map(|c| c["hub"].clone()).unwrap_or(Value::Null)});
                    if let Some(pred) = self.conversations.get(group).and_then(|c| c["successor_of"].as_str()) {
                        fields["successor_of"] = json!(pred); // M§7.5: admitted by the member mailbox without a grant
                    }
                    if let Some(g) = item.grants {
                        fields["grants"] = g;
                    }
                    if let Some(o) = item.origin {
                        fields["origin"] = json!(o);
                    }
                    if let Some(s) = seq {
                        // spec-gap 83: the adding commit's seq — where the new member starts counting the group
                        fields["seq"] = json!(s);
                    }
                    let env = wire::deposit(&self.key, "", now, group, "welcome", fields);
                    if let (Some(id), Some(seq)) = (wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)), seq) {
                        self.welcomes_sent.insert(id, (group.to_string(), to.clone(), seq));
                    }
                    out.push(Out::Identity(to, env));
                }
                "forward" if body["class"] == "ephemeral" => {
                    // M§11.2: never stored, no seq, no accepted; the envelope never outlives the originating
                    // deposit (spec-gap 49), so an expired activity is dropped here.
                    let Some(item) = self.fanout.get(&(group.to_string(), -1)).cloned() else { continue };
                    let (Some(sealed), Some(exp)) = (item.sealed, item.expires_at) else { continue };
                    if exp <= now {
                        continue;
                    }
                    let fields = json!({"recipient": to, "group": group, "class": "ephemeral", "sealed": sealed});
                    out.push(Out::Identity(to, wire::message(&self.key, "deposit", "", now, exp - now, fields)));
                }
                "fanout" | "forward" => {
                    let class = body["class"].as_str().unwrap_or("application").to_string();
                    let seq = body["seq"].as_i64();
                    let item = match seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) {
                        Some(i) => i,
                        None => match self.fanout.get(&(group.to_string(), -1)).cloned() {
                            Some(i) => i, // group-info and ephemeral: the latest deposit of that class
                            None => continue,
                        },
                    };
                    let mut fields = json!({"recipient": to, "class": class});
                    if let Some(s) = seq {
                        fields["seq"] = json!(s);
                    }
                    for (k, v) in [("mls", &item.mls), ("archive", &item.archive)] {
                        if let Some(s) = v {
                            fields[k] = json!(s);
                        }
                    }
                    if let Some(h) = &item.hub {
                        fields["hub"] = h.clone();
                    }
                    if let Some(b) = &item.blobs {
                        fields["blobs"] = b.clone();
                    }
                    out.push(Out::Identity(to, wire::deposit(&self.key, "", now, group, &class, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Ephemeral pushes (no cursor) become `items` carrying the sealed activity and its originating expiry.
    ///
    /// Spec: M§11.2. Impl (spec-gap 49): the pushed item is `{class, group, source, sealed, expires_at}`.
    fn ephemeral_pushes(&self, emissions: &[Value], dep: &Value, source: &str, now: i64) -> Vec<Out> {
        let exp = dep["expires_at"].as_i64().unwrap_or(0);
        let Some(sealed) = dep["sealed"].as_str() else { return vec![] };
        emissions
            .iter()
            .filter_map(|e| e.get("push"))
            .filter(|p| p["class"] == "ephemeral" && exp > now)
            .map(|p| {
                let to = p["to"].as_str().unwrap_or("").to_string();
                let item = json!({"class": "ephemeral", "group": dep["group"], "source": source, "sealed": sealed, "expires_at": exp});
                let env = wire::message(&self.key, "items", &to, now, exp - now, json!({"items": [item], "next": null}));
                Out::Device(to, env)
            })
            .collect()
    }

    /// Record the payload behind whatever cursor `owner`'s machine just assigned.
    fn absorb(&mut self, owner: &str, emissions: &[Value], item: Item) {
        for e in emissions {
            if let Some(c) = e.get("accepted").and_then(|a| a.get("cursor")).and_then(Value::as_str) {
                if e["accepted"]["duplicate"] != json!(true) {
                    if item.class == "application" {
                        // M§8.4 rule 6: the blobs this item references are replicated after it is stored
                        let blobs = item.blobs.as_ref().and_then(Value::as_array).into_iter().flatten().cloned();
                        self.replicate.extend(blobs.map(|b| (owner.to_string(), b)));
                    }
                    if let Some(o) = self.owned.get_mut(owner) {
                        o.store.put(c, item.clone());
                    }
                }
                return;
            }
        }
    }
}

/// Verify a hub-forwarded welcome's `origin`: the adder device's signed `handshake` deposit, with its
/// delegation (M§14.2). Returns what the mailbox machine checks: identity, group, `issued_at`.
fn origin_of(compact: &str, ctx: &Context) -> Option<Value> {
    let mut parts = compact.split('.');
    let env = Envelope {
        protected: parts.next()?.to_string(),
        payload: parts.next()?.to_string(),
        signature: parts.next()?.to_string(),
    };
    // Verified as a credential: it is presented after its own delivery, so the replay window does not apply;
    // the machine bounds its age against the hub deposit instead.
    let ver = envelope::verify_raw(&env, ctx, false).ok()?;
    let p = &ver.payload;
    if p["type"] != "deposit" || p["class"] != "handshake" {
        return None;
    }
    let identity = delegated_identity(&ver, ctx)?;
    Some(json!({"identity": identity, "group": p["group"], "issued_at": p["issued_at"]}))
}

fn grant_payload(compact: &str, ctx: &Context) -> Option<Value> {
    dsip_mailbox::verify::grant_credential(compact, ctx)
}

/// Verify the signed envelope a first-contact deposit carries, fresh at deposit time (§19.4 pipeline: signature,
/// delegation binding, introduction validity, expiry, ULID), and the profile's introduction rules (M§14.1).
/// Returns `(sender identity, recipient, expires_at)`.
fn first_contact_envelope(kind: &str, compact: &str, ctx: &Context) -> Result<(String, String, i64, Option<String>), String> {
    let mut parts = compact.split('.');
    let mut next = || parts.next().unwrap_or("").to_string();
    let env = Envelope { protected: next(), payload: next(), signature: next() };
    let ver = envelope::verify(&env, ctx, None).map_err(|v| format!("{:?}", v.code))?;
    let p = &ver.payload;
    if p["type"] != kind {
        return Err(format!("carried {} is not a {kind}", p["type"]));
    }
    if kind == "introduction" {
        let v = dsip_messaging::first_contact::check_introduction(p);
        if v["verdict"] != "accept" {
            return Err(v["code"].as_str().unwrap_or("introduction").to_string());
        }
    }
    // a grant names the introduction it answers in `session` (§19.4): what makes it solicited (spec-gap 81)
    let answers = (kind == "grant").then(|| p["session"].as_str().map(String::from)).flatten();
    Ok((ver.identity.clone(), p["to"].as_str().unwrap_or("").to_string(), p["expires_at"].as_i64().unwrap_or(0), answers))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.state)?;
    let key_path = args.state.join("service.key");
    let key = if key_path.exists() {
        let hex = std::fs::read_to_string(&key_path)?;
        let mut seed = [0u8; 32];
        for (i, c) in hex.trim().as_bytes().chunks(2).enumerate() {
            seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
        }
        KeyPair::from_seed(seed)
    } else {
        let k = KeyPair::generate();
        std::fs::write(&key_path, k.seed().iter().map(|b| format!("{b:02x}")).collect::<String>())?;
        k
    };
    std::fs::write(args.state.join("service.did"), key.did())?;
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
    hosts.extend(args.host.iter().cloned());
    let (cert, keyfile) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()), // a real certificate: browsers bind here (client stage 6)
        _ => tls::ensure_self_signed(&args.state, &hosts)?,
    };
    let acceptor = tls::acceptor(&cert, &keyfile)?;
    anyhow::ensure!(!args.owners.is_empty() || args.serve_any.is_some(), "give --owner <did> (repeatable) and/or --serve-any <n>");
    tracing::info!("mailbox {} for {} on wss://{}/dsip (ca {}){}", key.did(), args.owners.join(", "), args.listen, cert.display(),
        args.serve_any.map(|n| format!(", enrolling up to {n} more (spec-gap 115)")).unwrap_or_default());

    let mailbox_ctx = json!({"now": now_s(), "owner": "", "serves": [], "devices": [],
        "admit": args.admit, "intro_limit": args.intro_limit, "intro_window": args.intro_window, "inbox_cap": args.inbox_cap,
        "handover_wait": args.handover_wait, "quota_bytes": args.quota_bytes});
    let service = Arc::new(Mutex::new(Service {
        key,
        configured: args.owners.clone(),
        serve_any: args.serve_any,
        enrolled: vec![],
        owned: BTreeMap::new(),
        drop_box: Mailbox::new(&mailbox_ctx),
        mailbox_ctx,
        hints_nodes: args.hints_nodes.clone(),
        hinted: HashMap::new(),
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        seen: SeenIds::default(),
        supported: Supported::all_known(),
        hubs: HashMap::new(),
        views: HashMap::new(),
        fanout: HashMap::new(),
        conversations: HashMap::new(),
        hub_refs: HashMap::new(),
        bound: HashMap::new(),
        standby: HashMap::new(),
        peers: HashMap::new(),
        revocations: vec![],
        blob_dir: args.state.join("blobs"),
        blob_endpoint: blob_endpoint(&args.listen, args.host.first().map(String::as_str)),
        max_blob_bytes: args.max_blob_bytes,
        quota_bytes: args.quota_bytes,
        state_dir: args.state.clone(),
        retry: HashMap::new(),
        replicate: vec![],
        replicate_later: vec![],
        welcomes_sent: HashMap::new(),
        drop_fanout_to: args.drop_fanout_to.clone(),
    }));
    std::fs::create_dir_all(args.state.join("blobs"))?;
    // Bound before the state is reloaded: a connection waits in the backlog until the accept loop starts.
    let listener = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    {
        let mut st = service.lock().await;
        if st.restore()? {
            let items: usize = st.owned.values().map(|o| o.mailbox.snapshot()["items"].as_array().map_or(0, Vec::len)).sum();
            let devices: usize = st.owned.values().map(|o| o.mailbox.devices().len()).sum();
            tracing::info!("restored state: {} owner(s), {items} items, {} hubbed groups, {devices} registered devices",
                st.owned.len(), st.hubs.len());
        } else {
            for id in st.configured.clone() {
                st.ensure_owner(&id);
            }
        }
    }
    let retry_service = service.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(RETRY_TICK_S));
        let mut restarted = true; // the first tick runs at once: re-send whatever was queued before we stopped
        loop {
            tick.tick().await;
            let mut st = retry_service.lock().await;
            let now = now_s();
            st.catch_up(now);
            st.retry_fanout(&retry_service, restarted);
            let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut st.replicate_later).into_iter().partition(|(_, _, _, at)| *at <= now);
            st.replicate_later = waiting;
            drop(st);
            for (owner, entry, attempt, _) in due {
                let service = retry_service.clone();
                tokio::spawn(async move { replicate_blob(service, owner, entry, attempt).await });
            }
            restarted = false;
        }
    });

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = service.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    let result = match http::classify(tls).await {
                        Ok(http::First::WebSocket(stream)) => serve(stream, service).await,
                        Ok(http::First::Http(req)) => blob_request(req, service).await,
                        Err(e) => Err(e.into()),
                    };
                    if let Err(e) = result {
                        tracing::info!("{peer}: {e}");
                    }
                }
                Err(e) => tracing::info!("{peer}: TLS handshake failed: {e}"),
            }
        });
    }
}

/// One client connection: `hello`, then profile messages until it closes (M§4.3).
type Tls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// One blob request: `PUT` authorized by a `blob-put` envelope, or `GET` by hash (M§5.6, M§8.4).
async fn blob_request(mut req: http::Request<Tls>, service: Arc<Mutex<Service>>) -> Result<()> {
    let Some(sha) = req.path.strip_prefix(http::BLOB_PATH).map(String::from) else {
        return Ok(http::respond(&mut req.stream, 404, "text/plain", b"not found").await?);
    };
    let valid_name = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match req.method.as_str() {
        "GET" => {
            let (path, stored) = {
                let st = service.lock().await;
                let path = st.blob_dir.join(&sha);
                (path.clone(), valid_name && path.exists())
            };
            let verdict = dsip_messaging::mailbox::blob_get(&json!({"path_sha256": sha, "stored": if stored { vec![sha.clone()] } else { vec![] }}));
            if verdict["status"] == 200 {
                let body = std::fs::read(&path)?;
                http::respond(&mut req.stream, 200, "application/octet-stream", &body).await?;
            } else {
                http::respond(&mut req.stream, 404, "text/plain", b"not found").await?;
            }
            Ok(())
        }
        "PUT" => {
            let now = now_s();
            // The credential: the full envelope pipeline, the device's delegation, the message rules (M§5.1).
            let (authorization, mbx, stored) = {
                let mut st = service.lock().await;
                let resolver = st.resolver();
                let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
                let auth = req
                    .header("authorization")
                    .and_then(|h| h.strip_prefix("DSIP "))
                    .and_then(|compact| {
                        let mut parts = compact.trim().split('.');
                        let env = Envelope {
                            protected: parts.next()?.to_string(),
                            payload: parts.next()?.to_string(),
                            signature: parts.next()?.to_string(),
                        };
                        let ver = envelope::verify(&env, &ctx, None).ok()?;
                        if ver.msg_type() != "blob-put" || dsip_messaging::checks::check_message(&ver.payload)["verdict"] != "accept" {
                            return None;
                        }
                        let identity = delegated_identity(&ver, &ctx)?;
                        Some(json!({"identity": identity, "payload": ver.payload}))
                    });
                if let Some(a) = &auth {
                    let id = a["payload"]["id"].as_str().unwrap_or("").to_string();
                    st.seen.insert(&id, now, now);
                }
                // spec-gap 99: the quota covers stored items and the blobs on disk
                let blob_bytes: i64 = std::fs::read_dir(&st.blob_dir).into_iter().flatten().flatten()
                    .filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len() as i64).sum();
                let identity = auth.as_ref().and_then(|a| a["identity"].as_str()).unwrap_or("");
                let used = st.owned.get(identity).map_or(0, |o| o.mailbox.used_bytes());
                let mbx = json!({"did": st.key.did(), "serves": st.owned.keys().collect::<Vec<_>>(), "max_blob_bytes": st.max_blob_bytes,
                    "quota_bytes": st.quota_bytes, "used_bytes": used + blob_bytes});
                let stored = valid_name && st.blob_dir.join(&sha).exists();
                (auth.unwrap_or(Value::Null), mbx, stored)
            };
            let stored_list = if stored { vec![sha.clone()] } else { vec![] };
            // Decide everything that does not need the body first (413 before reading it).
            let declared = authorization["payload"]["size"].as_i64().unwrap_or(-1);
            let pre = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                "request": {"path_sha256": sha, "body_size": authorization["payload"]["size"], "body_sha256": authorization["payload"]["sha256"]}}));
            let verdict = if pre["status"].as_i64().is_some_and(|s| s >= 400) {
                pre
            } else {
                let content_length: i64 = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(-1);
                let body = if content_length == declared { http::read_body(&mut req, declared as usize).await? } else { vec![] };
                let body_sha = hex_sha256(&body);
                let v = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                    "request": {"path_sha256": sha, "body_size": body.len(), "body_sha256": body_sha}}));
                if v["status"] == 201 {
                    let st = service.lock().await;
                    let tmp = st.blob_dir.join(format!(".{sha}.part"));
                    std::fs::write(&tmp, &body)?;
                    std::fs::rename(&tmp, st.blob_dir.join(&sha))?;
                    tracing::info!("stored blob {sha} ({} bytes) for {}", body.len(), authorization["identity"]);
                }
                v
            };
            let st = service.lock().await;
            let to = authorization["payload"]["from"].as_str().unwrap_or("").to_string();
            let status = verdict["status"].as_u64().unwrap_or(500) as u16;
            let env = match verdict.get("accepted") {
                Some(a) => {
                    let mut extra = json!({});
                    if a.get("duplicate").is_some() {
                        extra["duplicate"] = json!(true);
                    }
                    wire::accepted(&st.key, &to, now, a["in_reply_to"].as_str().unwrap_or(""), extra)
                }
                None => {
                    tracing::info!("blob PUT {sha} refused: {status} {}", verdict["reason"]);
                    let in_reply_to = authorization["payload"]["id"].as_str();
                    wire::error(&st.key, &to, now, in_reply_to, verdict["reason"].as_str().unwrap_or("policy.blocked"), None)
                }
            };
            drop(st);
            http::respond(&mut req.stream, status, "application/json", env.frame().as_bytes()).await?;
            Ok(())
        }
        _ => Ok(http::respond(&mut req.stream, 405, "text/plain", b"method not allowed").await?),
    }
}

/// HTTPS trusting the service's `--ca`, read when used (it may be written after startup, as for peer connections).
fn https_client(ca: Option<&std::path::Path>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().use_rustls_tls().https_only(true);
    if let Some(ca) = ca {
        for cert in reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)? {
            b = b.add_root_certificate(cert);
        }
    }
    Ok(b.build()?)
}

/// Replicate one manifest blob into this mailbox, as the pinned decision says (M§8.4 rule 6, spec-gap 65).
async fn replicate_blob(service: Arc<Mutex<Service>>, owner: String, entry: Value, attempt: i64) {
    let (decision, http, path) = {
        let st = service.lock().await;
        let sha = entry["sha256"].as_str().unwrap_or("").to_string();
        let valid = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let path = st.blob_dir.join(&sha);
        let stored = if valid && path.exists() { vec![sha] } else { vec![] };
        let mode = st.owned.get(&owner).map_or("sync", |o| o.mailbox.mode()).to_string();
        let d = dsip_messaging::mailbox::blob_replicate(&json!({"mode": mode, "max_blob_bytes": st.max_blob_bytes,
            "stored": stored, "entry": entry, "attempt": attempt}));
        if !valid {
            return;
        }
        (d, https_client(st.ca.as_deref()), path)
    };
    let Ok(http) = http else { return };
    let uri = entry["uri"].as_str().unwrap_or("").to_string();
    if decision["action"] != "fetch" {
        if decision["reason"] != "stored" {
            tracing::info!("not replicating {uri}: {}", decision["reason"]);
        }
        return;
    }
    let fetched = match http.get(&uri).send().await {
        Ok(resp) if resp.status().as_u16() == 200 => match resp.bytes().await {
            Ok(body) => Some(body.to_vec()),
            Err(_) => None,
        },
        Ok(resp) => {
            tracing::info!("replicating {uri}: {}", resp.status());
            None
        }
        Err(e) => {
            tracing::info!("replicating {uri}: {e}");
            None
        }
    };
    let f = match &fetched {
        Some(body) => json!({"status": 200, "sha256": hex_sha256(body), "size": body.len()}),
        None => json!({"status": 0}),
    };
    let d = dsip_messaging::mailbox::blob_replicate(&json!({"entry": entry, "fetched": f, "attempt": attempt}));
    match (d["action"].as_str(), fetched) {
        (Some("store"), Some(body)) => {
            let tmp = path.with_extension("part");
            if std::fs::write(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &path)).is_ok() {
                tracing::info!("replicated blob {} ({} bytes) from {uri}", entry["sha256"].as_str().unwrap_or(""), body.len());
            }
        }
        _ if d["retry"] == json!(true) => {
            // spec-gap 67: the origin had nothing to serve just now; try again, with the fan-out backoff
            let delay = (RETRY_FIRST_S * (1 << (attempt - 1).min(4))).min(RETRY_MAX_S);
            let mut st = service.lock().await;
            st.replicate_later.push((owner.clone(), entry.clone(), attempt + 1, now_s() + delay));
            st.persist();
            tracing::info!("not replicating {uri}: {} (attempt {attempt}, again in {delay}s)", d["reason"]);
        }
        _ => tracing::info!("not replicating {uri}: {}", d["reason"]),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

async fn serve(tls: http::Prefixed<Tls>, service: Arc<Mutex<Service>>) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async_with_config(tls, Some(dsip_transport::conn::ws_config())).await?;
    let first = match tokio::time::timeout(std::time::Duration::from_secs(HELLO_TIMEOUT_S), ws.next()).await {
        Ok(Some(Ok(WsMessage::Text(t)))) => t.to_string(),
        _ => anyhow::bail!("no hello"),
    };
    let (device, identity, hello_env) = {
        let mut st = service.lock().await;
        let resolver = st.resolver();
        let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
        let inb = match verify_frame(&first, &ctx) {
            Ok(i) => i,
            Err(r) => {
                tracing::info!("hello rejected: {r}");
                // Answered like the service's own hello (core version block), so the client can read why (§13.2).
                let now = now_s();
                // Addressed from the rejected hello's own (unverified) fields: it is only ever sent back on this socket.
                let claimed = Envelope::from_frame(&first).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
                let mut body = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []},
                    "type": "error", "id": wire::new_id(now), "from": st.key.did(), "to": claimed["from"],
                    "reason": "transport.hello-rejected", "detail": r.code, "issued_at": now, "expires_at": now + wire::TTL_S});
                if let Some(h) = claimed["id"].as_str() {
                    body["in_reply_to"] = json!(h);
                }
                let env = envelope::sign(&body, &st.key, &st.key.kid());
                drop(st);
                let _ = ws.send(WsMessage::Text(env.frame().into())).await;
                anyhow::bail!("hello rejected: {r}");
            }
        };
        anyhow::ensure!(inb.msg_type() == "hello", "first envelope was {}", inb.msg_type());
        let (device, identity) = (inb.device().to_string(), inb.identity().to_string());
        let id = inb.payload()["id"].as_str().unwrap_or("").to_string();
        let hub = true;
        let env = wire::service_hello(&st.key, &id, now_s(), wire::mailbox_capabilities(hub, &st.blob_endpoint, st.max_blob_bytes));
        st.seen.insert(&id, now_s(), now_s());
        (device, identity, env)
    };
    ws.send(WsMessage::Text(hello_env.frame().into())).await?;
    tracing::info!("bound {device} (for {identity})");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut st = service.lock().await;
        // A device may hold a second, short-lived connection beside its binding (a KeyPackage fetch at its own mailbox):
        // that connection gets its replies on itself and changes nothing about the binding, its live push included.
        let second = st.bound.get(&device).is_some_and(|t| !t.is_closed());
        if second {
            st.standby.insert(device.clone(), tx.clone());
        } else {
            // Every binding can be pushed to (its replies, and an enrolment later on this connection); only a served
            // identity's device is registered (M§4.4).
            st.bound.insert(device.clone(), tx.clone());
            if st.serves(&identity) {
                // M§5.4: live push belongs to a connection. A new binding starts not live, whatever an earlier
                // connection of this device asked for, until it syncs live; otherwise a push could jump its cursor past
                // items stored while it was away, which it would then never sync.
                let o = st.ensure_owner(&identity);
                o.mailbox.step(&json!({"unbind": {"device": device}}));
                // The owner's registered devices are the ones that have bound (M§4.4), including before a restart.
                let mut devices: Vec<String> = o.mailbox.devices().to_vec();
                devices.push(device.clone());
                o.mailbox.register_devices(&devices);
            }
        }
        st.persist();
    }

    // The binding ends however the connection does (a clean close, a send error, a dropped socket), so the cleanup
    // below always runs.
    let result: Result<()> = async {
        loop {
            tokio::select! {
                outbound = rx.recv() => match outbound {
                    Some(frame) if frame == CLOSE_SENTINEL => {
                        // The device's delegation was revoked: end the binding now (M§12.4, spec-gap 57).
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                    None => return Ok(()),
                },
                inbound = ws.next() => match inbound {
                    Some(Ok(WsMessage::Text(t))) => {
                        let replies = handle(&service, t.to_string(), &device, &identity).await;
                        for frame in replies {
                            ws.send(WsMessage::Text(frame.into())).await?;
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                },
            }
        }
    }
    .await;
    let mut st = service.lock().await;
    if st.standby.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.standby.remove(&device); // a second connection ending changes nothing about the binding
    } else if st.bound.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.bound.remove(&device);
        if let Some(o) = st.owned.get_mut(&identity) {
            o.mailbox.step(&json!({"unbind": {"device": device}}));
        }
        tracing::info!("unbound {device}");
        // a connection that arrived while this one was still open becomes the binding: not live until it syncs (M§5.4)
        if let Some(next) = st.standby.remove(&device).filter(|t| !t.is_closed()) {
            st.bound.insert(device.clone(), next);
            tracing::info!("bound {device} again on its later connection");
        }
    }
    result
}

/// Verify one frame and run it through the state machines; returns frames for this connection.
async fn handle(service: &Arc<Mutex<Service>>, frame: String, sender: &str, bound_identity: &str) -> Vec<String> {
    let now = now_s();
    let mut st = service.lock().await;
    st.catch_up(now);
    let resolver = st.resolver();
    let inb = {
        let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
        match verify_frame(&frame, &ctx) {
            Ok(i) => i,
            Err(r) => {
                tracing::info!("refused frame from {sender}: {r}");
                let env = wire::error(&st.key, sender, now, None, r.token(), Some(&r.code));
                return vec![env.frame()];
            }
        }
    };
    st.seen.insert(inb.payload()["id"].as_str().unwrap_or(""), now, now);
    let signer = inb.device().to_string();
    let outs = dispatch(service, &mut st, &inb, &frame, sender, bound_identity, &resolver, now);
    let mut replies = vec![];
    for out in outs {
        match out {
            Out::Device(to, env) => {
                // A forwarded deposit's signer is not bound here: its answer returns on this connection (M§5.2).
                if to == sender || to == signer {
                    replies.push(env.frame());
                } else if let Some(tx) = st.bound.get(&to) {
                    let _ = tx.send(env.frame());
                }
            }
            Out::Identity(identity, env) => federate(service, &mut st, &identity, env),
        }
    }
    for (owner, entry) in std::mem::take(&mut st.replicate) {
        let service = service.clone();
        tokio::spawn(async move { replicate_blob(service, owner, entry, 1).await });
    }
    st.persist();
    replies
}

/// Route one verified message to the right state machine (M§5, M§6.5, M§6.6).
#[allow(clippy::too_many_arguments)]
fn dispatch(
    service: &Arc<Mutex<Service>>,
    st: &mut Service,
    inb: &dsip_mailbox::verify::Inbound,
    frame: &str,
    hello_device: &str,
    bound_identity: &str,
    resolver: &StaticResolver,
    now: i64,
) -> Vec<Out> {
    let p = inb.payload().clone();
    let device = inb.device().to_string();
    // §13.2: a device acts for the identity it bound as, not for the DID that signs each envelope
    // (a profile message's `from` is the device, M§5.1). A deposit forwarded by a mailbox is signed by a
    // device that did not bind here: it acts for the identity its header delegation proves (M§5.1, M§5.2).
    let identity = if device == hello_device {
        bound_identity.to_string()
    } else {
        let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
        delegated_identity(&inb.verified, &ctx).unwrap_or_else(|| device.clone())
    };
    let id = p["id"].as_str().unwrap_or("").to_string();
    match inb.msg_type() {
        "deposit" => {
            let class = p["class"].as_str().unwrap_or("");
            let group = p["group"].as_str().unwrap_or("").to_string();
            let mut item = Item::from_deposit(&p, &device, now);
            if matches!(class, "introduction" | "grant") {
                // First contact (M§14.1, spec-gap 54): a signed introduction or grant for an identity, under §19.4's rules.
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let (sender, to, expires_at, answers) = match first_contact_envelope(class, p["envelope"].as_str().unwrap_or(""), &ctx) {
                    Ok(v) => v,
                    Err(why) => {
                        tracing::info!("{class} refused: {why}");
                        return vec![Out::Device(device.clone(), wire::error(&st.key, &device, now, Some(&id), "policy.blocked", Some(&why)))];
                    }
                };
                if to != p["recipient"].as_str().unwrap_or("") {
                    return vec![Out::Device(device.clone(), wire::error(&st.key, &device, now, Some(&id), "policy.blocked", Some("recipient is not the envelope's to")))];
                }
                item.expires_at = Some(expires_at);
                let mut event = json!({"first_contact": {"id": id, "from": device, "sender_identity": sender, "recipient": to,
                    "kind": class, "expires_at": expires_at}});
                if let Some(session) = answers {
                    event["first_contact"]["session"] = json!(session);
                }
                // §19.4: the sender's budget is the service's, whoever the recipient is (an introduction for an identity
                // not served here costs the same as one held): the drop box counts every first-contact deposit and
                // refuses `policy.rate-limited` first; the recipient's own machine then holds what it accepts.
                let gate = st.drop_box.step(&event);
                let emissions = if gate.iter().any(|e| e.get("error").is_some()) || !st.serves(&to) {
                    gate
                } else {
                    st.mailbox_for(&to).step(&event)
                };
                for e in &emissions {
                    match (e.get("accepted"), e.get("error")) {
                        (Some(a), _) if a.get("cursor").is_some() => tracing::info!("held {class} from {sender} for {to}"),
                        (Some(_), _) => tracing::info!("{class} from {sender} for {to} accepted, not held"),
                        (_, Some(err)) => tracing::info!("{class} from {sender} refused: {}", err["reason"]),
                        _ => {}
                    }
                }
                st.absorb(&to, &emissions, item);
                return st.mailbox_out(&to, emissions, now);
            }
            let recipient = s_of(&p["recipient"]);
            if class == "welcome" && st.serves(&recipient) {
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let grant = p["grants"].as_array().into_iter().flatten().filter_map(Value::as_str)
                    .find_map(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
                // spec-gap 66: the welcome's own bytes tell a retried delivery from a new invitation
                let w_digest = p["mls"].as_str().and_then(dsip_core::b64::decode).map(|b| digest(&b));
                let mut w = json!({"id": id, "from": device, "adder_identity": identity,
                    "recipient": recipient, "group": group, "hub": p["hub"]["did"], "grant": grant,
                    "successor_of": p["successor_of"], "digest": w_digest, "size": item.stored_bytes()});
                // A service-signed welcome (no delegation) came from a hub: only `origin` names the adder (M§14.2).
                if device == hello_device && bound_identity == device {
                    w["via_hub"] = json!(true);
                    w["issued_at"] = p["issued_at"].clone();
                    w.as_object_mut().expect("object").remove("adder_identity");
                    if let Some(o) = p["origin"].as_str().and_then(|o| origin_of(o, &ctx)) {
                        w["origin"] = o;
                    }
                }
                let before = st.mailbox_for(&recipient).clone();
                let emissions = st.mailbox_for(&recipient).step(&json!({"welcome": w}));
                if let Some(e) = emissions.iter().find_map(|e| e.get("error")) {
                    tracing::info!("welcome for {group} refused: {} (origin {})", e["reason"], w.get("origin").is_some());
                }
                let emissions = st.commit(&recipient, before, emissions, item);
                if emissions.iter().any(|e| e.get("accepted").is_some()) {
                    st.hub_refs.insert(group.clone(), p["hub"].clone());
                }
                return st.mailbox_out(&recipient, emissions, now);
            }
            if class == "archive" {
                // The owner is the depositing device's identity; one not served here is refused by its machine.
                let owner = identity.clone();
                let event = json!({"archive": {"id": id, "device": device, "ref_group": p["ref_group"], "ref_seq": p["ref_seq"],
                    "size": item.stored_bytes()}});
                let before = st.mailbox_for(&owner).clone();
                let emissions = st.mailbox_for(&owner).step(&event);
                let emissions = st.commit(&owner, before, emissions, item);
                return st.mailbox_out(&owner, emissions, now);
            }
            if st.serves(&recipient) {
                // Fan-out from another hub for one of our owners.
                let event = json!({"hub_deposit": {"id": id, "from": identity, "recipient": recipient,
                    "group": group, "seq": p["seq"], "class": class, "expires_at": p["expires_at"], "size": item.stored_bytes()}});
                let before = st.mailbox_for(&recipient).clone();
                let emissions = st.mailbox_for(&recipient).step(&event);
                let mut out = st.ephemeral_pushes(&emissions, &p, &identity, now);
                let emissions = st.commit(&recipient, before, emissions, item);
                if let Some(a) = emissions.iter().find_map(|e| e.get("accepted")) {
                    tracing::info!("stored fan-out {class} seq {} in {group} as {}{}", p["seq"], a["cursor"],
                        if a["duplicate"] == json!(true) { " (duplicate)" } else { "" });
                }
                out.extend(st.mailbox_out(&recipient, emissions, now));
                return out;
            }
            if p["to"].as_str() != Some(st.key.did().as_str()) {
                // Addressed to another service: forward to the group's hub, or refuse (M§5.2, spec-gap 45).
                let owner = identity.clone();
                let event = json!({"forward": {"id": id, "device": device, "identity": identity, "group": group, "to": p["to"]}});
                let emissions = st.mailbox_for(&owner).step(&event);
                if emissions.iter().any(|e| e.get("forward").is_some()) {
                    let uri = st.hub_refs.get(&group).and_then(|h| h["uri"].as_str()).map(String::from);
                    let target = p["to"].as_str().unwrap_or("").to_string();
                    match (uri, Envelope::from_frame(frame)) {
                        (Some(uri), Ok(env)) => {
                            peer_send(service, st, PeerTarget::Service { did: target, uri }, PeerMsg::Forward(env, device.clone()));
                            return vec![];
                        }
                        _ => {
                            // M§9.4 (spec-gap 72): no endpoint for the hub is the same outage as a failed dial
                            let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("no endpoint known for the hub"));
                            return vec![Out::Device(device, env)];
                        }
                    }
                }
                return st.mailbox_out(&owner, emissions, now);
            }
            let mut item = item;
            if class == "handshake" {
                item.origin = Envelope::from_frame(frame).ok().map(|e| format!("{}.{}.{}", e.protected, e.payload, e.signature));
            }
            hub_deposit(st, &p, &device, &identity, item, resolver, now)
        }
        "sync" => {
            st.enrol_if_room(&identity, &device);
            let mut e = json!({"id": id, "device": device, "since": p["since"], "live": p["live"] == json!(true)});
            if let Some(a) = p.get("ack_through") {
                e["ack_through"] = a.clone();
            }
            if let Some(l) = p.get("limit") {
                e["limit"] = l.clone();
            }
            let emissions = st.mailbox_for(&identity).step(&json!({"sync": e}));
            let n = emissions.iter().find_map(|e| e["items"]["cursors"].as_array().map(Vec::len)).unwrap_or(0);
            tracing::info!("sync from {device} since {} live={}: {n} items", p["since"], p["live"] == json!(true));
            st.mailbox_out(&identity, emissions, now)
        }
        "key-packages" => {
            st.enrol_if_room(&identity, &device);
            let packages: Vec<String> = p["key_packages"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
            let count = packages.len() as i64;
            let last = p["last_resort"].as_str().map(String::from);
            if let Some(o) = st.owned.get_mut(&identity) {
                o.store.add_key_packages(&device, packages, last.clone());
            }
            let event = json!({"kp_upload": {"id": id, "device": device, "count": count, "last_resort": last.is_some()}});
            let emissions = st.mailbox_for(&identity).step(&event);
            st.mailbox_out(&identity, emissions, now)
        }
        "key-package-fetch" => {
            let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
            let grant = p["grant"].as_str().and_then(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
            tracing::info!("key-package-fetch from {identity} for {}: grant {}", p["target"],
                if p["grant"].is_null() { "none" } else if grant.is_null() { "presented, does not verify as the target's consent (M§14.2)" } else { "verified" });
            let mut event = json!({"kp_fetch": {"id": id, "from": device, "from_identity": identity,
                "target": p["target"], "grant": grant}});
            if let Some(g) = p.get("successor_of") {
                event["kp_fetch"]["successor_of"] = g.clone(); // M§7.5, spec-gap 61
            }
            let target = s_of(&p["target"]);
            let emissions = st.mailbox_for(&target).step(&event);
            st.mailbox_out(&target, emissions, now)
        }
        "mailbox-config" => {
            st.enrol_if_room(&identity, &device);
            let mut e = json!({"id": id, "device": device});
            for k in ["mode", "admit", "groups", "revoked_grants", "introductions_sent"] {
                if let Some(v) = p.get(k) {
                    e[k] = v.clone();
                }
            }
            // spec-gap 57: revocations from the owner identity, each signed directly by one of its keys
            let mut revoked_devices = vec![];
            for c in p["revoked_delegations"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let mut parts = c.split('.');
                let mut next = || parts.next().unwrap_or("").to_string();
                let rev = Envelope { protected: next(), payload: next(), signature: next() };
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let device_of = envelope::verify_raw(&rev, &ctx, false).ok().and_then(|ver| {
                    let q = &ver.payload;
                    (q["type"] == "delegation-revocation" && q["subject"] == json!(identity) && q["from"] == json!(identity)
                        && ver.signer_did == identity && st.serves(&identity))
                        .then(|| q["device"].as_str().map(String::from))
                        .flatten()
                });
                match device_of {
                    Some(d) => {
                        tracing::info!("delegation of {d} revoked by {identity}");
                        st.revocations.push(rev);
                        revoked_devices.push(d);
                    }
                    None => tracing::info!("revocation refused: not signed by {identity}"),
                }
            }
            if !revoked_devices.is_empty() {
                e["revoked_devices"] = json!(revoked_devices);
            }
            let emissions = st.mailbox_for(&identity).step(&json!({"config": e}));
            if emissions.iter().any(|x| x.get("accepted").is_some()) {
                // M§7.4 (spec-gap 60): a group moved to another hub is forwarded to that hub's endpoint from now on
                for g in p["groups"].as_array().into_iter().flatten() {
                    if let (Some(group), Some(did)) = (g["group"].as_str(), g["hub"].as_str()) {
                        if let Some(uri) = g["hub_uri"].as_str() {
                            st.hub_refs.insert(group.to_string(), json!({"did": did, "uri": uri}));
                        }
                        if g.get("handover_seq").is_some() {
                            tracing::info!("group {group} moved to hub {did} after seq {}", g["handover_seq"]);
                        }
                    }
                }
            }
            for c in emissions.iter().filter_map(|x| x.get("close")) {
                let d = c["device"].as_str().unwrap_or("");
                if let Some(tx) = st.bound.remove(d) {
                    let _ = tx.send(CLOSE_SENTINEL.to_string());
                    tracing::info!("closed the binding of revoked device {d}");
                }
            }
            st.mailbox_out(&identity, emissions, now)
        }
        other => {
            tracing::info!("no handler for {other}");
            vec![]
        }
    }
}

/// One group's hub state as it was before a deposit (M§9.3, spec-gap 99).
struct HubSnapshot {
    hub: Option<Value>,
    view: Option<Vec<u8>>,
    conversation: Option<Value>,
    /// The latest group-info / ephemeral payload (fan-out key `-1`).
    latest: Option<Item>,
}

impl HubSnapshot {
    /// Undo a deposit whose state could not be saved: the hub machine, its public view (a commit is merged into it
    /// on validation), the conversation, and the payload kept for fan-out.
    fn restore(self, st: &mut Service, group: &str, seq: Option<i64>) {
        let g = group.to_string();
        match self.hub.as_ref().and_then(Hub::from_full_state) {
            Some(h) => st.hubs.insert(g.clone(), h),
            None => st.hubs.remove(&g),
        };
        match self.view.as_deref().map(HubView::load) {
            Some(Ok(v)) => st.views.insert(g.clone(), v),
            _ => st.views.remove(&g),
        };
        match self.conversation {
            Some(c) => st.conversations.insert(g.clone(), c),
            None => st.conversations.remove(&g),
        };
        match (seq, self.latest) {
            (Some(s), _) => st.fanout.remove(&(g, s)),
            (None, Some(l)) => st.fanout.insert((g, -1), l),
            (None, None) => st.fanout.remove(&(g, -1)),
        };
    }
}

/// Hub path: bootstrap the public view from a GroupInfo, validate commits, sequence, fan out.
fn hub_deposit(
    st: &mut Service,
    p: &Value,
    device: &str,
    identity: &str,
    item: Item,
    resolver: &StaticResolver,
    now: i64,
) -> Vec<Out> {
    let group = p["group"].as_str().unwrap_or("").to_string();
    let class = p["class"].as_str().unwrap_or("").to_string();
    let id = p["id"].as_str().unwrap_or("").to_string();
    let mls = p["mls"].as_str().unwrap_or("");
    let bytes = dsip_core::b64::decode(mls).unwrap_or_default();
    let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
    // Spec: M§9.3 (spec-gap 99) — what a deposit may change here, restored if it cannot be made durable
    let before = HubSnapshot {
        hub: st.hubs.get(&group).map(Hub::full_state),
        view: st.views.get(&group).map(HubView::save),
        conversation: st.conversations.get(&group).cloned(),
        latest: st.fanout.get(&(group.clone(), -1)).cloned(),
    };

    let mut refreshed = None;
    if class == "group-info" {
        // Bootstrap or refresh the public view (M§6.5 rule 6).
        match HubView::from_group_info(&bytes) {
            Ok(view) if st.hubs.contains_key(&group) => refreshed = Some(view), // applied once the hub accepts it
            Ok(view) => {
                let conv = view.conversation().unwrap_or(Value::Null);
                if conv["hub"]["did"] != json!(st.key.did()) {
                    // Impl (spec-gap 60): a hub hosts only a group whose dsip_conversation names it
                    tracing::info!("group-info for {group} names hub {} — not hosting it", conv["hub"]["did"]);
                    let env = wire::error(&st.key, device, now, Some(&id), "mailbox.unknown-group", Some("the group names another hub"));
                    return vec![Out::Device(device.to_string(), env)];
                }
                let roster = view.roster(&ctx).unwrap_or(json!({}));
                let kind = conv["kind"].as_str().unwrap_or("direct");
                // M§7.4 (spec-gap 60): a group moved here continues the numbering its previous hub reached
                let next_seq = p["handover_seq"].as_i64().map_or(1, |h| h + 1);
                let mut ctx_hub = json!({"now": now, "kind": kind, "epoch": view.epoch(), "roster": roster, "next_seq": next_seq});
                if kind == "personal" {
                    // Impl (spec-gap 62): a personal group is hubbed at its owner's mailbox (M§7.1), so the owner — who may
                    // re-join it by external commit with no leaf left (M§6.8) — is the served identity that brought it here
                    ctx_hub["owner"] = json!(identity);
                }
                let hub = Hub::new(&ctx_hub);
                st.hubs.insert(group.clone(), hub);
                tracing::info!("hubbing {kind} group {group} from epoch {} at seq {next_seq}", view.epoch());
                st.conversations.insert(group.clone(), conv);
                st.views.insert(group.clone(), view);
            }
            Err(e) => tracing::info!("group-info refused: {e}"),
        }
    }
    let Some(_) = st.hubs.get_mut(&group) else {
        let env = wire::error(&st.key, device, now, Some(&id), "mailbox.unknown-group", None);
        return vec![Out::Device(device.to_string(), env)];
    };
    let mut deposit = json!({"id": id, "device": device, "identity": identity, "class": class, "digest": digest(&bytes)});
    if let Ok((_, epoch, _)) = message_header(&bytes) {
        deposit["epoch"] = json!(epoch);
    }
    if class == "ephemeral" {
        deposit["expires_at"] = p["expires_at"].clone();
        deposit["digest"] = json!(id);
    }
    if class == "handshake" {
        let view = st.views.get_mut(&group);
        let commit = view.map(|v| v.observe_commit(&bytes, &ctx).unwrap_or(json!({"adds": [], "removes": [], "valid": false})));
        if let Some(c) = commit {
            if c.get("adds").is_some() {
                deposit["commit"] = c;
            }
        }
    }
    let hub = st.hubs.get_mut(&group).expect("hub");
    let emissions = hub.step(&json!({"deposit": deposit}));
    if let Some(view) = refreshed.filter(|_| emissions.iter().any(|e| e.get("accepted").is_some())) {
        st.conversations.insert(group.clone(), view.conversation().unwrap_or(Value::Null));
        st.views.insert(group.clone(), view);
    }
    if let Some(c) = deposit.get("commit").filter(|c| c["moves_to"].is_string()) {
        if emissions.iter().any(|e| e.get("accepted").is_some()) {
            tracing::info!("group {group} moves to hub {}: ordered here, refused from now on", c["moves_to"]);
        }
    }
    for e in &emissions {
        if let Some(err) = e.get("error") {
            tracing::info!("hub refused {class} from {identity}: {}", err["reason"]);
        }
    }
    if let Some(seq) = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq"))) {
        tracing::info!("hub sequenced {class} seq {seq} from {identity} in {group}");
    }
    // Remember the payload so the fan-out can carry it: by seq, or as the latest of its class.
    let seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
    st.fanout.insert((group.clone(), seq.unwrap_or(-1)), item);
    // M§9.3 (spec-gap 99): a newly accepted item is durable before anyone hears of it — the depositor's `accepted`
    // and the fan-out both wait for the write. If it fails, the deposit is undone and refused, and the sender
    // retries it (M§9.3) as if the hub had been unreachable.
    let stored = emissions.iter().filter_map(|e| e.get("accepted")).any(|a| a["duplicate"] != json!(true));
    if stored && !st.persist() {
        before.restore(st, &group, seq);
        tracing::warn!("refusing {class} {id} from {identity} in {group}: its state could not be saved");
        let fields = json!({"reason": "mailbox.quota-exceeded", "in_reply_to": id, "retry_after": SAVE_RETRY_AFTER_S});
        return vec![Out::Device(device.to_string(), wire::message(&st.key, "error", device, now, wire::TTL_S, fields))];
    }
    // Fan-out to member identities is routed once each one's mailbox is resolved (M§4.2): in-process when that
    // mailbox is this service, federated otherwise ([`peer_task`]).
    st.hub_out(&group, emissions, now)
}

/// Deposit into a member identity's mailbox (M§6.5 rule 5), on the connection kept for that identity; the mailbox is
/// resolved when the connection is dialled: its DID document (M§4.2, authoritative), or for an identity with no
/// document its reachability hint's `DSIPMailbox` endpoint (M§4.2 `did:key`; §8.1 rule 6: a hint, never authority),
/// looked up on the hints nodes (DHT Hints Profile §10). The deposit is addressed to the resolved mailbox there —
/// or, when that mailbox is this service, taken in-process. An identity enrolled here (spec-gap 115) whose hint
/// names another mailbox is reached there: what it advertises decides, not where it once bound.
fn federate(service: &Arc<Mutex<Service>>, st: &mut Service, identity: &str, env: Envelope) {
    peer_send(service, st, PeerTarget::Identity(identity.to_string()), PeerMsg::Fanout(env));
}

/// Where a peer connection goes: a member identity whose mailbox is resolved when dialling, or a service already
/// known by DID and endpoint (the hub a group is registered with, M§6.6).
enum PeerTarget {
    Identity(String),
    Service { did: String, uri: String },
}

impl PeerTarget {
    /// The key the connection is kept under.
    fn key(&self) -> &str {
        match self {
            PeerTarget::Identity(id) => id,
            PeerTarget::Service { did, .. } => did,
        }
    }
}

/// The `DSIPMailbox` entries an identity's DID document lists, if it has one held here.
fn document_mailboxes(identity: &str, resolver: &StaticResolver) -> Option<Vec<Value>> {
    let doc = dsip_core::did::Resolver::resolve(resolver, identity)?;
    Some(doc.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect())
}

/// Resolve `identity`'s mailbox to `(mailbox DID, uri)`: the document's entries through the vector-pinned
/// `select_mailbox` (M§4.2); with no document, the hints nodes' records folded by §8.3 (`dsip_dht::record::select`)
/// and their `DSIPMailbox` endpoints offered as `hint_entries`. `None` when nothing usable is found.
async fn resolve_mailbox(service: &Arc<Mutex<Service>>, identity: &str) -> Option<(String, String)> {
    let (entries, nodes, ca) = {
        let st = service.lock().await;
        let resolver = st.resolver();
        if let Some(cached) = st.hinted.get(identity).filter(|(_, _, exp)| *exp > now_s()) {
            return Some((cached.0.clone(), cached.1.clone()));
        }
        (document_mailboxes(identity, &resolver), st.hints_nodes.clone(), st.ca.clone())
    };
    let (source, entries) = match entries {
        Some(e) => ("document_entries", e),
        None => {
            // M§4.2: hints only for an identity with no document entry; every node's records through §8.3. A node
            // may be plain http (a local node, or one proxied elsewhere): the records are signed, the transport is not
            // what is trusted (§8.1 rule 6).
            let http = {
                let mut b = reqwest::Client::builder().use_rustls_tls();
                if let Some(ca) = ca.as_deref() {
                    for cert in std::fs::read(ca).ok().and_then(|pem| reqwest::Certificate::from_pem_bundle(&pem).ok()).into_iter().flatten() {
                        b = b.add_root_certificate(cert);
                    }
                }
                b.build().ok()?
            };
            let mut frames: Vec<String> = vec![];
            for n in &nodes {
                let url = format!("{}/dsip/v1/hints/{}", n.trim_end_matches('/'), identity);
                match http.get(&url).send().await {
                    Ok(r) if r.status().as_u16() == 200 => {
                        let v: Value = r.json().await.unwrap_or(Value::Null);
                        for f in v["hints"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                            if !frames.iter().any(|x| x == f) {
                                frames.push(f.to_string());
                            }
                        }
                    }
                    Ok(r) => tracing::info!("hints for {identity} at {n}: {}", r.status()),
                    Err(e) => tracing::info!("hints for {identity} at {n}: {e}"),
                }
            }
            let resolver = StaticResolver::default();
            let ctx = Context::new(now_s(), &resolver);
            let (winner, _) = dsip_dht::record::select(&frames, &ctx);
            let Some(hint) = winner.filter(|h| h.subject == identity) else {
                tracing::info!("no mailbox for {identity}: no document held and no verified hint on {} node(s)", nodes.len());
                return None;
            };
            let entries: Vec<Value> = hint.endpoints.iter().filter(|e| e.service() == "DSIPMailbox")
                .map(|e| { let mut v = json!(e); v.as_object_mut().map(|m| m.remove("service")); v }).collect();
            tracing::info!("hint for {identity}: {} DSIPMailbox endpoint(s), seq {}, signed by {} — a hint, not authority (§8.1)",
                entries.len(), hint.seq, hint.signer);
            let mut st = service.lock().await;
            if let Some(e) = entries.first() {
                st.hinted.insert(identity.to_string(), (s_of(&e["mailbox"]), s_of(&e["uri"]), hint.expires_at.min(now_s() + HINT_REUSE_S)));
            }
            ("hint_entries", entries)
        }
    };
    let choice = select_mailbox(&json!({source: entries}));
    let mailbox_did = choice["selected"].as_str().map(String::from)?;
    let uri = entries.iter().find(|e| e["mailbox"] == json!(mailbox_did)).and_then(|e| e["uri"].as_str()).unwrap_or_default().to_string();
    Some((mailbox_did, uri))
}

/// Send on the connection kept for `target`, dialling it first if needed.
fn peer_send(service: &Arc<Mutex<Service>>, st: &mut Service, target: PeerTarget, msg: PeerMsg) {
    let k = target.key().to_string();
    if st.peers.get(&k).is_none_or(|tx| tx.is_closed()) {
        let (tx, rx) = mpsc::unbounded_channel();
        st.peers.insert(k.clone(), tx);
        let (key, ca, service2, name) = (st.key.clone(), st.ca.clone(), service.clone(), k.clone());
        tokio::spawn(async move {
            if let Err(e) = peer_task(key, ca, target, rx, service2).await {
                tracing::info!("connection for {name} ended: {e}");
            }
        });
    }
    if let Some(tx) = st.peers.get(&k) {
        let _ = tx.send(msg);
    }
}

/// One outbound connection to the mailbox of `identity`: send deposits, feed acceptances back to the hub. When it
/// ends — no mailbox found, a dial that failed, or a connection lost — every deposit a device forwarded through it
/// and the hub never answered is answered `mailbox.hub-unreachable`, so the device keeps it pending (M§9.4,
/// spec-gap 72).
async fn peer_task(
    key: KeyPair,
    ca: Option<PathBuf>,
    target: PeerTarget,
    mut rx: mpsc::UnboundedReceiver<PeerMsg>,
    service: Arc<Mutex<Service>>,
) -> Result<()> {
    // forwarded deposit id → the owner device waiting for the hub's answer (M§5.2)
    let mut forwarded: HashMap<String, String> = HashMap::new();
    let identity = target.key().to_string();
    let resolved = match target {
        PeerTarget::Identity(id) => resolve_mailbox(&service, &id).await,
        PeerTarget::Service { did, uri } => Some((did, uri)),
    };
    let outcome = match resolved {
        Some((mailbox_did, _)) if mailbox_did == key.did() => {
            // The member's mailbox is this service: in-process (M§6.5 rule 5). The resolution is re-done when this
            // task ends: after a quiet minute, or at once when this mailbox does not hold the group for the member
            // (it registered the group elsewhere: its hint has moved on, or will), so the hub follows the hint.
            loop {
                let Ok(Some(msg)) = tokio::time::timeout(std::time::Duration::from_secs(HINT_REUSE_S as u64), rx.recv()).await else { break };
                let mut st = service.lock().await;
                match msg {
                    PeerMsg::Fanout(env) => {
                        // Exactly what a remote mailbox would do with this deposit: addressed to this service, verified
                        // as a frame and dispatched — a welcome through M§14.2's authorization, a fan-out into the
                        // member's registration — and the answers read as the peer loop reads them (M§6.5 rule 5).
                        let now = now_s();
                        let mut dep = wire::payload_of(&env).unwrap_or_default();
                        let (group, class, id) = (s_of(&dep["group"]), s_of(&dep["class"]), s_of(&dep["id"]));
                        let seq = dep["seq"].as_i64().unwrap_or(-1);
                        dep["to"] = json!(st.key.did());
                        let env = envelope::sign(&dep, &st.key, &st.key.kid());
                        let frame = env.frame();
                        let resolver = st.resolver();
                        let me = st.key.did();
                        let inb = {
                            let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
                            match verify_frame(&frame, &ctx) {
                                Ok(i) => i,
                                Err(r) => {
                                    tracing::info!("our own fan-out {class} in {group} does not verify: {r}");
                                    continue;
                                }
                            }
                        };
                        st.seen.insert(&id, now, now);
                        let outs = dispatch(&service, &mut st, &inb, &frame, &me, &me, &resolver, now);
                        let mut refused: Option<String> = None;
                        let mut more = vec![];
                        let (replies, rest): (Vec<Out>, Vec<Out>) = outs.into_iter().partition(|o| matches!(o, Out::Device(to, _) if *to == me));
                        for reply in replies {
                            let Out::Device(_, renv) = reply else { continue };
                            let Some(p) = wire::payload_of(&renv) else { continue };
                            if p["type"] == "error" {
                                refused = Some(s_of(&p["reason"]));
                                let queued = if seq >= 0 || class == "welcome" { " (queued, retried)" } else { "" };
                                tracing::info!("our own mailbox refused hub fan-out {class} seq {} in {group}: {}{queued}", dep["seq"], p["reason"]);
                            } else if p["type"] == "accepted" {
                                if p["duplicate"] == json!(true) {
                                    tracing::info!("our own mailbox already had {class} seq {} in {group}", dep["seq"]);
                                }
                                // spec-gap 66: a welcome carries no seq; its acknowledgement is matched by deposit id
                                let welcome_seq = if class == "welcome" { st.welcomes_sent.remove(&id).map(|(_, _, s)| s) } else { None };
                                if let Some(h) = st.hubs.get_mut(&group) {
                                    if let Some(s) = welcome_seq {
                                        more.extend(h.step(&json!({"ack": {"identity": identity, "seq": s, "class": "welcome"}})));
                                    }
                                    if seq >= 0 && class != "welcome" {
                                        more.extend(h.step(&json!({"ack": {"identity": identity, "seq": seq}})));
                                    }
                                }
                            }
                        }
                        let mut outs = rest;
                        outs.extend(st.hub_out(&group, more, now));
                        let (local, rest): (Vec<Out>, Vec<Out>) = outs.into_iter().partition(|o| matches!(o, Out::Device(..)));
                        st.send_local(local);
                        route_identities(&service, &mut st, rest);
                        st.persist();
                        if refused.as_deref() == Some("mailbox.unknown-group") {
                            tracing::info!("{identity} has not registered {group} here: its mailbox is looked up again at the next delivery");
                            st.hinted.remove(&identity);
                            break;
                        }
                    }
                    PeerMsg::Forward(env, device) => {
                        if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                            forwarded.insert(id, device); // a forward to ourselves cannot arise; answered unreachable below
                        }
                    }
                }
            }
            Ok(())
        }
        Some((mailbox_did, uri)) => {
            let dropped = service.lock().await.drop_fanout_to.as_deref() == Some(mailbox_did.as_str());
            if dropped {
                tracing::info!("dropping fan-out to {mailbox_did} (fault injection: --drop-fanout-to)");
                Err(anyhow::anyhow!("fan-out dropped"))
            } else {
                peer_run(&key, ca, uri, &mailbox_did, &mut rx, &mut forwarded, &service).await
            }
        }
        None => Err(anyhow::anyhow!("no mailbox found for {identity}")),
    };
    let mut lost: Vec<(String, String)> = forwarded.drain().collect();
    while let Ok(msg) = rx.try_recv() {
        if let PeerMsg::Forward(env, device) = msg {
            if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                lost.push((id, device));
            }
        }
    }
    if !lost.is_empty() {
        let st = service.lock().await;
        let now = now_s();
        for (id, device) in lost {
            tracing::info!("hub of {identity} unreachable: answering {device}'s deposit {id} mailbox.hub-unreachable");
            if let Some(tx) = st.bound.get(&device) {
                let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("the group's hub could not be reached"));
                let _ = tx.send(env.frame());
            }
        }
    }
    outcome
}

/// Deliver hub outs addressed to identities (M§6.5 rule 5): each through its resolved mailbox.
fn route_identities(service: &Arc<Mutex<Service>>, st: &mut Service, outs: Vec<Out>) {
    for out in outs {
        if let Out::Identity(to, env) = out {
            federate(service, st, &to, env);
        }
    }
}

async fn peer_run(
    key: &KeyPair,
    ca: Option<PathBuf>,
    uri: String,
    mailbox_did: &str,
    rx: &mut mpsc::UnboundedReceiver<PeerMsg>,
    forwarded: &mut HashMap<String, String>,
    service: &Arc<Mutex<Service>>,
) -> Result<()> {
    let tls = tls::client_config(ca.as_deref())?;
    let mut seen = SeenIds::default();
    let params = ConnectParams {
        url: uri,
        tls,
        device: key,
        on_behalf_of: None,
        delegations: vec![],
        supported: Supported::all_known(),
    };
    // The resolver is built and dropped inside the call: `&dyn Resolver` is not Send across awaits.
    let mut conn = {
        let resolver = StaticResolver::default();
        Connection::connect(&params, &resolver, &mut seen).await?
    };
    // deposit id → (group, recipient identity, seq): an `accepted` names only what it answers, but the
    // hub's fan-out queue is per identity (M§6.5 rule 5), so the recipient has to be remembered here.
    let mut inflight: HashMap<String, (String, String, i64)> = HashMap::new();
    anyhow::ensure!(conn.relay.did == mailbox_did, "peer mailbox is {} not {mailbox_did}", conn.relay.did);
    tracing::info!("federating to {mailbox_did}");
    loop {
        tokio::select! {
            next = rx.recv() => match next {
                Some(PeerMsg::Fanout(env)) => {
                    // The deposit is addressed to the peer mailbox: re-signed with the resolved `to` (M§5.2).
                    let mut env = env;
                    if let Some(mut p) = wire::payload_of(&env) {
                        if let (Some(id), Some(group), Some(to)) =
                            (p["id"].as_str(), p["group"].as_str(), p["recipient"].as_str())
                        {
                            inflight.insert(id.into(), (group.into(), to.into(), p["seq"].as_i64().unwrap_or(-1)));
                        }
                        p["to"] = json!(mailbox_did);
                        env = envelope::sign(&p, key, &key.kid());
                    }
                    conn.send(&env).await?
                }
                Some(PeerMsg::Forward(env, device)) => {
                    if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                        forwarded.insert(id, device);
                    }
                    tracing::info!("forwarding a deposit to hub {mailbox_did}");
                    conn.send(&env).await?
                }
                None => break,
            },
            frame = conn.recv() => match frame? {
                Some(text) => {
                    let Ok(env) = Envelope::from_frame(&text) else { continue };
                    let Some(p) = wire::payload_of(&env) else { continue };
                    if let Some(device) = p["in_reply_to"].as_str().and_then(|id| forwarded.remove(id)) {
                        // The hub's answer to a forwarded deposit, passed through to the device (M§5.2).
                        let st = service.lock().await;
                        if let Some(tx) = st.bound.get(&device) {
                            let _ = tx.send(text.clone());
                        }
                        continue;
                    }
                    if p["type"] == "error" {
                        tracing::info!("{mailbox_did} refused our deposit: {} {}", p["reason"], p["detail"]);
                    }
                    if p["type"] == "accepted" {
                        // spec-gap 66: a welcome carries no seq, so its acknowledgement is matched by deposit id
                        if let Some(id) = p["in_reply_to"].as_str() {
                            let mut st = service.lock().await;
                            if let Some((group, identity, seq)) = st.welcomes_sent.remove(id) {
                                if let Some(hub) = st.hubs.get_mut(&group) {
                                    let more = hub.step(&json!({"ack": {"identity": identity, "seq": seq, "class": "welcome"}}));
                                    let outs = st.hub_out(&group, more, now_s());
                                    route_identities(service, &mut st, outs);
                                }
                                st.persist();
                                continue;
                            }
                        }
                        let Some((group, identity, seq)) = p["in_reply_to"].as_str().and_then(|id| inflight.remove(id)) else {
                            continue;
                        };
                        if seq < 0 {
                            continue; // group-info and ephemeral are not sequenced
                        }
                        let mut st = service.lock().await;
                        if p["duplicate"] == json!(true) {
                            tracing::info!("{mailbox_did} already had seq {seq} in {group}");
                        }
                        if let Some(hub) = st.hubs.get_mut(&group) {
                            let more = hub.step(&json!({"ack": {"identity": identity, "seq": seq}}));
                            // The ack may release the next queued item for that mailbox.
                            let outs = st.hub_out(&group, more, now_s());
                            route_identities(service, &mut st, outs);
                        }
                        st.persist();
                    }
                }
                None => break,
            },
        }
    }
    Ok(())
}
