//! The mailbox/hub service.
//!
//! Spec: M§4.3 (bind with `hello`, advertise mailbox capabilities), M§5 (the profile message set),
//! M§6.5–M§6.6 (hub ordering, fan-out, group registration), M§9.1 (deposit once, push to bound
//! devices), M§14.2 (first-contact authorization).
//!
//! Impl: every decision comes from `dsip_messaging::{mailbox::Mailbox, hub::Hub}` and, for commits,
//! `dsip_mls::HubView`; this binary only moves bytes and keeps the payloads the cursors name.
//! One instance serves one owner identity and hubs the groups whose deposits name it. An owner
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

use std::collections::HashMap;
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
    /// The identity this mailbox serves.
    #[arg(long)]
    owner: String,
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

struct Service {
    key: KeyPair,
    owner: String,
    resolver_files: Vec<PathBuf>,
    ca: Option<PathBuf>,
    seen: SeenIds,
    supported: Supported,
    mailbox: Mailbox,
    hubs: HashMap<String, Hub>,
    views: HashMap<String, HubView>,
    store: Store,
    /// Items the hub has sequenced but whose fan-out is still in flight, by (group, seq).
    fanout: HashMap<(String, i64), Item>,
    /// `dsip_conversation` of each hubbed group: its kind and the hub reference welcomes carry.
    conversations: HashMap<String, Value>,
    /// Hub `{did, uri}` of each group registered for the owner, from its welcome (M§6.6): where to forward.
    hub_refs: HashMap<String, Value>,
    bound: HashMap<String, mpsc::UnboundedSender<String>>,
    peers: HashMap<String, mpsc::UnboundedSender<PeerMsg>>,
    /// `delegation-revocation` records from the owner identity (spec-gap 57).
    revocations: Vec<Envelope>,
    /// Ciphertext blobs, one file per SHA-256 (M§8.4).
    blob_dir: PathBuf,
    /// `https://…/blobs` as advertised (M§4.3).
    blob_endpoint: String,
    max_blob_bytes: i64,
    /// Where [`STATE_FILE`] lives.
    state_dir: PathBuf,
    /// Unacknowledged fan-out heads by (group, member identity, class): (seq, next retry at, current delay). A welcome
    /// has its own queue (spec-gap 66), so it is tracked apart from the identity's sequenced items.
    retry: HashMap<(String, String, String), (i64, i64, i64)>,
    /// Manifest blobs of newly stored items, waiting to be replicated (M§8.4 rule 6, spec-gap 65).
    replicate: Vec<Value>,
    /// Blobs whose replication is still to be tried again: `(entry, attempts so far, next attempt at)` (spec-gap 67).
    replicate_later: Vec<(Value, i64, i64)>,
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
    fn persist(&mut self) {
        let now = now_s();
        self.seen.sweep(now);
        let queued: HashMap<&String, std::collections::BTreeSet<i64>> = self.hubs.iter().map(|(g, h)| (g, h.queued_seqs())).collect();
        // A fan-out payload is kept while its seq is queued for some mailbox; group-info and ephemeral (-1) are the latest.
        self.fanout.retain(|(g, seq), _| *seq < 0 || queued.get(g).is_some_and(|q| q.contains(seq)));
        let compact = |e: &Envelope| format!("{}.{}.{}", e.protected, e.payload, e.signature);
        let state = json!({
            "format": 1,
            "service": self.key.did(),
            "owner": self.owner,
            "mailbox": self.mailbox.full_state(),
            "hubs": self.hubs.iter().map(|(g, h)| (g.clone(), h.full_state())).collect::<serde_json::Map<_, _>>(),
            "views": self.views.iter().map(|(g, v)| (g.clone(), serde_json::from_slice(&v.save()).unwrap_or(Value::Null)))
                .collect::<serde_json::Map<_, _>>(),
            "store": serde_json::to_value(&self.store).unwrap_or(Value::Null),
            "fanout": self.fanout.iter().map(|((g, seq), it)| json!([g, seq, it])).collect::<Vec<_>>(),
            "conversations": self.conversations,
            "hub_refs": self.hub_refs,
            "revocations": self.revocations.iter().map(compact).collect::<Vec<_>>(),
            "welcomes_sent": self.welcomes_sent.iter().map(|(id, (g, i, s))| json!([id, g, i, s])).collect::<Vec<_>>(),
            "replicate_later": self.replicate_later.iter().map(|(e, n, at)| json!([e, n, at])).collect::<Vec<_>>(),
            "seen": self.seen.entries(),
        });
        let bytes = serde_json::to_vec(&state).unwrap_or_default();
        if let Err(e) = write_atomically(&self.state_dir.join(STATE_FILE), &bytes) {
            tracing::warn!("saving state failed: {e}");
        }
    }

    /// Reload what [`Service::persist`] saved. Returns false when there is nothing to reload.
    fn restore(&mut self) -> Result<bool> {
        let path = self.state_dir.join(STATE_FILE);
        if !path.exists() {
            return Ok(false);
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&path)?).context("reading saved state")?;
        anyhow::ensure!(v["format"] == 1, "unknown state format {}", v["format"]);
        anyhow::ensure!(v["owner"] == json!(self.owner), "saved state is for {}, not {}", v["owner"], self.owner);
        self.mailbox = Mailbox::from_full_state(&v["mailbox"]).context("saved mailbox")?;
        for (g, h) in v["hubs"].as_object().into_iter().flatten() {
            self.hubs.insert(g.clone(), Hub::from_full_state(h).context("saved hub")?);
        }
        for (g, view) in v["views"].as_object().into_iter().flatten() {
            let view = HubView::load(&serde_json::to_vec(view)?).map_err(|e| anyhow::anyhow!("saved view of {g}: {e}"))?;
            self.views.insert(g.clone(), view);
        }
        self.store = serde_json::from_value(v["store"].clone()).context("saved store")?;
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
            self.replicate_later.push((r[0].clone(), r[1].as_i64().unwrap_or(1), r[2].as_i64().unwrap_or(0)));
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
            let resolver = self.resolver();
            for out in self.hub_out(&group, vec![e], now) {
                match out {
                    // Our own owner's queue is delivered in-process; it waits like any other when the mailbox refuses
                    // its own hub (a moved group's handover, spec-gap 71).
                    Out::Identity(id, env) if id == self.owner => {
                        let outs = self.deliver_local(&group, env, now);
                        self.send_local(outs);
                    }
                    Out::Identity(id, env) => federate(service, self, &id, env, &resolver),
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
        let behind = now - self.mailbox.now();
        if behind > 0 {
            let emissions = self.mailbox.step(&json!({"advance": behind}));
            let outs = self.mailbox_out(emissions, now);
            self.send_local(outs);
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

    /// A hub fan-out addressed to our own owner: into the mailbox in-process. The hub's queue is acknowledged only
    /// when the mailbox took the item (spec-gap 71: a moved group's mailbox holds even its own hub off until the old
    /// hub's items arrive or the handover wait expires), and whatever that acknowledgement releases is delivered
    /// the same way.
    fn deliver_local(&mut self, group: &str, env: Envelope, now: i64) -> Vec<Out> {
        let mut result = vec![];
        let mut pending = vec![env];
        while let Some(env) = pending.pop() {
            let dep = wire::payload_of(&env).unwrap_or(json!({}));
            let (outs, refused) = self.local_deposit(&dep, now);
            result.extend(outs);
            let (class, id) = (s_of(&dep["class"]), s_of(&dep["id"]));
            if let Some(reason) = refused {
                let queued = if dep["seq"].is_i64() || class == "welcome" { " (queued, retried)" } else { "" };
                tracing::info!("our own mailbox refused hub fan-out {class} seq {} in {group}: {reason}{queued}", dep["seq"]);
                continue;
            }
            // spec-gap 66: a welcome carries no seq; the one queued for it is remembered by deposit id
            let welcome_seq = if class == "welcome" { self.welcomes_sent.remove(&id).map(|(_, _, s)| s) } else { None };
            let Some(h) = self.hubs.get_mut(group) else { continue };
            let mut more = vec![];
            if let Some(s) = welcome_seq {
                // the welcome for our own owner never leaves the process, so its queue is released here
                more.extend(h.step(&json!({"ack": {"identity": self.owner, "seq": s, "class": "welcome"}})));
            }
            if let Some(s) = dep["seq"].as_i64().filter(|_| class != "welcome") {
                // A local ack may release the owner's next queued item; deliver it the same way.
                more.extend(h.step(&json!({"ack": {"identity": self.owner, "seq": s}})));
            }
            if !more.is_empty() {
                tracing::info!("local fan-out released {} more", more.len());
            }
            for o in self.hub_out(group, more, now) {
                match o {
                    Out::Identity(to, env) if to == self.owner => pending.push(env),
                    other => result.push(other),
                }
            }
        }
        result
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

    /// Mailbox emissions → envelopes (M§5.3, M§5.4, M§5.5).
    fn mailbox_out(&mut self, emissions: Vec<Value>, now: i64) -> Vec<Out> {
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
                        .filter_map(|c| self.store.get(c).map(|it| self.item_value(it, c)))
                        .collect();
                    let env = wire::items(&self.key, &to, now, body["in_reply_to"].as_str(), list, body["next"].clone());
                    out.push(Out::Device(to, env));
                }
                "push" => {
                    if let Some(c) = body["cursor"].as_str() {
                        if let Some(it) = self.store.get(c) {
                            let env = wire::items(&self.key, &to, now, None, vec![self.item_value(it, c)], Value::Null);
                            out.push(Out::Device(to, env));
                        }
                    }
                }
                "key_packages" => {
                    let mut packages = vec![];
                    let mut last_resort = None;
                    for (device, kind) in body["devices"].as_object().into_iter().flatten() {
                        if let Some(bytes) = self.store.take_key_package(device, kind.as_str().unwrap_or("")) {
                            if kind == "last-resort" {
                                last_resort = Some(bytes);
                            } else {
                                packages.push(json!(bytes));
                            }
                        }
                    }
                    let mut fields = json!({"in_reply_to": body["in_reply_to"], "subject": self.owner, "key_packages": packages});
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

    /// Feed a hub fan-out addressed to our own owner straight into the mailbox (no socket). The second value is the
    /// mailbox's refusal reason, if it refused.
    fn local_deposit(&mut self, dep: &Value, now: i64) -> (Vec<Out>, Option<String>) {
        let item = Item::from_deposit(dep, &self.key.did(), now);
        // A welcome's `seq` (spec-gap 83) tells the new member where it starts counting; it is not a place in the
        // mailbox's sequence — the commit holds that seq — so the mailbox stores the welcome unsequenced, as before.
        let seq = if dep["class"] == "welcome" { Value::Null } else { dep["seq"].clone() };
        let event = json!({"hub_deposit": {"id": dep["id"], "from": self.key.did(), "recipient": self.owner,
            "group": dep["group"], "seq": seq, "class": dep["class"], "expires_at": dep["expires_at"]}});
        let emissions = self.mailbox.step(&event);
        let refused = emissions.iter().find_map(|e| e["error"]["reason"].as_str().map(String::from));
        let mut out = self.ephemeral_pushes(&emissions, dep, &self.key.did(), now);
        self.absorb(&emissions, item);
        out.extend(self.mailbox_out(emissions, now));
        (out, refused)
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

    /// Record the payload behind whatever cursor the machine just assigned.
    fn absorb(&mut self, emissions: &[Value], item: Item) {
        for e in emissions {
            if let Some(c) = e.get("accepted").and_then(|a| a.get("cursor")).and_then(Value::as_str) {
                if e["accepted"]["duplicate"] != json!(true) {
                    if item.class == "application" {
                        // M§8.4 rule 6: the blobs this item references are replicated after it is stored
                        self.replicate.extend(item.blobs.as_ref().and_then(Value::as_array).into_iter().flatten().cloned());
                    }
                    self.store.put(c, item.clone());
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
    let (cert, keyfile) = tls::ensure_self_signed(&args.state, &hosts)?;
    let acceptor = tls::acceptor(&cert, &keyfile)?;
    tracing::info!("mailbox {} for {} on wss://{}/dsip (ca {})", key.did(), args.owner, args.listen, cert.display());

    let mailbox = Mailbox::new(&json!({"now": now_s(), "owner": args.owner, "serves": [args.owner], "devices": [],
        "admit": args.admit, "intro_limit": args.intro_limit, "intro_window": args.intro_window, "inbox_cap": args.inbox_cap,
        "handover_wait": args.handover_wait}));
    let service = Arc::new(Mutex::new(Service {
        key,
        owner: args.owner.clone(),
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        seen: SeenIds::default(),
        supported: Supported::all_known(),
        mailbox,
        hubs: HashMap::new(),
        views: HashMap::new(),
        store: Store::default(),
        fanout: HashMap::new(),
        conversations: HashMap::new(),
        hub_refs: HashMap::new(),
        bound: HashMap::new(),
        peers: HashMap::new(),
        revocations: vec![],
        blob_dir: args.state.join("blobs"),
        blob_endpoint: blob_endpoint(&args.listen, args.host.first().map(String::as_str)),
        max_blob_bytes: args.max_blob_bytes,
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
            tracing::info!("restored state: {} items, {} hubbed groups, {} registered devices",
                st.mailbox.snapshot()["items"].as_array().map_or(0, Vec::len), st.hubs.len(), st.mailbox.devices().len());
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
            let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut st.replicate_later).into_iter().partition(|(_, _, at)| *at <= now);
            st.replicate_later = waiting;
            drop(st);
            for (entry, attempt, _) in due {
                let service = retry_service.clone();
                tokio::spawn(async move { replicate_blob(service, entry, attempt).await });
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
                let mbx = json!({"did": st.key.did(), "serves": [st.owner], "max_blob_bytes": st.max_blob_bytes});
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
async fn replicate_blob(service: Arc<Mutex<Service>>, entry: Value, attempt: i64) {
    let (decision, http, path) = {
        let st = service.lock().await;
        let sha = entry["sha256"].as_str().unwrap_or("").to_string();
        let valid = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let path = st.blob_dir.join(&sha);
        let stored = if valid && path.exists() { vec![sha] } else { vec![] };
        let d = dsip_messaging::mailbox::blob_replicate(&json!({"mode": st.mailbox.mode(), "max_blob_bytes": st.max_blob_bytes,
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
            st.replicate_later.push((entry.clone(), attempt + 1, now_s() + delay));
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
        if identity == st.owner {
            st.bound.insert(device.clone(), tx.clone());
            // The owner's registered devices are the ones that have bound (M§4.4), including before a restart.
            let mut devices: Vec<String> = st.mailbox.devices().to_vec();
            devices.push(device.clone());
            st.mailbox.register_devices(&devices);
        }
        st.persist();
    }

    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(frame) if frame == CLOSE_SENTINEL => {
                    // The device's delegation was revoked: end the binding now (M§12.4, spec-gap 57).
                    let _ = ws.close(None).await;
                    break;
                }
                Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                None => break,
            },
            inbound = ws.next() => match inbound {
                Some(Ok(WsMessage::Text(t))) => {
                    let replies = handle(&service, t.to_string(), &device, &identity).await;
                    for frame in replies {
                        ws.send(WsMessage::Text(frame.into())).await?;
                    }
                }
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
            },
        }
    }
    let mut st = service.lock().await;
    // A device may hold a second, short-lived connection; only its own binding ends here.
    if st.bound.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.bound.remove(&device);
        st.mailbox.step(&json!({"unbind": {"device": device}}));
        tracing::info!("unbound {device}");
    }
    Ok(())
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
            Out::Identity(identity, env) => federate(service, &mut st, &identity, env, &resolver),
        }
    }
    for entry in std::mem::take(&mut st.replicate) {
        let service = service.clone();
        tokio::spawn(async move { replicate_blob(service, entry, 1).await });
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
                let emissions = st.mailbox.step(&event);
                for e in &emissions {
                    match (e.get("accepted"), e.get("error")) {
                        (Some(a), _) if a.get("cursor").is_some() => tracing::info!("held {class} from {sender} for {to}"),
                        (Some(_), _) => tracing::info!("{class} from {sender} for {to} accepted, not held"),
                        (_, Some(err)) => tracing::info!("{class} from {sender} refused: {}", err["reason"]),
                        _ => {}
                    }
                }
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            if class == "welcome" && p["recipient"].as_str() == Some(st.owner.as_str()) {
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let grant = p["grants"].as_array().into_iter().flatten().filter_map(Value::as_str)
                    .find_map(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
                // spec-gap 66: the welcome's own bytes tell a retried delivery from a new invitation
                let w_digest = p["mls"].as_str().and_then(dsip_core::b64::decode).map(|b| digest(&b));
                let mut w = json!({"id": id, "from": device, "adder_identity": identity,
                    "recipient": st.owner, "group": group, "hub": p["hub"]["did"], "grant": grant,
                    "successor_of": p["successor_of"], "digest": w_digest});
                // A service-signed welcome (no delegation) came from a hub: only `origin` names the adder (M§14.2).
                if device == hello_device && bound_identity == device {
                    w["via_hub"] = json!(true);
                    w["issued_at"] = p["issued_at"].clone();
                    w.as_object_mut().expect("object").remove("adder_identity");
                    if let Some(o) = p["origin"].as_str().and_then(|o| origin_of(o, &ctx)) {
                        w["origin"] = o;
                    }
                }
                let emissions = st.mailbox.step(&json!({"welcome": w}));
                if let Some(e) = emissions.iter().find_map(|e| e.get("error")) {
                    tracing::info!("welcome for {group} refused: {} (origin {})", e["reason"], w.get("origin").is_some());
                }
                if emissions.iter().any(|e| e.get("accepted").is_some()) {
                    st.hub_refs.insert(group.clone(), p["hub"].clone());
                }
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            if class == "archive" {
                let event = json!({"archive": {"id": id, "device": device, "ref_group": p["ref_group"], "ref_seq": p["ref_seq"]}});
                let emissions = st.mailbox.step(&event);
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            if p["recipient"].as_str() == Some(st.owner.as_str()) {
                // Fan-out from another hub for our owner.
                let event = json!({"hub_deposit": {"id": id, "from": identity, "recipient": st.owner,
                    "group": group, "seq": p["seq"], "class": class, "expires_at": p["expires_at"]}});
                let emissions = st.mailbox.step(&event);
                let mut out = st.ephemeral_pushes(&emissions, &p, &identity, now);
                st.absorb(&emissions, item);
                out.extend(st.mailbox_out(emissions, now));
                return out;
            }
            if p["to"].as_str() != Some(st.key.did().as_str()) {
                // Addressed to another service: forward to the group's hub, or refuse (M§5.2, spec-gap 45).
                let event = json!({"forward": {"id": id, "device": device, "identity": identity, "group": group, "to": p["to"]}});
                let emissions = st.mailbox.step(&event);
                if emissions.iter().any(|e| e.get("forward").is_some()) {
                    let uri = st.hub_refs.get(&group).and_then(|h| h["uri"].as_str()).map(String::from);
                    let target = p["to"].as_str().unwrap_or("").to_string();
                    match (uri, Envelope::from_frame(frame)) {
                        (Some(uri), Ok(env)) => {
                            peer_send(service, st, &target, uri, PeerMsg::Forward(env, device.clone()));
                            return vec![];
                        }
                        _ => {
                            // M§9.4 (spec-gap 72): no endpoint for the hub is the same outage as a failed dial
                            let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("no endpoint known for the hub"));
                            return vec![Out::Device(device, env)];
                        }
                    }
                }
                return st.mailbox_out(emissions, now);
            }
            let mut item = item;
            if class == "handshake" {
                item.origin = Envelope::from_frame(frame).ok().map(|e| format!("{}.{}.{}", e.protected, e.payload, e.signature));
            }
            hub_deposit(st, &p, &device, &identity, item, resolver, now)
        }
        "sync" => {
            let mut e = json!({"id": id, "device": device, "since": p["since"], "live": p["live"] == json!(true)});
            if let Some(a) = p.get("ack_through") {
                e["ack_through"] = a.clone();
            }
            if let Some(l) = p.get("limit") {
                e["limit"] = l.clone();
            }
            let emissions = st.mailbox.step(&json!({"sync": e}));
            st.mailbox_out(emissions, now)
        }
        "key-packages" => {
            let packages: Vec<String> = p["key_packages"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
            let count = packages.len() as i64;
            let last = p["last_resort"].as_str().map(String::from);
            st.store.add_key_packages(&device, packages, last.clone());
            let event = json!({"kp_upload": {"id": id, "device": device, "count": count, "last_resort": last.is_some()}});
            let emissions = st.mailbox.step(&event);
            st.mailbox_out(emissions, now)
        }
        "key-package-fetch" => {
            let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
            let grant = p["grant"].as_str().and_then(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
            let mut event = json!({"kp_fetch": {"id": id, "from": device, "from_identity": identity,
                "target": p["target"], "grant": grant}});
            if let Some(g) = p.get("successor_of") {
                event["kp_fetch"]["successor_of"] = g.clone(); // M§7.5, spec-gap 61
            }
            let emissions = st.mailbox.step(&event);
            st.mailbox_out(emissions, now)
        }
        "mailbox-config" => {
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
                    (q["type"] == "delegation-revocation" && q["subject"] == json!(st.owner) && q["from"] == json!(st.owner)
                        && ver.signer_did == st.owner)
                        .then(|| q["device"].as_str().map(String::from))
                        .flatten()
                });
                match device_of {
                    Some(d) => {
                        tracing::info!("delegation of {d} revoked by {}", st.owner);
                        st.revocations.push(rev);
                        revoked_devices.push(d);
                    }
                    None => tracing::info!("revocation refused: not signed by {}", st.owner),
                }
            }
            if !revoked_devices.is_empty() {
                e["revoked_devices"] = json!(revoked_devices);
            }
            let emissions = st.mailbox.step(&json!({"config": e}));
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
            st.mailbox_out(emissions, now)
        }
        other => {
            tracing::info!("no handler for {other}");
            vec![]
        }
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
                    // re-join it by external commit with no leaf left (M§6.8) — is the identity this mailbox serves
                    ctx_hub["owner"] = json!(st.owner);
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
    let outs = st.hub_out(&group, emissions, now);
    // Fan-out addressed to our own owner never leaves the process.
    let mut result = vec![];
    for o in outs {
        match o {
            Out::Identity(to, env) if to == st.owner => result.extend(st.deliver_local(&group, env, now)),
            other => result.push(other),
        }
    }
    result
}

/// Deposit into another identity's mailbox, found through its DID document (M§4.2, M§6.5 rule 5).
fn federate(service: &Arc<Mutex<Service>>, st: &mut Service, identity: &str, env: Envelope, resolver: &StaticResolver) {
    let doc = dsip_core::did::Resolver::resolve(resolver, identity);
    let entries: Vec<Value> = doc
        .map(|d| d.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect())
        .unwrap_or_default();
    let choice = select_mailbox(&json!({"document_entries": entries}));
    let Some(mailbox_did) = choice["selected"].as_str().map(String::from) else {
        tracing::info!("no mailbox for {identity}: {}", choice);
        return;
    };
    if st.drop_fanout_to.as_deref() == Some(mailbox_did.as_str()) {
        tracing::info!("dropping fan-out to {mailbox_did} (fault injection: --drop-fanout-to)");
        return;
    }
    let uri = entries
        .iter()
        .find(|e| e["mailbox"] == json!(mailbox_did))
        .and_then(|e| e["uri"].as_str())
        .unwrap_or_default()
        .to_string();
    let mut env = env;
    // The deposit is addressed to the peer mailbox; re-sign with the resolved `to` (M§5.2).
    if let Some(mut p) = wire::payload_of(&env) {
        p["to"] = json!(mailbox_did);
        env = envelope::sign(&p, &st.key, &st.key.kid());
    }
    peer_send(service, st, &mailbox_did, uri, PeerMsg::Fanout(env));
}

/// Send on the connection to a peer service, dialling it first if needed.
fn peer_send(service: &Arc<Mutex<Service>>, st: &mut Service, peer_did: &str, uri: String, msg: PeerMsg) {
    if st.peers.get(peer_did).is_none_or(|tx| tx.is_closed()) {
        let (tx, rx) = mpsc::unbounded_channel();
        st.peers.insert(peer_did.to_string(), tx);
        let (key, ca, service2, target) = (st.key.clone(), st.ca.clone(), service.clone(), peer_did.to_string());
        tokio::spawn(async move {
            let name = target.clone();
            if let Err(e) = peer_task(key, ca, uri, target, rx, service2).await {
                tracing::info!("connection to {name} ended: {e}");
            }
        });
    }
    if let Some(tx) = st.peers.get(peer_did) {
        let _ = tx.send(msg);
    }
}

/// One outbound connection to a peer mailbox: send deposits, feed acceptances back to the hub. When it ends —
/// a dial that failed, or a connection lost — every deposit a device forwarded through it and the hub never
/// answered is answered `mailbox.hub-unreachable`, so the device keeps it pending (M§9.4, spec-gap 72).
async fn peer_task(
    key: KeyPair,
    ca: Option<PathBuf>,
    uri: String,
    mailbox_did: String,
    mut rx: mpsc::UnboundedReceiver<PeerMsg>,
    service: Arc<Mutex<Service>>,
) -> Result<()> {
    // forwarded deposit id → the owner device waiting for the hub's answer (M§5.2)
    let mut forwarded: HashMap<String, String> = HashMap::new();
    let outcome = peer_run(&key, ca, uri, &mailbox_did, &mut rx, &mut forwarded, &service).await;
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
            tracing::info!("hub {mailbox_did} unreachable: answering {device}'s deposit {id} mailbox.hub-unreachable");
            if let Some(tx) = st.bound.get(&device) {
                let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("the group's hub could not be reached"));
                let _ = tx.send(env.frame());
            }
        }
    }
    outcome
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
                    if let Some(p) = wire::payload_of(&env) {
                        if let (Some(id), Some(group), Some(to)) =
                            (p["id"].as_str(), p["group"].as_str(), p["recipient"].as_str())
                        {
                            inflight.insert(id.into(), (group.into(), to.into(), p["seq"].as_i64().unwrap_or(-1)));
                        }
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
                                    for out in outs {
                                        if let Out::Identity(to, env) = out {
                                            let resolver = st.resolver();
                                            federate(service, &mut st, &to, env, &resolver);
                                        }
                                    }
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
                            for out in outs {
                                if let Out::Identity(to, env) = out {
                                    let resolver = st.resolver();
                                    federate(service, &mut st, &to, env, &resolver);
                                }
                            }
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
