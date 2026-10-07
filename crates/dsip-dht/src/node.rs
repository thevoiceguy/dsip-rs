//! A Kademlia node for the hints overlay.
//!
//! Spec: §8.3/§8.5 applied mechanically at the storage boundary — an inbound
//! PUT is stored only if [`crate::record::evaluate`] accepts it against
//! whatever this node already holds for the key; anything else is counted and
//! dropped (the poisoning path of plan §10.3). GETs return every record the
//! network offers and the caller ranks them with [`crate::record::select`].
//!
//! Impl: records are re-announced every [`NodeConfig::republish_interval`]
//! while unexpired so replication survives churn; re-*signing* before
//! `expires_at` is the publisher's job (it holds the key), see the agent.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use futures_util::StreamExt;
use libp2p::kad::{self, store::RecordStore, QueryId, Quorum, Record, RecordKey};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{Context, Envelope};

use crate::record::{evaluate, key_for, select, Hint};
use crate::PROTOCOL;

/// Verification failures one peer may cause per [`REJECTION_WINDOW`] before its PUTs are dropped unverified.
///
/// Spec: DHT profile §4 — a node SHOULD count rejections per remote peer for rate limiting.
/// Impl: only verification failures count (signature, signer binding, schema, key); `expired`
/// and `replay-window` are what honest replication produces around a record's expiry, so they
/// never throttle a peer. Run 5 of the WAN campaign measured the unthrottled cost: 50 forged
/// PUTs/s took 3–6 % of a core on every honest node.
pub const REJECTION_BUDGET: u32 = 20;
/// The window [`REJECTION_BUDGET`] applies to.
pub const REJECTION_WINDOW: Duration = Duration::from_secs(60);

/// Whether a rejection code counts against the sending peer (see [`REJECTION_BUDGET`]).
fn counts_against_peer(code: &str) -> bool {
    !matches!(code, "expired" | "replay-window")
}

/// Node configuration.
pub struct NodeConfig {
    /// libp2p identity (a `did:key` device seed makes the PeerId derive from the DSIP key).
    pub keypair: identity::Keypair,
    /// Listen addresses.
    pub listen: Vec<Multiaddr>,
    /// Bootstrap peers (`/ip4/…/tcp/…/p2p/<PeerId>`).
    pub bootstrap: Vec<Multiaddr>,
    /// DID documents for `did:web` subjects/signers (hints for `did:key` need none).
    pub resolver: StaticResolver,
    /// How often held records are re-announced.
    pub republish_interval: Duration,
    /// Kademlia query timeout.
    pub query_timeout: Duration,
    /// Serve the overlay (Kademlia server mode). `false` for short-lived clients (`dsip resolve`,
    /// `call`, `answer`): they query and publish but never enter other nodes' routing tables.
    ///
    /// Impl: on the WAN testbed every CLI run joined in server mode and its dead PeerId stayed in
    /// the routing tables (7–17 entries in a 4-node overlay), so publishes and GETs spent their
    /// parallelism on peers that no longer exist.
    pub server: bool,
    /// Where learned peers are kept across restarts (one `/…/p2p/<PeerId>` multiaddr per line).
    ///
    /// Spec: DHT profile §3 — implementations SHOULD persist learned peers across restarts.
    /// Impl: read at start and dialed alongside `bootstrap`; rewritten every republish tick.
    /// On the WAN testbed a restarted bootstrap node with nothing to dial sat with an empty
    /// routing table for minutes, until another node happened to dial it.
    pub peers_file: Option<std::path::PathBuf>,
    /// Where held records are kept across restarts: one JSON line `{"frame", "republish"}` per record.
    ///
    /// Spec: DHT profile §4 — a record is verified at every hop, a node's own disk included.
    /// Impl: rewritten every republish tick; at start every line is evaluated again (signature, expiry, §8.3
    /// against what is already restored) and only what verifies is stored. `republish` marks the records this
    /// node publishes itself, which it keeps re-announcing; the others it only serves.
    pub records_file: Option<std::path::PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            keypair: identity::Keypair::generate_ed25519(),
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr")],
            bootstrap: vec![],
            resolver: StaticResolver::default(),
            republish_interval: Duration::from_secs(60),
            query_timeout: Duration::from_secs(10),
            server: true,
            peers_file: None,
            records_file: None,
        }
    }
}

/// Counters exposed for the findings report.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    /// Records currently held.
    pub stored: usize,
    /// Inbound PUTs accepted.
    pub puts_accepted: u64,
    /// Inbound PUTs rejected, by verdict code.
    pub puts_rejected: BTreeMap<String, u64>,
    /// Inbound PUTs that lost to an existing record (older seq / same-seq conflict).
    pub puts_superseded: u64,
    /// Peers in the routing table.
    pub routing_peers: usize,
    /// Successful outbound publishes.
    pub publishes: u64,
    /// GET queries issued.
    pub gets: u64,
}

/// Result of a GET.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetOutcome {
    /// Subject DID queried.
    pub did: String,
    /// Winning hint, if any verified.
    pub winner: Option<Hint>,
    /// Every record returned, with its verdict (frame, verdict JSON).
    pub candidates: Vec<(String, serde_json::Value)>,
    /// Number of raw records the network returned.
    pub returned: usize,
}

/// Result of a publish.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishOutcome {
    /// Key (hex).
    pub key: String,
    /// Peers that acknowledged (0 when alone; the record is still held locally).
    pub acknowledged: usize,
    /// Verdict of our own evaluation of the record before publishing.
    pub verdict: serde_json::Value,
}

enum Command {
    Publish(String, oneshot::Sender<Result<PublishOutcome>>),
    Get(String, oneshot::Sender<Result<GetOutcome>>),
    /// Test-only: inject a record under an arbitrary DID's key without evaluating it (poisoning experiments).
    PutRaw(String, String, oneshot::Sender<Result<PublishOutcome>>),
    Addrs(oneshot::Sender<Vec<Multiaddr>>),
    Stats(oneshot::Sender<Stats>),
    Shutdown,
}

/// Handle to a running node.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::Sender<Command>,
}

impl Handle {
    /// Publish a signed hint frame.
    pub async fn publish(&self, frame: String) -> Result<PublishOutcome> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::Publish(frame, tx)).await.map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    /// Resolve hints for a DID.
    pub async fn get(&self, did: String) -> Result<GetOutcome> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::Get(did, tx)).await.map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    /// Test-only: put `frame` under `did`'s key with no verification. This is the attacker's
    /// tool for plan §10.3 poisoning runs; honest nodes never call it.
    pub async fn put_raw(&self, did: String, frame: String) -> Result<PublishOutcome> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::PutRaw(did, frame, tx)).await.map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    /// Listen addresses (with `/p2p/<PeerId>`).
    pub async fn addrs(&self) -> Result<Vec<Multiaddr>> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::Addrs(tx)).await.map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))
    }

    /// Counters.
    pub async fn stats(&self) -> Result<Stats> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::Stats(tx)).await.map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))
    }

    /// Stop the node.
    pub async fn shutdown(&self) {
        let _ = self.tx.send(Command::Shutdown).await;
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
}

struct PendingGet {
    did: String,
    frames: Vec<String>,
    reply: oneshot::Sender<Result<GetOutcome>>,
}

struct PendingPut {
    key: String,
    verdict: serde_json::Value,
    reply: oneshot::Sender<Result<PublishOutcome>>,
}

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None })
}

/// Start a node; returns its handle and the PeerId.
pub async fn start(cfg: NodeConfig) -> Result<(Handle, PeerId)> {
    let peer_id = cfg.keypair.public().to_peer_id();
    let resolver = cfg.resolver.clone();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(cfg.keypair.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let mut kcfg = kad::Config::new(StreamProtocol::new(PROTOCOL));
            // Every inbound record is evaluated before it is stored (§8.3 at the storage boundary).
            kcfg.set_record_filtering(kad::StoreInserts::FilterBoth);
            kcfg.set_query_timeout(cfg.query_timeout);
            kcfg.set_record_ttl(Some(Duration::from_secs(6 * 3600)));
            kcfg.set_publication_interval(None); // we re-announce ourselves (republish_interval)
            kcfg.set_replication_interval(Some(Duration::from_secs(120)));
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());
            let mut kad = kad::Behaviour::with_config(key.public().to_peer_id(), store, kcfg);
            kad.set_mode(Some(if cfg.server { kad::Mode::Server } else { kad::Mode::Client }));
            let identify = identify::Behaviour::new(identify::Config::new(PROTOCOL.into(), key.public()));
            Behaviour { kad, identify }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    for addr in &cfg.listen {
        swarm.listen_on(addr.clone()).with_context(|| format!("listen on {addr}"))?;
    }
    // Configured bootstrap peers first, then the peers this node learned before its last restart.
    let mut known: Vec<Multiaddr> = cfg.bootstrap.clone();
    if let Some(f) = &cfg.peers_file {
        known.extend(read_peers(f).into_iter().filter(|a| !cfg.bootstrap.contains(a) && peer_of(a) != Some(peer_id)));
    }
    dial_known(&mut swarm, &known);
    let peers_file = cfg.peers_file.clone();
    let records_file = cfg.records_file.clone();
    // records kept before a restart, verified again before they are served or re-announced
    let mut restored_held: HashMap<Vec<u8>, (String, i64)> = HashMap::new();
    if let Some(f) = &records_file {
        let ctx = Context::new(now_s(), &cfg.resolver);
        let (mut kept, mut dropped) = (0usize, 0usize);
        for line in std::fs::read_to_string(f).unwrap_or_default().lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { dropped += 1; continue };
            let frame = v["frame"].as_str().unwrap_or("").to_string();
            let Some(h) = evaluate(&frame, &ctx, None).hint else { dropped += 1; continue };
            let key = key_for(&h.subject);
            let existing = swarm.behaviour_mut().kad.store_mut().get(&RecordKey::new(&key))
                .and_then(|r| Envelope::from_frame(&String::from_utf8_lossy(&r.value)).ok());
            let ev = evaluate(&frame, &ctx, existing.as_ref());
            if !(ev.verdict.ok() && ev.winner == "input") {
                dropped += 1;
                continue;
            }
            let record = Record { key: RecordKey::new(&key), value: frame.clone().into_bytes(), publisher: None, expires: None };
            let _ = swarm.behaviour_mut().kad.store_mut().put(record);
            if v["republish"] == true {
                restored_held.insert(key, (frame, h.expires_at));
            }
            kept += 1;
        }
        if kept + dropped > 0 {
            tracing::info!("restored {kept} record(s) from {}, dropped {dropped} that no longer verify", f.display());
        }
    }

    let (tx, mut rx) = mpsc::channel::<Command>(64);
    let republish_interval = cfg.republish_interval;
    tokio::spawn(async move {
        let mut listen_addrs: Vec<Multiaddr> = vec![];
        let mut gets: HashMap<QueryId, PendingGet> = HashMap::new();
        let mut puts: HashMap<QueryId, PendingPut> = HashMap::new();
        let mut held: HashMap<Vec<u8>, (String, i64)> = restored_held; // key → (frame, expires_at)
        let mut stats = Stats::default();
        // peer → (window start, verification failures in it)
        let mut rejections: HashMap<PeerId, (std::time::Instant, u32)> = HashMap::new();
        let mut republish = tokio::time::interval(republish_interval);
        republish.tick().await;
        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let full = address.with(libp2p::multiaddr::Protocol::P2p(peer_id));
                        tracing::info!("listening on {full}");
                        listen_addrs.push(full);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        if info.protocols.iter().any(|p| p.as_ref() == PROTOCOL) {
                            for a in routable(info.listen_addrs) {
                                swarm.behaviour_mut().kad.add_address(&peer_id, a);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest {
                        request: kad::InboundRequest::PutRecord { record: Some(record), source, .. } })) => {
                        let now = std::time::Instant::now();
                        if let Some((start, n)) = rejections.get(&source) {
                            if now.duration_since(*start) < REJECTION_WINDOW && *n >= REJECTION_BUDGET {
                                *stats.puts_rejected.entry("rate-limited".into()).or_default() += 1;
                                continue;
                            }
                        }
                        // §8.3 at the storage boundary: verify against the subject, compare with what we hold.
                        let frame = String::from_utf8_lossy(&record.value).into_owned();
                        let existing = swarm.behaviour_mut().kad.store_mut().get(&record.key)
                            .and_then(|r| Envelope::from_frame(&String::from_utf8_lossy(&r.value)).ok());
                        let ctx = Context::new(now_s(), &resolver);
                        let ev = evaluate(&frame, &ctx, existing.as_ref());
                        match (&ev.verdict.ok(), ev.winner, &ev.hint) {
                            (true, "input", Some(h)) => {
                                if record.key.as_ref() != key_for(&h.subject).as_slice() {
                                    *stats.puts_rejected.entry("key-mismatch".into()).or_default() += 1;
                                    tracing::warn!("rejected PUT from {source}: key does not match subject");
                                    charge(&mut rejections, source, now);
                                } else {
                                    let _ = swarm.behaviour_mut().kad.store_mut().put(record);
                                    stats.puts_accepted += 1;
                                }
                            }
                            (true, _, _) => { stats.puts_superseded += 1; }
                            (false, _, _) => {
                                let code = ev.verdict.code.map(|c| serde_json::to_value(c).unwrap().as_str().unwrap_or("?").to_string()).unwrap_or_default();
                                tracing::warn!("rejected PUT from {source}: {code}");
                                if counts_against_peer(&code) {
                                    charge(&mut rejections, source, now);
                                }
                                *stats.puts_rejected.entry(code).or_default() += 1;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) => {
                        match result {
                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(pr))) => {
                                if let Some(g) = gets.get_mut(&id) {
                                    g.frames.push(String::from_utf8_lossy(&pr.record.value).into_owned());
                                }
                            }
                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }))
                            | kad::QueryResult::GetRecord(Err(_)) => {
                                if step.last {
                                    if let Some(g) = gets.remove(&id) {
                                        finish_get(g, &resolver);
                                    }
                                }
                            }
                            kad::QueryResult::PutRecord(res) => {
                                if let Some(p) = puts.remove(&id) {
                                    let acknowledged = match &res {
                                        // Quorum::All asks for K acknowledgements, so a small overlay
                                        // ends in QuorumFailed carrying exactly the peers that stored it.
                                        Ok(_) => kad::K_VALUE.get(),
                                        Err(kad::PutRecordError::QuorumFailed { success, .. }) => success.len(),
                                        Err(_) => 0,
                                    };
                                    stats.publishes += 1;
                                    let _ = p.reply.send(Ok(PublishOutcome { key: p.key, acknowledged, verdict: p.verdict }));
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                },
                cmd = rx.recv() => match cmd {
                    Some(Command::Publish(frame, reply)) => {
                        // §8.3 applies to our own publishes too: never replace a newer record we already hold.
                        let probe = Envelope::from_frame(&frame).ok()
                            .and_then(|e| serde_json::from_slice::<serde_json::Value>(&dsip_core::b64::decode(&e.payload)?).ok())
                            .and_then(|p| p.get("subject").and_then(|s| s.as_str()).map(key_for));
                        let existing = probe.as_ref().and_then(|k| swarm.behaviour_mut().kad.store_mut().get(&RecordKey::new(k))
                            .and_then(|r| Envelope::from_frame(&String::from_utf8_lossy(&r.value)).ok()));
                        let ctx = Context::new(now_s(), &resolver);
                        let ev = evaluate(&frame, &ctx, existing.as_ref());
                        let Some(h) = ev.hint.as_ref() else {
                            let _ = reply.send(Err(anyhow!("refusing to publish an unverifiable hint: {}", ev.to_expect())));
                            continue;
                        };
                        if ev.winner != "input" {
                            let _ = reply.send(Err(anyhow!("refusing to publish: superseded by a record already held ({:?})", ev.conflict)));
                            continue;
                        }
                        let key = key_for(&h.subject);
                        let record = Record { key: RecordKey::new(&key), value: frame.clone().into_bytes(), publisher: None, expires: None };
                        let _ = swarm.behaviour_mut().kad.store_mut().put(record.clone());
                        held.insert(key.clone(), (frame.clone(), h.expires_at));
                        // Impl: Quorum::All, not One. libp2p-kad ends a put as soon as its quorum is met,
                        // so with One the record reached only the first wave of closest peers (on the WAN
                        // testbed: 2 of 4 nodes, never the farthest). All waits for every closest peer.
                        match swarm.behaviour_mut().kad.put_record(record, Quorum::All) {
                            Ok(qid) => { puts.insert(qid, PendingPut { key: hex(&key), verdict: ev.to_expect(), reply }); }
                            Err(e) => { let _ = reply.send(Ok(PublishOutcome { key: hex(&key), acknowledged: 0, verdict: serde_json::json!({"stored_locally_only": e.to_string()}) })); }
                        }
                    }
                    Some(Command::PutRaw(did, frame, reply)) => {
                        let key = key_for(&did);
                        let record = Record { key: RecordKey::new(&key), value: frame.into_bytes(), publisher: None, expires: None };
                        let _ = swarm.behaviour_mut().kad.store_mut().put(record.clone());
                        match swarm.behaviour_mut().kad.put_record(record, Quorum::All) {
                            Ok(qid) => { puts.insert(qid, PendingPut { key: hex(&key), verdict: serde_json::json!({"raw": true}), reply }); }
                            Err(e) => { let _ = reply.send(Ok(PublishOutcome { key: hex(&key), acknowledged: 0, verdict: serde_json::json!({"raw": true, "stored_locally_only": e.to_string()}) })); }
                        }
                    }
                    Some(Command::Get(did, reply)) => {
                        stats.gets += 1;
                        let qid = swarm.behaviour_mut().kad.get_record(RecordKey::new(&key_for(&did)));
                        gets.insert(qid, PendingGet { did, frames: vec![], reply });
                    }
                    Some(Command::Addrs(reply)) => { let _ = reply.send(listen_addrs.clone()); }
                    Some(Command::Stats(reply)) => {
                        let mut s = stats.clone();
                        s.stored = swarm.behaviour_mut().kad.store_mut().records().count();
                        s.routing_peers = swarm.behaviour_mut().kad.kbuckets().map(|b| b.num_entries()).sum();
                        let _ = reply.send(s);
                    }
                    Some(Command::Shutdown) | None => break,
                },
                _ = republish.tick() => {
                    let in_table: usize = swarm.behaviour_mut().kad.kbuckets().map(|b| b.num_entries()).sum();
                    if in_table == 0 {
                        // nobody in the routing table: dial everything this node has ever known (DHT profile §3)
                        dial_known(&mut swarm, &known);
                    } else if let Some(f) = &peers_file {
                        save_peers(f, &mut swarm);
                    }
                    let now = now_s();
                    held.retain(|_, (_, exp)| *exp > now);
                    rejections.retain(|_, (start, _)| start.elapsed() < REJECTION_WINDOW);
                    for (key, (frame, _)) in &held {
                        let record = Record { key: RecordKey::new(key), value: frame.clone().into_bytes(), publisher: None, expires: None };
                        let _ = swarm.behaviour_mut().kad.put_record(record, Quorum::All);
                    }
                    if let Some(f) = &records_file {
                        save_records(f, &mut swarm, &held);
                    }
                }
            }
        }
    });
    Ok((Handle { tx }, peer_id))
}

/// Write every record the store holds as a JSON line, marking the ones this node re-announces itself.
fn save_records(path: &std::path::Path, swarm: &mut libp2p::Swarm<Behaviour>, held: &HashMap<Vec<u8>, (String, i64)>) {
    let mut lines = vec![];
    for r in swarm.behaviour_mut().kad.store_mut().records() {
        let frame = String::from_utf8_lossy(&r.value).into_owned();
        lines.push(serde_json::json!({"frame": frame, "republish": held.contains_key(r.key.as_ref())}).to_string());
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, lines.join("\n") + "\n").and_then(|_| std::fs::rename(&tmp, path)).is_err() {
        tracing::warn!("could not save records to {}", path.display());
    }
}

/// Dial `addrs` (each `/…/p2p/<PeerId>`) and start a Kademlia bootstrap.
fn dial_known(swarm: &mut libp2p::Swarm<Behaviour>, addrs: &[Multiaddr]) {
    for addr in addrs {
        if let Some(peer) = peer_of(addr) {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            let _ = swarm.dial(addr.clone());
        }
    }
    let _ = swarm.behaviour_mut().kad.bootstrap();
}

/// Peers saved by [`save_peers`]; a missing or unreadable file is an empty list.
fn read_peers(path: &std::path::Path) -> Vec<Multiaddr> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse::<Multiaddr>().ok())
        .filter(|a| peer_of(a).is_some())
        .collect()
}

/// Write every routing-table entry's routable addresses as `/…/p2p/<PeerId>` lines.
fn save_peers(path: &std::path::Path, swarm: &mut libp2p::Swarm<Behaviour>) {
    let mut lines = vec![];
    for bucket in swarm.behaviour_mut().kad.kbuckets() {
        for entry in bucket.iter() {
            let peer = *entry.node.key.preimage();
            for a in routable(entry.node.value.iter().cloned().collect()) {
                let full = if peer_of(&a).is_some() { a } else { a.with(libp2p::multiaddr::Protocol::P2p(peer)) };
                lines.push(full.to_string());
            }
        }
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, lines.join("\n") + "\n").and_then(|_| std::fs::rename(&tmp, path)).is_err() {
        tracing::warn!("could not save peers to {}", path.display());
    }
}

/// The listen addresses worth routing to: a peer that advertises any non-loopback address
/// loses its loopback ones.
///
/// Impl: a node listening on 0.0.0.0 advertises 127.0.0.1 too (libp2p expands the wildcard,
/// loopback first). Once that sat in a routing table, a client on a host that runs its own
/// node dialed the loopback address, reached the wrong node, and libp2p gave up on the peer
/// (`WrongPeerId`): on the WAN testbed Bob's client on L2 never stored a hint on L3. A peer
/// that advertises only loopback (a localhost testnet) keeps it.
fn routable(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let loopback = |a: &Multiaddr| {
        a.iter().any(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
            libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
            _ => false,
        })
    };
    if addrs.iter().all(loopback) {
        addrs
    } else {
        addrs.into_iter().filter(|a| !loopback(a)).collect()
    }
}

/// Count one verification failure against `peer`, starting a fresh window when the last one has lapsed.
fn charge(rejections: &mut HashMap<PeerId, (std::time::Instant, u32)>, peer: PeerId, now: std::time::Instant) {
    let e = rejections.entry(peer).or_insert((now, 0));
    if now.duration_since(e.0) >= REJECTION_WINDOW {
        *e = (now, 0);
    }
    e.1 += 1;
    if e.1 == REJECTION_BUDGET {
        tracing::warn!("peer {peer} reached {REJECTION_BUDGET} rejected PUTs in {} s: dropping its PUTs unverified until the window ends",
                       REJECTION_WINDOW.as_secs());
    }
}

fn finish_get(g: PendingGet, resolver: &StaticResolver) {
    let ctx = Context::new(now_s(), resolver);
    let returned = g.frames.len();
    let (winner, candidates) = select(&g.frames, &ctx);
    let _ = g.reply.send(Ok(GetOutcome { did: g.did, winner, candidates, returned }));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_dropped_when_a_public_address_exists() {
        let got = routable(vec![ma("/ip4/127.0.0.1/tcp/4001"), ma("/ip4/139.162.109.138/tcp/4001"), ma("/ip6/::1/tcp/4001")]);
        assert_eq!(got, vec![ma("/ip4/139.162.109.138/tcp/4001")]);
    }

    #[test]
    fn loopback_only_peer_keeps_its_addresses() {
        let addrs = vec![ma("/ip4/127.0.0.1/tcp/4001")];
        assert_eq!(routable(addrs.clone()), addrs);
    }
}
