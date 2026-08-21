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
            kad.set_mode(Some(kad::Mode::Server));
            let identify = identify::Behaviour::new(identify::Config::new(PROTOCOL.into(), key.public()));
            Behaviour { kad, identify }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    for addr in &cfg.listen {
        swarm.listen_on(addr.clone()).with_context(|| format!("listen on {addr}"))?;
    }
    for addr in &cfg.bootstrap {
        if let Some(peer) = peer_of(addr) {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            let _ = swarm.dial(addr.clone());
        }
    }
    let _ = swarm.behaviour_mut().kad.bootstrap();

    let (tx, mut rx) = mpsc::channel::<Command>(64);
    let republish_interval = cfg.republish_interval;
    tokio::spawn(async move {
        let mut listen_addrs: Vec<Multiaddr> = vec![];
        let mut gets: HashMap<QueryId, PendingGet> = HashMap::new();
        let mut puts: HashMap<QueryId, PendingPut> = HashMap::new();
        let mut held: HashMap<Vec<u8>, (String, i64)> = HashMap::new(); // key → (frame, expires_at)
        let mut stats = Stats::default();
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
                            for a in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, a);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest {
                        request: kad::InboundRequest::PutRecord { record: Some(record), source, .. } })) => {
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
                                } else {
                                    let _ = swarm.behaviour_mut().kad.store_mut().put(record);
                                    stats.puts_accepted += 1;
                                }
                            }
                            (true, _, _) => { stats.puts_superseded += 1; }
                            (false, _, _) => {
                                let code = ev.verdict.code.map(|c| serde_json::to_value(c).unwrap().as_str().unwrap_or("?").to_string()).unwrap_or_default();
                                tracing::warn!("rejected PUT from {source}: {code}");
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
                                        Ok(_) => 1,
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
                        match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
                            Ok(qid) => { puts.insert(qid, PendingPut { key: hex(&key), verdict: ev.to_expect(), reply }); }
                            Err(e) => { let _ = reply.send(Ok(PublishOutcome { key: hex(&key), acknowledged: 0, verdict: serde_json::json!({"stored_locally_only": e.to_string()}) })); }
                        }
                    }
                    Some(Command::PutRaw(did, frame, reply)) => {
                        let key = key_for(&did);
                        let record = Record { key: RecordKey::new(&key), value: frame.into_bytes(), publisher: None, expires: None };
                        let _ = swarm.behaviour_mut().kad.store_mut().put(record.clone());
                        match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
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
                    let now = now_s();
                    held.retain(|_, (_, exp)| *exp > now);
                    for (key, (frame, _)) in &held {
                        let record = Record { key: RecordKey::new(key), value: frame.clone().into_bytes(), publisher: None, expires: None };
                        let _ = swarm.behaviour_mut().kad.put_record(record, Quorum::One);
                    }
                }
            }
        }
    });
    Ok((Handle { tx }, peer_id))
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
