//! Reachability hints on Pkarr: publish this identity's `_dsip` records, and discover a callee's relay, through
//! Pkarr relays, the Mainline DHT directly, or both.
//!
//! Spec: §8.1 (a hint is never authority), §8.3 (the higher seq wins), §8.5; DHT Hints Profile §9 (v0.9,
//! spec-gap 105). The relay HTTP API is Pkarr's: `PUT /<z32>` and `GET /<z32>`, the body a relay payload
//! (`signature ‖ ts ‖ dns`). On the DHT the same bytes are a BEP 44 mutable item: key, signature, `seq` = ts,
//! `v` = dns, no salt.
//!
//! Impl: relays and the DHT are sources of the same candidates. Every candidate, whatever its source, is read offline
//! by `dsip_core::pkarr::read`, and the highest valid seq wins — the mainline crate's own signature check and
//! "most recent" choice are not relied on. The publisher starts from the highest candidate that verifies under its
//! own key, keeps that packet's foreign TXT/A/AAAA records, and signs a timestamp strictly above it. The DHT put
//! carries no compare-and-swap: the seq order already settles concurrent publishers of one key.

use anyhow::{Context as _, Result};
use dsip_core::pkarr::{self, Hint, PublishEndpoint};
use dsip_transport::identity::Identity;
use futures_util::StreamExt as _;
use mainline::{async_dht::AsyncDht, Dht, MutableItem};
use std::time::Duration;

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// How long a DHT lookup may take before the answers in hand are used.
const DHT_QUERY: Duration = Duration::from_secs(20);

/// Where Pkarr packets are published and looked up: Pkarr relays, a Mainline DHT node, or both.
///
/// Spec: none (infrastructure).
pub struct Pkarr {
    relays: Vec<String>,
    dht: Option<AsyncDht>,
    http: reqwest::Client,
}

/// A Pkarr packet as found, with where it was found.
struct Candidate {
    source: String,
    payload: Vec<u8>,
}

impl Pkarr {
    /// `None` when neither relays nor the DHT were asked for. `bootstrap` empty means Mainline's public bootstrap
    /// nodes.
    pub async fn new(relays: &[String], mainline: bool, bootstrap: &[String]) -> Result<Option<Pkarr>> {
        if relays.is_empty() && !mainline {
            return Ok(None);
        }
        let dht = if mainline {
            let mut b = Dht::builder();
            if !bootstrap.is_empty() {
                b.bootstrap(bootstrap);
            }
            let dht = b.build().context("starting a Mainline DHT node")?.as_async();
            let joined = dht.bootstrapped().await;
            let addr = dht.info().await.local_addr();
            println!("dht        mainline node {addr} {}   (BEP 44; a hints tier, never authority §8.1)",
                     if joined { "joined" } else { "did NOT join — no bootstrap node answered" });
            Some(dht)
        } else {
            None
        };
        let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Some(Pkarr { relays: relays.to_vec(), dht, http }))
    }

    /// Every packet the sources hold for `key`: one per relay, and every distinct item the DHT returns.
    async fn candidates(&self, key: &[u8; 32]) -> Vec<Candidate> {
        let z32 = pkarr::z32_encode(key);
        let mut out = vec![];
        for r in &self.relays {
            let url = format!("{}/{z32}", r.trim_end_matches('/'));
            let Ok(resp) = self.http.get(url).send().await else { continue };
            if resp.status().is_success() {
                if let Ok(b) = resp.bytes().await {
                    out.push(Candidate { source: format!("pkarr relay {r}"), payload: b.to_vec() });
                }
            }
        }
        if let Some(dht) = &self.dht {
            let mut items = dht.get_mutable(key, None, None);
            let deadline = tokio::time::Instant::now() + DHT_QUERY;
            while let Ok(Some(item)) = tokio::time::timeout_at(deadline, items.next()).await {
                let mut payload = item.signature().to_vec();
                payload.extend_from_slice(&(item.seq() as u64).to_be_bytes());
                payload.extend_from_slice(item.value());
                if !out.iter().any(|c| c.payload == payload) {
                    out.push(Candidate { source: "mainline DHT".into(), payload });
                }
            }
        }
        out
    }

    /// Publish this identity's `_dsip` endpoint at `relay_uri` to every source, signed by the identity key.
    ///
    /// Spec: DHT Hints Profile §9 (publishing).
    pub async fn publish(&self, id: &Identity, relay_uri: &str, ttl: u32) -> Result<()> {
        let key = &id.controller;
        let public = key.public();
        let z32 = pkarr::z32_encode(&public);
        // one slot per key: start from the newest packet of our own, keep its foreign records, stay above its ts
        let mut prev_ts = 0u64;
        let mut foreign = vec![];
        for c in self.candidates(&public).await {
            let p = &c.payload;
            if p.len() < 72 || !pkarr::verify_payload(&public, p) {
                continue; // not ours: a relay's or a node's claim cannot move our seq
            }
            let ts = u64::from_be_bytes(p[64..72].try_into().unwrap_or_default());
            if ts > prev_ts {
                prev_ts = ts;
                let (keep, dropped) = pkarr::foreign_records(&public, p);
                if dropped > 0 {
                    println!("hint       pkarr: {dropped} foreign record(s) of a type that cannot be carried over were dropped");
                }
                foreign = keep;
            }
        }
        let ts = now_us().max(prev_ts + 1);
        let ep = PublishEndpoint { uri: relay_uri.to_string(), bindings: vec!["ws/1.0".into()], service: None };
        let payload = pkarr::build_payload(key, &[ep], ttl, ts, &foreign).map_err(|e| anyhow::anyhow!(e))?;
        let mut stored = vec![];
        for r in &self.relays {
            let resp = self.http.put(format!("{}/{z32}", r.trim_end_matches('/'))).body(payload.clone()).send().await;
            match resp {
                Ok(resp) if resp.status().is_success() => stored.push(format!("relay {r}")),
                Ok(resp) => println!("hint       pkarr relay {r} refused the publish: {}", resp.status()),
                Err(e) => println!("hint       pkarr relay {r} unreachable: {e}"),
            }
        }
        if let Some(dht) = &self.dht {
            let sig: [u8; 64] = payload[..64].try_into().expect("64-byte signature");
            let item = MutableItem::new_signed_unchecked(public, sig, &payload[72..], ts as i64, None);
            match dht.put_mutable(item, None).await {
                Ok(_) => stored.push("the mainline DHT".into()),
                Err(e) => println!("hint       mainline DHT put failed: {e}"),
            }
        }
        anyhow::ensure!(!stored.is_empty(), "no Pkarr relay or DHT stored the hint");
        println!("hint       pkarr published {relay_uri}  seq {ts}  ttl {ttl} s  to {}   §8.5 signed by the identity key",
                 stored.join(", "));
        Ok(())
    }

    /// Discover `did`'s relay: every candidate from every source is read and checked offline, and the highest seq
    /// wins (§8.3). `None` when no source holds a valid, unexpired hint.
    ///
    /// Spec: §8.3, §8.5; DHT Hints Profile §9 (reading).
    pub async fn discover(&self, did: &str) -> Result<Option<Hint>> {
        let key = dsip_core::did::public_from_did_key(did).context("Pkarr discovery is for did:key subjects")?;
        let mut best: Option<(Hint, String)> = None;
        for c in self.candidates(&key).await {
            match pkarr::read(did, &c.payload, now_s()) {
                Ok(h) => {
                    if best.as_ref().is_none_or(|(b, _)| h.seq > b.seq) {
                        best = Some((h, c.source));
                    }
                }
                Err(e) => println!("hint       {}: rejected ({})", c.source, e.0),
            }
        }
        if let Some((h, source)) = &best {
            let uri = h.endpoints.first().and_then(|e| e["uri"].as_str()).unwrap_or("-");
            println!("hint       pkarr {uri}  seq {}  expires in {} s  from {source}, signed by the identity key   §8.1 hint, not authority",
                     h.seq, h.expires_at - now_s());
        }
        Ok(best.map(|(h, _)| h))
    }
}

/// `dsip mainline-testnet`: a local Mainline DHT of `nodes` nodes on 127.0.0.1, for demos and tests — nothing reaches
/// the public DHT. Prints `bootstrap <addr>,<addr>,…` and runs until killed.
///
/// Spec: none (infrastructure).
pub async fn testnet(nodes: usize) -> Result<()> {
    let net = mainline::Testnet::builder(nodes).build().context("building the local Mainline testnet")?;
    println!("bootstrap {}", net.bootstrap.join(","));
    tokio::signal::ctrl_c().await?;
    drop(net);
    Ok(())
}
