//! Reachability hints on Pkarr relays: publish this identity's `_dsip` records, and discover a callee's relay.
//!
//! Spec: §8.1 (a hint is never authority), §8.3 (the higher seq wins), §8.5; DHT Hints Profile §9 (v0.9,
//! spec-gap 105). The relay HTTP API is Pkarr's: `PUT /<z32>` and `GET /<z32>`, the body a relay payload
//! (`signature ‖ ts ‖ dns`).
//!
//! Impl: relays only — a Pkarr relay writes to and reads from the Mainline DHT itself; direct DHT access (the
//! `mainline` crate) is a later step. The publisher keeps the zone's foreign TXT/A/AAAA records and its timestamp
//! strictly above the previous one (BEP 44's seq); every payload read is checked by `dsip_core::pkarr::read`.

use anyhow::{Context as _, Result};
use dsip_core::pkarr::{self, Hint, PublishEndpoint};
use dsip_transport::identity::Identity;

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?)
}

async fn get(http: &reqwest::Client, relay: &str, z32: &str) -> Option<Vec<u8>> {
    let resp = http.get(format!("{}/{z32}", relay.trim_end_matches('/'))).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.bytes().await.ok().map(|b| b.to_vec())
}

/// Publish this identity's `_dsip` endpoint at `relay_uri` to every Pkarr relay, signed by the identity key.
///
/// Spec: DHT Hints Profile §9 (publishing).
pub async fn publish(relays: &[String], id: &Identity, relay_uri: &str, ttl: u32) -> Result<()> {
    let key = &id.controller;
    let z32 = pkarr::z32_encode(&key.public());
    let http = client()?;
    // one slot per key: start from what is there, keep its foreign records and stay above its timestamp
    let mut prev_ts = 0u64;
    let mut foreign = vec![];
    for r in relays {
        if let Some(p) = get(&http, r, &z32).await.filter(|p| p.len() >= 72) {
            let ts = u64::from_be_bytes(p[64..72].try_into().unwrap_or_default());
            if ts > prev_ts && pkarr::verify_payload(&key.public(), &p) {
                prev_ts = ts;
                let (keep, dropped) = pkarr::foreign_records(&key.public(), &p);
                if dropped > 0 {
                    println!("hint       pkarr: {dropped} foreign record(s) of a type that cannot be carried over were dropped");
                }
                foreign = keep;
            }
        }
    }
    let ts = now_us().max(prev_ts + 1);
    let ep = PublishEndpoint { uri: relay_uri.to_string(), bindings: vec!["ws/1.0".into()], service: None };
    let payload = pkarr::build_payload(key, &[ep], ttl, ts, &foreign).map_err(|e| anyhow::anyhow!(e))?;
    let mut stored = 0;
    for r in relays {
        let resp = http.put(format!("{}/{z32}", r.trim_end_matches('/'))).body(payload.clone()).send().await;
        match resp {
            Ok(resp) if resp.status().is_success() => stored += 1,
            Ok(resp) => println!("hint       pkarr relay {r} refused the publish: {}", resp.status()),
            Err(e) => println!("hint       pkarr relay {r} unreachable: {e}"),
        }
    }
    anyhow::ensure!(stored > 0, "no Pkarr relay stored the hint");
    println!("hint       pkarr published {relay_uri}  seq {ts}  ttl {ttl} s  at {stored} of {} relay(s)   §8.5 signed by the identity key",
             relays.len());
    Ok(())
}

/// Discover `did`'s relay from the Pkarr relays: every relay is asked, every answer read and checked, and the highest
/// seq wins (§8.3). `None` when no relay holds a valid, unexpired hint.
///
/// Spec: §8.3, §8.5; DHT Hints Profile §9 (reading).
pub async fn discover(relays: &[String], did: &str) -> Result<Option<Hint>> {
    let key = dsip_core::did::public_from_did_key(did).context("Pkarr discovery is for did:key subjects")?;
    let z32 = pkarr::z32_encode(&key);
    let http = client()?;
    let mut best: Option<Hint> = None;
    for r in relays {
        let Some(payload) = get(&http, r, &z32).await else { continue };
        match pkarr::read(did, &payload, now_s()) {
            Ok(h) => {
                if best.as_ref().is_none_or(|b| h.seq > b.seq) {
                    best = Some(h);
                }
            }
            Err(e) => println!("hint       pkarr relay {r}: rejected ({})", e.0),
        }
    }
    if let Some(h) = &best {
        let uri = h.endpoints.first().and_then(|e| e["uri"].as_str()).unwrap_or("-");
        println!("hint       pkarr {uri}  seq {}  expires in {} s  signed by the identity key   §8.1 hint, not authority",
                 h.seq, h.expires_at - now_s());
    }
    Ok(best)
}
