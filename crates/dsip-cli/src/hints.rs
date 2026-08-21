//! The hints tier of discovery, as seen from the CLI.
//!
//! Spec: §8.1 — authority order is DID document > alias > cache > hints; this
//! module is the *last* tier and labels everything it returns as hint-sourced.
//! §8.5 — experimental. Plan §10.4 deliverable 1: `dsip resolve` consults the
//! DHT as the hints tier; `answer --publish-hint` publishes signed
//! reachability; `call --dht` discovers a peer's relay with no DNS or Web PKI.

use std::time::Duration;

use anyhow::{Context as _, Result};
use libp2p::Multiaddr;

use dsip_core::envelope::Envelope;
use dsip_dht::node::{start, Handle, NodeConfig};
use dsip_dht::record::{hint_payload, sign_hint, Endpoint, Hint};
use dsip_transport::identity::Identity;
use dsip_transport::now_s;

/// Start an in-process DHT node bootstrapped to `bootstrap` and give the routing table a moment.
pub async fn join(bootstrap: &[Multiaddr]) -> Result<Handle> {
    let cfg = NodeConfig { bootstrap: bootstrap.to_vec(), ..NodeConfig::default() };
    let (handle, peer) = start(cfg).await.context("starting DHT node")?;
    println!("dht        joined as {peer} via {} bootstrap node(s)   §8.5 (experimental; bootstrap is configuration)", bootstrap.len());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    Ok(handle)
}

/// Query the hints tier for `did` and print what came back, clearly labeled.
pub async fn discover(handle: &Handle, did: &str) -> Result<Option<Hint>> {
    let out = handle.get(did.to_string()).await?;
    println!("hints      {} record(s) returned for {}", out.returned, did);
    for (i, (_, verdict)) in out.candidates.iter().enumerate() {
        println!("           [{i}] {verdict}");
    }
    match &out.winner {
        Some(h) => {
            let via = if h.signer == h.subject { "subject key".to_string() } else { format!("delegated device {}", h.signer) };
            println!("hint       {}  seq {}  expires in {} s  signed by {via}", h.endpoints.first().map(|e| e.uri.as_str()).unwrap_or("-"),
                     h.seq, h.expires_at - now_s());
            println!("           ✓ verified against the subject DID — HINT-SOURCED, NOT AUTHORITATIVE (§8.1 rule 6, §8.3)");
        }
        None => println!("hint       none verified"),
    }
    Ok(out.winner.clone())
}

/// Sign and publish a reachability hint for this identity at `relay_uri`.
///
/// `seq` is the issue time, which is monotonic per publisher clock; `ttl` bounds the record's life.
pub async fn publish(handle: &Handle, id: &Identity, relay_uri: &str, ttl_s: i64) -> Result<()> {
    let now = now_s();
    let payload = hint_payload(
        &id.meta.identity,
        &id.meta.identity,
        &[Endpoint { uri: relay_uri.to_string(), bindings: vec!["ws/1.0".into()] }],
        now,
        now,
        ttl_s,
    );
    let env: Envelope = sign_hint(&payload, &id.device, vec![id.delegation.clone()]);
    let out = handle.publish(env.frame()).await?;
    println!("hint       published {} → {relay_uri}  seq {now}  ttl {ttl_s} s  acknowledged by {} peer(s)   §8.3 signed, expiring",
             &out.key[..16], out.acknowledged);
    Ok(())
}
