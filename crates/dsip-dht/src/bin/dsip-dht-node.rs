//! `dsip-dht-node` — run one hints-overlay node with a control port.
//!
//! Spec: §8.5 (experimental DHT discovery); plan §10.2.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libp2p::{identity, Multiaddr};
use tokio::net::TcpListener;

use dsip_core::did::StaticResolver;
use dsip_dht::node::{start, NodeConfig};

#[derive(Parser)]
#[command(name = "dsip-dht-node", version, about = "DSIP reachability-hints DHT node (experimental)")]
struct Args {
    /// Listen multiaddr(s).
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    listen: Vec<Multiaddr>,
    /// Bootstrap peer multiaddr(s) with `/p2p/<PeerId>`.
    #[arg(long)]
    bootstrap: Vec<Multiaddr>,
    /// Control port (JSON lines).
    #[arg(long, default_value = "127.0.0.1:0")]
    control: String,
    /// 32-byte hex seed for a deterministic PeerId.
    #[arg(long)]
    seed: Option<String>,
    /// DID document JSON files for did:web subjects.
    #[arg(long)]
    did_document: Vec<PathBuf>,
    /// Re-announce interval in seconds.
    #[arg(long, default_value_t = 60)]
    republish: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn".into()))
        .init();
    let args = Args::parse();
    let keypair = match &args.seed {
        Some(hex) => {
            let mut seed = [0u8; 32];
            for (i, c) in hex.as_bytes().chunks(2).enumerate().take(32) {
                seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
            }
            identity::Keypair::ed25519_from_bytes(seed)?
        }
        None => identity::Keypair::generate_ed25519(),
    };
    let mut resolver = StaticResolver::default();
    for f in &args.did_document {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(f)?)?;
        resolver.insert(serde_json::from_value(v)?);
    }
    let cfg = NodeConfig {
        keypair,
        listen: args.listen.clone(),
        bootstrap: args.bootstrap.clone(),
        resolver,
        republish_interval: Duration::from_secs(args.republish),
        ..NodeConfig::default()
    };
    let (handle, peer_id) = start(cfg).await?;
    let control = TcpListener::bind(&args.control).await?;
    println!("peer: {peer_id}");
    println!("control: {}", control.local_addr()?);
    tokio::time::sleep(Duration::from_millis(200)).await;
    for a in handle.addrs().await? {
        println!("listening: {a}");
    }
    dsip_dht::control::serve(control, handle).await
}
