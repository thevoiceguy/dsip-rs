//! `dsip-node` — run a DSIP hints node: overlay member, Mainline DHT participant, HTTP hints API.
//!
//! Spec: DHT Reachability Hints Profile §10 (v0.11); plan `impl/docs/dsip-node-plan.md` (stage 1: flags only;
//! the config file, state directory, limits and metrics are stages 2–3).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::Multiaddr;

#[derive(Parser)]
#[command(name = "dsip-node", version, about = "DSIP hints node: overlay + Mainline DHT + HTTP hints API (never authoritative, §8.1)")]
struct Args {
    /// HTTP hints API listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http: String,
    /// Overlay listen multiaddr(s); none to stay out of the overlay.
    #[arg(long)]
    overlay_listen: Vec<Multiaddr>,
    /// Overlay bootstrap peer multiaddr(s), with `/p2p/<PeerId>`.
    #[arg(long)]
    overlay_bootstrap: Vec<Multiaddr>,
    /// File keeping learned overlay peers across restarts.
    #[arg(long)]
    overlay_peers_file: Option<std::path::PathBuf>,
    /// Join the Mainline DHT.
    #[arg(long)]
    mainline: bool,
    /// Mainline bootstrap nodes (host:port), comma-separated; default: the public ones.
    #[arg(long, value_delimiter = ',')]
    mainline_bootstrap: Vec<String>,
    /// Mainline UDP port (0: any).
    #[arg(long, default_value_t = 0)]
    mainline_port: u16,
    /// Serve Mainline as a server node (store and answer for others), not only as a client.
    #[arg(long)]
    mainline_server: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn".into()))
        .init();
    let a = Args::parse();
    let (overlay, peer_id) = if a.overlay_listen.is_empty() {
        (None, String::from("-"))
    } else {
        let cfg = dsip_dht::node::NodeConfig {
            listen: a.overlay_listen.clone(),
            bootstrap: a.overlay_bootstrap.clone(),
            peers_file: a.overlay_peers_file.clone(),
            republish_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let (h, id) = dsip_dht::node::start(cfg).await.context("starting the overlay")?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        for addr in h.addrs().await? {
            println!("overlay: {addr}");
        }
        (Some(h), id.to_string())
    };
    let mainline = if a.mainline {
        let mut b = mainline::Dht::builder();
        if !a.mainline_bootstrap.is_empty() {
            b.bootstrap(&a.mainline_bootstrap);
        }
        if a.mainline_port != 0 {
            b.port(a.mainline_port);
        }
        if a.mainline_server {
            b.server_mode();
        }
        let dht = b.build().context("starting the Mainline node")?.as_async();
        let joined = dht.bootstrapped().await;
        println!("mainline: {} {}", dht.info().await.local_addr(), if joined { "joined" } else { "did NOT join" });
        Some(dht)
    } else {
        None
    };
    let node = Arc::new(dsip_node::Node { overlay, mainline, held: Default::default(), peer_id });
    let listener = tokio::net::TcpListener::bind(&a.http).await.with_context(|| format!("binding {}", a.http))?;
    println!("http: {}", listener.local_addr()?);
    axum::serve(listener, dsip_node::router(node)).await?;
    Ok(())
}
