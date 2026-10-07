//! `dsip-node` — run a DSIP hints node: overlay member, Mainline DHT participant, HTTP hints API.
//!
//! Spec: DHT Reachability Hints Profile §10 (v0.11); plan `impl/docs/dsip-node-plan.md`. Configuration is a TOML
//! file (`--config`) whose every key a flag overrides; the state directory keeps the overlay identity, learned peers,
//! held records and Mainline routing nodes, so a restart rejoins at once.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dsip_node::config::{Config, StateDir};
use libp2p::Multiaddr;

#[derive(Parser)]
#[command(name = "dsip-node", version, about = "DSIP hints node: overlay + Mainline DHT + HTTP hints API (never authoritative, §8.1)")]
struct Args {
    /// TOML config file; flags override its keys.
    #[arg(long)]
    config: Option<PathBuf>,
    /// State directory (identity, peers, held records). Without one, nothing survives a restart.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// HTTP hints API listen address [default: 127.0.0.1:8080].
    #[arg(long)]
    http: Option<String>,
    /// Overlay listen multiaddr(s); none to stay out of the overlay.
    #[arg(long)]
    overlay_listen: Vec<Multiaddr>,
    /// Overlay bootstrap multiaddr(s), with `/p2p/<PeerId>`.
    #[arg(long)]
    overlay_bootstrap: Vec<Multiaddr>,
    /// Join the Mainline DHT.
    #[arg(long)]
    mainline: bool,
    /// Mainline bootstrap nodes (host:port), comma-separated; default: the public ones.
    #[arg(long, value_delimiter = ',')]
    mainline_bootstrap: Vec<String>,
    /// Mainline UDP port (0: any).
    #[arg(long)]
    mainline_port: Option<u16>,
    /// Serve Mainline as a server node (store and answer for others), not only as a client.
    #[arg(long)]
    mainline_server: bool,
    /// Ban an overlay peer for this long once it spends its rejection budget [default: 600; 0: never].
    #[arg(long)]
    ban_secs: Option<u64>,
    /// Also refuse a banned peer's IP before the handshake (honest peers behind the same NAT are refused too).
    #[arg(long)]
    ban_ip: bool,
    /// HTTP requests per client IP per minute [default: 120; 0: no limit].
    #[arg(long)]
    http_requests_per_ip_per_min: Option<u32>,
}

fn parse_addrs(v: &[String], what: &str) -> Result<Vec<Multiaddr>> {
    v.iter().map(|a| a.parse::<Multiaddr>().with_context(|| format!("{what}: {a}"))).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn".into()))
        // colour only on a terminal: journald and log files get plain text
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let a = Args::parse();
    let cfg = match &a.config {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    };
    // a flag wins over the file, the file over the default
    let state = match a.state_dir.clone().or(cfg.node.state_dir.clone()) {
        Some(p) => Some(StateDir::open(&p).with_context(|| format!("state directory {}", p.display()))?),
        None => None,
    };
    let http = a.http.clone().or(cfg.http.listen.clone()).unwrap_or_else(|| "127.0.0.1:8080".into());
    let overlay_listen =
        if a.overlay_listen.is_empty() { parse_addrs(&cfg.overlay.listen.clone().unwrap_or_default(), "overlay.listen")? } else { a.overlay_listen.clone() };
    let overlay_bootstrap = if a.overlay_bootstrap.is_empty() {
        parse_addrs(&cfg.overlay.bootstrap.clone().unwrap_or_default(), "overlay.bootstrap")?
    } else {
        a.overlay_bootstrap.clone()
    };
    let mainline_on = a.mainline || cfg.mainline.enabled.unwrap_or(false);
    let mainline_server = a.mainline_server || cfg.mainline.server.unwrap_or(false);
    let mainline_port = a.mainline_port.or(cfg.mainline.port).unwrap_or(0);
    let mainline_bootstrap =
        if a.mainline_bootstrap.is_empty() { cfg.mainline.bootstrap.clone().unwrap_or_default() } else { a.mainline_bootstrap.clone() };

    let (overlay, peer_id) = if overlay_listen.is_empty() {
        (None, String::from("-"))
    } else {
        let keypair = match &state {
            Some(st) => libp2p::identity::Keypair::ed25519_from_bytes(st.overlay_seed()?)?,
            None => libp2p::identity::Keypair::generate_ed25519(),
        };
        let ncfg = dsip_dht::node::NodeConfig {
            keypair,
            listen: overlay_listen,
            bootstrap: overlay_bootstrap,
            peers_file: state.as_ref().map(StateDir::overlay_peers),
            records_file: state.as_ref().map(StateDir::overlay_records),
            ban_secs: a.ban_secs.or(cfg.limits.ban_secs).unwrap_or(600),
            ban_ip: a.ban_ip || cfg.limits.ban_ip.unwrap_or(false),
            republish_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let (h, id) = dsip_dht::node::start(ncfg).await.context("starting the overlay")?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        for addr in h.addrs().await? {
            println!("overlay: {addr}");
        }
        (Some(h), id.to_string())
    };

    let mainline = if mainline_on {
        let mut b = mainline::Dht::builder();
        if !mainline_bootstrap.is_empty() {
            b.bootstrap(&mainline_bootstrap);
        }
        // the routing nodes known before the last restart join the configured bootstrap
        let saved: Vec<String> = state
            .as_ref()
            .and_then(|st| std::fs::read_to_string(st.mainline_nodes()).ok())
            .map(|t| t.lines().map(str::to_string).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        if !saved.is_empty() {
            b.extra_bootstrap(&saved);
        }
        if mainline_port != 0 {
            b.port(mainline_port);
        }
        if mainline_server {
            b.server_mode();
        }
        let dht = b.build().context("starting the Mainline node")?.as_async();
        let joined = dht.bootstrapped().await;
        println!("mainline: {} {} ({} saved node(s))", dht.info().await.local_addr(), if joined { "joined" } else { "did NOT join" },
                 saved.len());
        if let Some(st) = state.clone() {
            let d = dht.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    let nodes = d.to_bootstrap().await;
                    if !nodes.is_empty() {
                        let _ = dsip_node::config::write_atomic(&st.mainline_nodes(), (nodes.join("\n") + "\n").as_bytes());
                    }
                }
            });
        }
        Some(dht)
    } else {
        None
    };

    let mut node = dsip_node::Node::new(overlay, mainline, peer_id, state);
    node.limits = dsip_node::Limits {
        http_per_ip_per_min: a.http_requests_per_ip_per_min.or(cfg.limits.http_requests_per_ip_per_min).unwrap_or(120),
        trust_forwarded_for: cfg.limits.trust_x_forwarded_for.unwrap_or(false),
    };
    let node = Arc::new(node);
    let (kept, dropped) = node.restore().await;
    if kept + dropped > 0 {
        println!("pkarr: restored {kept} packet(s), dropped {dropped} that no longer pass the store check");
    }
    let listener = tokio::net::TcpListener::bind(&http).await.with_context(|| format!("binding {http}"))?;
    println!("http: {}", listener.local_addr()?);
    axum::serve(listener, dsip_node::router(node).into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}
