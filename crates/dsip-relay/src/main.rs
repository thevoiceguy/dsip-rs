//! `dsip-relay` — the relay binary: flags, the relay's key and certificate, then [`dsip_relay::RelayServer`] on a TLS
//! port.
//!
//! Spec: none (infrastructure)

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use serde_json::Value;
use tokio::net::TcpListener;

use dsip_core::keys::KeyPair;
use dsip_relay::{www, RelayConfig, RelayServer};
use dsip_transport::tls;

#[derive(Parser)]
#[command(name = "dsip-relay", version, about = "DSIP relay (ws/1.0, forking with leg tracking, store-and-forward within the §13.3 boundary)")]
struct Args {
    /// DID document JSON files (repeatable) for verifying `did:web` identities that bind here (§8.1: the document is
    /// authoritative). Without them only `did:key` identities can bind.
    #[arg(long)]
    did_document: Vec<PathBuf>,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// State directory (relay key seed, self-signed cert/key).
    #[arg(long, default_value = ".dsip-relay")]
    state: PathBuf,
    /// Extra hostnames for the self-signed certificate.
    #[arg(long)]
    host: Vec<String>,
    /// Introductions allowed per sender identity and per recipient inbox within --intro-window (§19.4 mandatory rate limit).
    #[arg(long, default_value_t = 5)]
    intro_limit: usize,
    /// Rate-limit window in seconds.
    #[arg(long, default_value_t = 3600)]
    intro_window: i64,
    /// T-Presence-Grace: seconds a device's presence record outlives its unbind (P§8: 0–300; 0 drops it at the unbind).
    #[arg(long, default_value_t = dsip_broadcast::authority::PRESENCE_GRACE_S, value_parser = clap::value_parser!(i64).range(0..=300))]
    presence_grace: i64,
    /// An identity whose presence anyone may watch: this relay's own policy for it (P§6 rule 4), as for a broadcaster.
    /// Repeatable. Every other identity's presence is private (P§6, §9.2): watched by its own devices and by subscribers
    /// presenting a grant of its with `dsip.subscribe`.
    #[arg(long = "presence-public")]
    presence_public: Vec<String>,
    /// Maximum queued envelopes per recipient (§13.3 store-and-forward boundary).
    #[arg(long, default_value_t = 100)]
    inbox_cap: usize,
    /// Maximum bytes of queued envelopes across all recipients — the relay's store-and-forward memory budget.
    /// Beyond it new envelopes for offline recipients are refused `transport.routing-refused` (§13.3).
    #[arg(long, default_value_t = 67_108_864)]
    queue_budget_bytes: usize,
    /// Serve only these identities (repeatable): a *private* relay (§13.6). Any verified device may still bind, so
    /// outside parties can reach the served identities, but only traffic to or from a served identity is routed,
    /// envelopes are held only for served identities, and only they may publish here. Unset: an *open* relay that
    /// serves every identity that binds.
    #[arg(long)]
    serve: Vec<String>,
    /// File of identities to serve, one DID per line (`#` comments), added to `--serve`.
    #[arg(long)]
    serve_file: Option<PathBuf>,
    /// Maximum seconds an envelope is held for an offline recipient (advertised as offline_retention_s).
    #[arg(long, default_value_t = 86_400)]
    offline_retention: i64,
    /// Serve static files from this directory on the same TLS port (the browser client; one origin, one cert).
    #[arg(long)]
    www: Option<PathBuf>,
    /// A certificate chain (PEM) for the TLS port, with --key: a deployment's real certificate (§13.2: validated
    /// against the advertised hostname). Without it a self-signed certificate is made in --state.
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// The private key (PEM) for --cert.
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
    /// A JSON file served as `/config.json`: the operator's defaults for the client it serves (`relay`, `nodes`,
    /// `gateway`, `tn_policy`, `ice`, `publish_hint`); the client's own settings override them.
    #[arg(long)]
    client_config: Option<PathBuf>,
    /// ICE server URI(s) (`turn:host:3478`, `stun:host:3478`; repeatable) minted into short-lived credentials at
    /// `/turn` with --turn-secret.
    #[arg(long)]
    turn_uri: Vec<String>,
    /// The secret coturn holds as `static-auth-secret` (TURN REST API credentials). Prefer --turn-secret-file: a
    /// command line is visible to every process on the host.
    #[arg(long, requires = "turn_uri", conflicts_with = "turn_secret_file")]
    turn_secret: Option<String>,
    /// A file holding that secret (trailing whitespace ignored).
    #[arg(long, requires = "turn_uri")]
    turn_secret_file: Option<PathBuf>,
    /// Lifetime of minted TURN credentials, seconds.
    #[arg(long, default_value_t = 3600)]
    turn_ttl: i64,
    /// Forward `/dsip/v1/*` to a hints node at this `host:port` (plain HTTP, DHT Hints Profile §10), so the client
    /// reaches the node through the origin that served it.
    #[arg(long)]
    node_proxy: Option<String>,
    /// Serve `GET /status` (JSON; `?detail=1` adds DIDs and sessions) and `GET /metrics` (Prometheus) on this
    /// address, plain HTTP: bound devices, sessions, queues, refusals. Keep it on loopback (`dsipctl relay-status`).
    #[arg(long)]
    status_listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    ).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.state)?;

    // Relay identity: a did:key from a persisted seed. Spec §7.2 recommends did:web for relays;
    // Impl: did:key keeps the local demo free of DNS/Web PKI; a did:web document can wrap this key.
    let seed_path = args.state.join("relay.key");
    let key = if seed_path.exists() {
        let hex = std::fs::read_to_string(&seed_path)?;
        let mut seed = [0u8; 32];
        for (i, c) in hex.trim().as_bytes().chunks(2).enumerate().take(32) {
            seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
        }
        KeyPair::from_seed(seed)
    } else {
        let k = KeyPair::generate();
        std::fs::write(&seed_path, k.seed().iter().map(|b| format!("{b:02x}")).collect::<String>())?;
        k
    };
    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    hosts.extend(args.host.iter().cloned());
    let (cert, keyfile) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => tls::ensure_self_signed(&args.state, &hosts)?,
    };
    let acceptor = tls::acceptor(&cert, &keyfile)?;

    tracing::info!("relay did: {}", key.did());
    if args.cert.is_some() {
        tracing::info!("listening on wss://{}/dsip  (certificate {})", args.listen, cert.display());
    } else {
        tracing::info!("listening on wss://{}/dsip  (clients: --ca {})", args.listen, cert.display());
    }

    let mut served: HashSet<String> = args.serve.iter().cloned().collect();
    if let Some(path) = &args.serve_file {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        served.extend(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from));
    }
    let served = (!served.is_empty()).then_some(served);
    match &served {
        Some(s) => tracing::info!("private relay: serving {} identities (§13.6)", s.len()),
        None => tracing::info!("open relay: serving every identity that binds (§13.6)"),
    }
    let cfg = RelayConfig {
        intro_limit: args.intro_limit,
        intro_window: args.intro_window,
        presence_grace: args.presence_grace,
        presence_public: args.presence_public.clone(),
        inbox_cap: args.inbox_cap,
        queue_budget_bytes: args.queue_budget_bytes,
        served,
        offline_retention: args.offline_retention,
    };
    let resolver = dsip_transport::resolver::build_resolver(&args.did_document, &[]).await?;
    let relay = RelayServer::new(key, resolver, cfg);
    relay.spawn_clock();
    if let Some(addr) = args.status_listen {
        relay.spawn_status(addr);
    }

    if let Some(w) = &args.www {
        tracing::info!("serving {} at https://{}/", w.display(), args.listen);
    }
    let client_config = match &args.client_config {
        Some(p) => Some(serde_json::from_str::<Value>(&std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
            .with_context(|| format!("parsing {}", p.display()))?),
        None => None,
    };
    let turn_secret = match (&args.turn_secret, &args.turn_secret_file) {
        (Some(s), _) => Some(s.clone()),
        (None, Some(p)) => Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?.trim_end().to_string()),
        (None, None) => None,
    };
    let turn = turn_secret.map(|secret| www::Turn { uris: args.turn_uri.clone(), secret, ttl_s: args.turn_ttl });
    if let Some(t) = &turn {
        tracing::info!("minting TURN credentials for {} at /turn ({} s)", t.uris.join(" "), t.ttl_s);
    }
    if let Some(n) = &args.node_proxy {
        tracing::info!("forwarding /dsip/v1/* to the hints node at {n}");
    }
    let routes = Arc::new(www::Routes { www: args.www.clone(), client_config, turn, node_proxy: args.node_proxy.clone() });
    let listener = TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    Ok(relay.serve_tls(listener, acceptor, routes).await?)
}
