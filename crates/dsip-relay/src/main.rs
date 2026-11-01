//! `dsip-relay` — the relay binary: flags, the relay's key and certificate, then [`dsip_relay::RelayServer`] on a TLS
//! port.
//!
//! Spec: none (infrastructure)

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use serde_json::Value;
use tokio::net::TcpListener;

use dsip_core::keys::KeyPair;
use dsip_relay::store::QueueStore;
use dsip_relay::{www, RelayConfig, RelayServer};
use dsip_transport::logging::LogTo;
use dsip_transport::tls;

#[derive(Parser)]
#[command(name = "dsip-relay", version, about = "DSIP relay (ws/1.0, forking with leg tracking, store-and-forward within the §13.3 boundary)",
    after_help = "dsip-relay admin --help: operate a running relay (bindings) through its status port")]
struct Args {
    /// TOML config file: each key is one of these flags in snake_case (`config.example.toml`); a flag given here
    /// wins over the file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// DID document JSON files (repeatable) for verifying `did:web` identities that bind here (§8.1: the document is
    /// authoritative). Without them only `did:key` identities can bind.
    #[arg(long)]
    did_document: Vec<PathBuf>,
    /// Do not fetch `did:web` documents over HTTPS (§7.2): only the --did-document files, and `did:key`, verify.
    #[arg(long)]
    no_fetch_did_web: bool,
    /// Seconds a fetched `did:web` document is reused before it is fetched again.
    #[arg(long, default_value_t = dsip_transport::resolver::DidWebResolver::TTL_S)]
    did_web_ttl: u64,
    /// PEM certificates trusted, besides the public web PKI, for fetching `did:web` documents (a private CA).
    #[arg(long)]
    did_web_ca: Option<PathBuf>,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// State directory (relay key seed, self-signed cert/key, the store-and-forward queue `queue.redb`).
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
    /// Serve `GET /status` (JSON; `?detail=1` adds DIDs and sessions), `GET /metrics` (Prometheus) and the admin
    /// commands (`dsip-relay admin`) on this address, plain HTTP: bound devices, sessions, queues, refusals. Keep it
    /// on loopback (`dsipctl relay-status`).
    #[arg(long)]
    status_listen: Option<SocketAddr>,
    /// Wake sleeping devices through their push gateways (Wake Profile, draft): answer `wake-register`, advertise
    /// `wake` in the relay's `hello`, and ask a device's gateway to wake it when an invite is held for it.
    #[arg(long)]
    wake: bool,
    /// A push gateway (its DID) devices may register through (repeatable). None given: any gateway (W§4.2).
    #[arg(long, requires = "wake")]
    wake_gateway: Vec<String>,
    /// Where log lines go: `auto` is journald under systemd, standard error elsewhere. `RUST_LOG` filters.
    #[arg(long, value_enum, default_value_t)]
    log: LogTo,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    if dsip_transport::admin::invoked() {
        return Ok(dsip_transport::admin::run("dsip-relay", dsip_relay::ADMIN_COMMANDS).await);
    }
    let args: Args = dsip_transport::config_file::parse();
    dsip_transport::logging::init(args.log);
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
    // §13.3: what the relay holds for offline recipients survives a restart. Opened before the self-signed
    // certificate is written: scripts that wait for the certificate dial soon after.
    let queue_path = args.state.join("queue.redb");
    let queue_store = Arc::new(QueueStore::open(&queue_path).with_context(|| format!("opening {}", queue_path.display()))?);
    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    hosts.extend(args.host.iter().cloned());
    let (cert, keyfile) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => tls::ensure_self_signed(&args.state, &hosts)?,
    };
    // SIGHUP reads the certificate again (a renewal): new connections get it, bound devices stay bound
    let certs = tls::Certificates::load(&cert, &keyfile)?;
    certs.reload_on_sighup()?;
    dsip_transport::shutdown::exit_on_terminate()?;

    tracing::info!("relay did: {}", key.did());

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
    let resolver = dsip_transport::resolver::build_resolver(&args.did_document, &[]).await?;
    let wake = if args.wake {
        // a gateway's document: the --did-document files, then (unless fetching is off) its did:web document
        let held: Arc<dyn dsip_transport::DidResolver> = Arc::new(resolver.clone());
        let docs: Arc<dyn dsip_transport::DidResolver> = if args.no_fetch_did_web {
            held
        } else {
            let mut web = dsip_transport::DidWebResolver::new();
            if let Some(ca) = &args.did_web_ca {
                web = web.with_ca(&std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?)?;
            }
            Arc::new(dsip_transport::Chain(held, Arc::new(web)))
        };
        let mut client = dsip_transport::wake::WakeClient::new(docs);
        if let Some(ca) = &args.did_web_ca {
            client = client.with_ca(&std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?)?;
        }
        let gateways = (!args.wake_gateway.is_empty()).then(|| args.wake_gateway.clone());
        tracing::info!("waking devices through {} (Wake Profile)", gateways.as_ref().map_or("any gateway".to_string(), |g| g.join(", ")));
        Some(dsip_relay::wake::WakeConfig { client, gateways, store: Some(args.state.join("wake-registrations.json")) })
    } else {
        None
    };
    let cfg = RelayConfig {
        intro_limit: args.intro_limit,
        intro_window: args.intro_window,
        presence_grace: args.presence_grace,
        presence_public: args.presence_public.clone(),
        inbox_cap: args.inbox_cap,
        queue_budget_bytes: args.queue_budget_bytes,
        served,
        offline_retention: args.offline_retention,
        did_web: dsip_transport::resolver::web_documents(!args.no_fetch_did_web, args.did_web_ttl, args.did_web_ca.as_deref())?,
        queue_store: Some(queue_store),
        wake,
    };
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
    // logged once bound: scripts wait for this line before they dial
    if args.cert.is_some() {
        tracing::info!("listening on wss://{}/dsip  (certificate {})", args.listen, cert.display());
    } else {
        tracing::info!("listening on wss://{}/dsip  (clients: --ca {})", args.listen, cert.display());
    }
    relay.serve_tls(listener, certs.acceptor(), routes).await?;
    Ok(ExitCode::SUCCESS)
}
