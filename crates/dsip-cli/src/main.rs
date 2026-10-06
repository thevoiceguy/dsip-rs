//! `dsip` — the DSIP PoC command line.
//!
//! Spec: §25.1 "CLI test tool". Subcommands: `keygen`, `sign`, `verify`,
//! `vectors run`, `identity init|show`, `resolve`, `call`, `answer`.

use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{self, Envelope};
use dsip_core::keys::KeyPair;

mod broadcast_cli;
mod console;
mod hints;
mod pkarr_cli;
mod record_fork;
mod recorder;
mod vectors;

#[derive(Parser)]
#[command(name = "dsip", version, about = "DSIP Core v1.0 proof-of-concept CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an Ed25519 device key and print its did:key (seed to --out as hex).
    Keygen {
        /// Write the 32-byte seed (hex) here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Deterministic fixture key by name (alice, bob-phone, …) instead of random.
        #[arg(long)]
        fixture: Option<String>,
    },
    /// Sign a JSON payload file with a key (seed hex file) and print the envelope frame.
    Sign {
        /// Seed hex file.
        #[arg(long)]
        key: PathBuf,
        /// Payload JSON file.
        payload: PathBuf,
    },
    /// Verify an envelope frame (stages 1–14) and print the verdict and decoded payload.
    Verify {
        /// Envelope JSON file.
        envelope: PathBuf,
        /// Receiver clock (default: now).
        #[arg(long)]
        now: Option<i64>,
        /// Delegation envelope files to present.
        #[arg(long)]
        delegation: Vec<PathBuf>,
        /// DID documents (JSON file mapping did → document).
        #[arg(long)]
        did_documents: Option<PathBuf>,
    },
    /// Conformance vectors.
    Vectors {
        #[command(subcommand)]
        cmd: VectorsCmd,
    },
    /// Identity directories (controller key + device key + delegation).
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Resolve a DID (did:key natively; did:web over HTTPS) and show its DSIP signaling endpoint.
    Resolve {
        /// The DID.
        did: String,
        /// Also consult the DHT hints tier via these bootstrap peers (never authoritative).
        #[arg(long)]
        dht: Vec<libp2p::Multiaddr>,
        /// Also consult these Pkarr relays (DHT Hints Profile §9; never authoritative).
        #[arg(long = "pkarr-relay")]
        pkarr_relays: Vec<String>,
        /// Also consult the Mainline DHT directly (DHT Hints Profile §9; never authoritative).
        #[arg(long)]
        mainline: bool,
        /// Mainline bootstrap node(s) `host:port` (default: Mainline's public bootstrap nodes).
        #[arg(long = "mainline-bootstrap", value_delimiter = ',')]
        mainline_bootstrap: Vec<String>,
    },
    /// Publish this identity's Pkarr pointer to its devices (DHT Hints Profile §9.1), signed by the identity key: the
    /// occasional step (valid up to 7 days) that lets each device publish its own hint.
    PkarrPointer {
        /// Identity directory (its identity key signs).
        #[arg(long)]
        identity: PathBuf,
        /// A device's did:key (repeatable), in the order resolvers should try them.
        #[arg(long = "device", required = true)]
        devices: Vec<String>,
        /// Pointer lifetime in seconds, at most 604,800.
        #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u32).range(60..=604_800))]
        ttl: u32,
        /// Pkarr relays.
        #[arg(long = "pkarr-relay")]
        pkarr_relays: Vec<String>,
        /// Also put it on the Mainline DHT directly.
        #[arg(long)]
        mainline: bool,
        /// Mainline bootstrap nodes.
        #[arg(long = "mainline-bootstrap", value_delimiter = ',')]
        mainline_bootstrap: Vec<String>,
    },
    /// Run a recorder service (Recording Profile C§6): answer recording sessions only and record each stream.
    Recorder {
        /// Identity directory (its delegation should carry `dsip.record`).
        #[arg(long)]
        identity: PathBuf,
        /// Relay URL.
        #[arg(long)]
        relay: String,
        /// CA for the relay's certificate.
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Where recordings and their metadata go.
        #[arg(long)]
        dir: PathBuf,
        /// Media stack.
        #[arg(long, default_value = "forge")]
        media_backend: String,
        /// Run for this many seconds.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Run a local Mainline DHT on 127.0.0.1 for demos and tests (nothing reaches the public DHT); prints its
    /// bootstrap addresses and runs until killed.
    MainlineTestnet {
        /// Number of nodes.
        #[arg(long, default_value_t = 10)]
        nodes: usize,
    },
    /// Place a signed call through a relay (a held grant for the callee is attached automatically).
    Call {
        #[command(flatten)]
        opts: ConnOpts,
        /// Callee identity or device DID.
        #[arg(long)]
        to: String,
    },
    /// Send an introduction (§19.4 first contact) and wait for a grant, a rejection, or silence.
    Introduce {
        #[command(flatten)]
        opts: ConnOpts,
        /// Recipient identity DID.
        #[arg(long)]
        to: String,
        /// Stated purpose (≤ 280 chars; a claim).
        #[arg(long, default_value = "Hello — may I call you?")]
        purpose: String,
        /// Out-of-band contact token issued by the recipient.
        #[arg(long)]
        token: Option<String>,
        /// Seconds to wait for an outcome before treating silence as the answer.
        #[arg(long, default_value_t = 30)]
        wait: u64,
    },
    /// Verified Broadcast (§22) and subscriptions (§9.3).
    Broadcast {
        #[command(subcommand)]
        cmd: BroadcastCmd,
    },
    /// Wait for calls through a relay.
    Answer {
        #[command(flatten)]
        opts: ConnOpts,
        /// Automatic policy: accept | screen | decline | none.
        #[arg(long, default_value = "none")]
        auto: String,
        /// §19.4: reject invites from identities holding no grant (policy.first-contact-required).
        #[arg(long)]
        first_contact: bool,
        /// Pre-authorize a contact token (auto-grants a matching introduction once).
        #[arg(long)]
        token: Vec<String>,
    },
}

#[derive(clap::Args)]
struct BConn {
    /// Identity directory.
    #[arg(long)]
    identity: PathBuf,
    /// Relay URL (the authority).
    #[arg(long, default_value = "wss://127.0.0.1:8443/dsip")]
    relay: String,
    /// Certificate to trust for the relay.
    #[arg(long)]
    ca: Option<PathBuf>,
}

impl BConn {
    fn conn(self) -> broadcast_cli::Conn {
        broadcast_cli::Conn { identity: self.identity, relay: self.relay, ca: self.ca }
    }
}

#[derive(Subcommand)]
enum BroadcastCmd {
    /// Publish a signed publication record for `<identity>:<stream>`.
    Publish {
        #[command(flatten)]
        conn: BConn,
        /// Stream suffix (stream_id = identity DID + ":" + suffix).
        #[arg(long, default_value = "radio:main")]
        stream: String,
        /// Title (a claim).
        #[arg(long, default_value = "Live")]
        title: String,
        /// live | scheduled | ended.
        #[arg(long, default_value = "live")]
        state: String,
        /// Variant `id,codec,transport,uri[,integrity]` (repeatable).
        #[arg(long = "variant")]
        variants: Vec<String>,
        /// Record lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: i64,
        /// Policy `key=value` (repeatable), e.g. transcoding=allowed.
        #[arg(long = "policy")]
        policy: Vec<String>,
    },
    /// Withdraw a publication.
    Unpublish {
        #[command(flatten)]
        conn: BConn,
        /// Stream suffix.
        #[arg(long, default_value = "radio:main")]
        stream: String,
        /// Publication id (default: the last one published from this identity directory).
        #[arg(long)]
        publication: Option<String>,
    },
    /// Subscribe to publication or presence events and verify what arrives.
    Subscribe {
        #[command(flatten)]
        conn: BConn,
        /// Stream id or subject DID.
        #[arg(long)]
        target: String,
        /// Event classes (publication | presence).
        #[arg(long, default_value = "publication")]
        events: Vec<String>,
        /// Requested lifetime (capped per event class).
        #[arg(long, default_value_t = 600)]
        expires_in: i64,
        /// Seconds to listen.
        #[arg(long, default_value_t = 20)]
        wait: u64,
        /// Receiver codecs.
        #[arg(long, default_value = "codec:audio/opus")]
        codec: Vec<String>,
        /// Receiver transports.
        #[arg(long, default_value = "transport:webrtc")]
        transport: Vec<String>,
    },
    /// As a relay/transcoder, attach a signed provenance statement to someone's publication.
    Provenance {
        #[command(flatten)]
        conn: BConn,
        /// Original stream id.
        #[arg(long)]
        stream: String,
        /// Original publication id.
        #[arg(long)]
        publication: String,
        /// transcode | relay | repackage.
        #[arg(long, default_value = "transcode")]
        operation: String,
        /// Input variant id.
        #[arg(long)]
        input: String,
        /// Output variant id.
        #[arg(long)]
        output: String,
        /// Output URI.
        #[arg(long)]
        uri: Option<String>,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Create a new identity directory.
    Init {
        /// Directory.
        #[arg(long)]
        dir: PathBuf,
        /// Display name (a claim, §18.2).
        #[arg(long, default_value = "DSIP user")]
        name: String,
        /// Deterministic vector fixture keys (alice, bob, carol) instead of random.
        #[arg(long)]
        fixture: Option<String>,
        /// Make this a second device of the identity in this directory (reuses its controller key).
        #[arg(long)]
        controller_from: Option<PathBuf>,
        /// Delegate this capability too (repeatable), e.g. `dsip.record` for a recorder (Recording Profile C§1).
        #[arg(long = "capability")]
        capabilities: Vec<String>,
    },
    /// Show an identity directory.
    Show {
        /// Directory.
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(clap::Args)]
struct ConnOpts {
    /// Identity directory.
    #[arg(long)]
    identity: PathBuf,
    /// Relay URL (wss://…). Default wss://127.0.0.1:8443/dsip, or the callee's hint when --dht discovers one.
    #[arg(long)]
    relay: Option<String>,
    /// DHT bootstrap peer(s): join the hints overlay (discover the callee's relay; publish our own with --publish-hint).
    #[arg(long)]
    dht: Vec<libp2p::Multiaddr>,
    /// Publish a signed reachability hint for this identity at the relay we bind to (answer side).
    #[arg(long)]
    publish_hint: bool,
    /// Pkarr relay(s) (https://…): discover the callee's relay from its `_dsip` records (did:key subjects; DHT Hints
    /// Profile §9), or publish our own with --publish-pkarr.
    #[arg(long = "pkarr-relay")]
    pkarr_relays: Vec<String>,
    /// Publish this identity's `_dsip` records to the Pkarr relays, signed by the identity key, and re-publish before
    /// they expire (answer side).
    #[arg(long)]
    publish_pkarr: bool,
    /// Declare this side recorded (Recording Profile C§3) by this recorder identity: every invite, answer and update
    /// carries the signed declaration; change it mid-call with `record on|pause|off`.
    #[arg(long)]
    recorded_by: Option<String>,
    /// With --recorded-by: declare nothing until `record on` (recording begun mid-call, C§3).
    #[arg(long)]
    record_later: bool,
    /// With --recorded-by: open the recorder leg (C§6) from this second device of our identity, forwarding both
    /// voices to the recorder once the call's media flows.
    #[arg(long)]
    record_device: Option<PathBuf>,
    /// The declared recording purpose (C§7 registry: compliance, quality, personal).
    #[arg(long, default_value = "compliance")]
    record_purpose: String,
    /// When the other side declares recording (C§4): `ask` (the user types accept-recording / decline-recording),
    /// `always`, or `never` (decline at once, as `policy.recording: forbidden`).
    #[arg(long, default_value = "ask", value_parser = ["ask", "always", "never"])]
    recording_accept: String,
    /// With --publish-pkarr: publish this **device's** own zone (its endpoint and its delegation, signed by the device
    /// key) instead of the identity's, so the identity key can stay offline (DHT Hints Profile §9.1). The identity
    /// lists its devices once with `dsip pkarr-pointer`.
    #[arg(long)]
    pkarr_device: bool,
    /// Use the Mainline DHT directly for Pkarr (with or without --pkarr-relay): discover the callee's `_dsip` records,
    /// or publish our own with --publish-pkarr. Never authoritative (§8.1).
    #[arg(long)]
    mainline: bool,
    /// Mainline bootstrap node(s) `host:port` (default: Mainline's public bootstrap nodes).
    #[arg(long = "mainline-bootstrap", value_delimiter = ',')]
    mainline_bootstrap: Vec<String>,
    /// Hint lifetime in seconds, at most 3,600 (§12.9, DHT profile §2: nodes reject longer hints).
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(i64).range(3..=dsip_core::HINT_MAX_VALIDITY_S))]
    hint_ttl: i64,
    /// Seal outbound session bodies — SDP, identity claims, DTMF, policy — to the peer's key agreement key
    /// (extension `sealed-body/1.0`, §10.4). Relays then see only routing fields. Inbound sealed bodies open either way.
    #[arg(long)]
    seal: bool,
    /// Media source: `none`, `tone`, `tone:<hz>`, or `file:<path.ogg>`. Anything but none enables WebRTC media.
    #[arg(long, default_value = "none")]
    media: String,
    /// Record inbound audio to this Ogg/Opus file (enables WebRTC media).
    #[arg(long)]
    record: Option<PathBuf>,
    /// STUN server(s) for ICE (none needed on one host).
    #[arg(long)]
    stun: Vec<String>,
    /// TURN server(s) for relay candidates, e.g. `turn:host:3478` — the fallback
    /// when STUN cannot punch a path (symmetric NAT on both ends).
    #[arg(long)]
    turn: Vec<String>,
    /// TURN long-term-credential username (applied to every `--turn`).
    #[arg(long)]
    turn_user: Option<String>,
    /// TURN long-term-credential password (applied to every `--turn`).
    #[arg(long)]
    turn_pass: Option<String>,
    /// Force ICE to use only relay (TURN) candidates — the symmetric-NAT path.
    /// Needs `--turn`; on a single host it forces media through the relay.
    #[arg(long)]
    relay_only: bool,
    /// Media backend: `forge` (default) or `webrtc-rs` (the reference/fallback stack).
    #[arg(long, default_value = "forge")]
    media_backend: String,
    /// Certificate to trust for the relay (self-signed PEM).
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Offer video in invites.
    #[arg(long)]
    video: bool,
    /// Scripted commands, `;`-separated, e.g. "sleep 2; update; sleep 2; hangup; quit".
    #[arg(long)]
    script: Option<String>,
    /// DID document JSON files for the resolver.
    #[arg(long)]
    did_document: Vec<PathBuf>,
    /// T-Establish seconds (5–60).
    #[arg(long)]
    t_establish: Option<i64>,
    /// T-Ring seconds (30–300).
    #[arg(long)]
    t_ring: Option<i64>,
    /// T-Ring-Local seconds (30–300).
    #[arg(long)]
    t_ring_local: Option<i64>,
}

impl ConnOpts {
    fn into_console(self) -> console::ConsoleOpts {
        console::ConsoleOpts {
            identity: self.identity, relay: self.relay, ca: self.ca, video: self.video, script: self.script,
            did_documents: self.did_document, t_establish: self.t_establish, t_ring: self.t_ring, t_ring_local: self.t_ring_local,
            dht: self.dht, publish_hint: self.publish_hint, hint_ttl: self.hint_ttl, seal: self.seal,
            pkarr_relays: self.pkarr_relays, publish_pkarr: self.publish_pkarr, pkarr_device: self.pkarr_device,
            mainline: self.mainline, mainline_bootstrap: self.mainline_bootstrap,
            recorded_by: self.recorded_by, record_later: self.record_later, record_device: self.record_device, fork_taps: None, record_purpose: self.record_purpose, recording_accept: self.recording_accept,
            media: self.media, record: self.record, stun: self.stun,
            turn: self.turn.iter().map(|uri| dsip_media::TurnConfig {
                uri: uri.clone(),
                username: self.turn_user.clone().unwrap_or_default(),
                password: self.turn_pass.clone().unwrap_or_default(),
            }).collect(),
            media_backend: self.media_backend,
            relay_only: self.relay_only,
        }
    }
}

#[derive(Subcommand)]
enum VectorsCmd {
    /// Run the vector suite (Rust side of the parity contract).
    Run {
        /// Vector directory (default: impl/vectors relative to the workspace).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Only vectors whose id starts with this prefix.
        #[arg(long)]
        only: Option<String>,
        /// Write machine-readable results here (for parity diffing).
        #[arg(long)]
        json: Option<PathBuf>,
        /// Print passing vectors too.
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
    ).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out, fixture } => {
            let k = match fixture {
                Some(name) => KeyPair::from_fixture_name(&name),
                None => KeyPair::generate(),
            };
            if let Some(p) = out {
                std::fs::write(&p, hex(&k.seed())).with_context(|| format!("writing {}", p.display()))?;
                println!("seed written to {}", p.display());
            }
            println!("did: {}", k.did());
            println!("kid: {}", k.kid());
        }
        Cmd::Sign { key, payload } => {
            let k = load_key(&key)?;
            let payload: Value = serde_json::from_slice(&std::fs::read(&payload)?)?;
            let env = envelope::sign(&payload, &k, &k.kid());
            println!("{}", env.frame());
        }
        Cmd::Verify { envelope: path, now, delegation, did_documents } => {
            let text = std::fs::read_to_string(&path)?;
            let env = Envelope::from_frame(&text).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
            let resolver = match did_documents {
                Some(p) => StaticResolver::from_json_map(&serde_json::from_slice(&std::fs::read(p)?)?),
                None => StaticResolver::default(),
            };
            let now = now.unwrap_or_else(|| {
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
            });
            let mut ctx = envelope::Context::new(now, &resolver);
            for d in delegation {
                let t = std::fs::read_to_string(&d)?;
                ctx.delegations.push(Envelope::from_frame(&t).map_err(|v| anyhow::anyhow!("{:?}", v.code))?);
            }
            match envelope::verify(&env, &ctx, Some(&text)) {
                Ok(ver) => {
                    let sem = dsip_schema::check_payload(&ver.payload, &dsip_schema::SemanticContext::default());
                    println!("envelope: accept (signer {}, identity {})", ver.signer_did, ver.identity);
                    println!("payload:  {}", serde_json::to_string(&sem.to_expect())?);
                    println!("{}", serde_json::to_string_pretty(&ver.payload)?);
                    if !sem.ok() {
                        std::process::exit(2);
                    }
                }
                Err(v) => {
                    println!("envelope: {}", serde_json::to_string(&v.to_expect())?);
                    if let Some(d) = v.detail {
                        println!("detail: {d}");
                    }
                    std::process::exit(2);
                }
            }
        }
        Cmd::Vectors { cmd: VectorsCmd::Run { dir, only, json, verbose } } => {
            let dir = dir.unwrap_or_else(vectors::default_dir);
            let failures = vectors::run(&dir, only.as_deref(), json.as_deref(), verbose)?;
            if failures > 0 {
                std::process::exit(1);
            }
        }
        Cmd::Identity { cmd: IdentityCmd::Init { dir, name, fixture, controller_from, capabilities } } => {
            let id = dsip_transport::identity::Identity::init_with(&dir, &name, fixture.as_deref(), controller_from.as_deref(), &capabilities)?;
            println!("identity   {}", id.meta.identity);
            println!("device     {}", id.meta.device);
            println!("delegation {}/delegation.json (controller→device, dsip.signaling, 1 year)   §7.4", dir.display());
        }
        Cmd::Identity { cmd: IdentityCmd::Show { dir } } => {
            let id = dsip_transport::identity::Identity::load(&dir)?;
            println!("{}", serde_json::to_string_pretty(&id.meta)?);
            println!("delegation: {}", id.delegation.frame());
        }
        Cmd::MainlineTestnet { nodes } => pkarr_cli::testnet(nodes).await?,
        Cmd::PkarrPointer { identity, devices, ttl, pkarr_relays, mainline, mainline_bootstrap } => {
            let p = pkarr_cli::Pkarr::new(&pkarr_relays, mainline, &mainline_bootstrap).await?
                .context("give --pkarr-relay or --mainline")?;
            p.publish_pointer(&dsip_transport::identity::Identity::load(&identity)?, &devices, ttl).await?;
        }
        Cmd::Recorder { identity, relay, ca, dir, media_backend, seconds } => recorder::run(identity, relay, ca, dir, media_backend, seconds).await?,
        Cmd::Resolve { did, dht, pkarr_relays, mainline, mainline_bootstrap } => {
            if let Some(pk) = dsip_core::did::public_from_did_key(&did) {
                println!("method     did:key (self-certifying; no network resolution)          §7.2, §8.5");
                println!("key        {}", dsip_core::did::multibase_ed25519(&pk));
                println!("kid        {}", dsip_core::did::did_key_kid(&pk));
                println!("authority  the key itself (§8.1 step 2); no DID document ⇒ no authoritative service endpoint");
                if let Some(p) = pkarr_cli::Pkarr::new(&pkarr_relays, mainline, &mainline_bootstrap).await? {
                    if p.discover(&did).await?.is_none() {
                        println!("hint       pkarr: no valid hint found");
                    }
                }
                if dht.is_empty() && pkarr_relays.is_empty() && !mainline {
                    println!("signaling  — (pass --dht, --pkarr-relay or --mainline to consult the hints tier)");
                } else if !dht.is_empty() {
                    let h = hints::join(&dht).await?;
                    hints::discover(&h, &did).await?;
                    h.shutdown().await;
                }
            } else if did.starts_with("did:web:") {
                println!("method     did:web → {}   (depends on DNS + Web PKI, §8.4)", dsip_transport::resolver::did_web_url(&did)?);
                let doc = dsip_transport::resolver::fetch_did_web(&did).await?;
                println!("authority  DID document (§8.1 rule 4)");
                println!("{}", serde_json::to_string_pretty(&doc)?);
                match doc.signaling_uri() {
                    Some(u) => println!("signaling  {u}   (DSIPSignaling, ws/1.0)   §13.2"),
                    None => println!("signaling  none advertised"),
                }
            } else {
                bail!("unsupported DID method in {did} (v1.0 requires did:key and did:web, §7.2)");
            }
        }
        Cmd::Call { opts, to } => finish(console::run(opts.into_console(), console::Mode::Call { to }).await),
        Cmd::Introduce { opts, to, purpose, token, wait } => {
            finish(console::run(opts.into_console(), console::Mode::Introduce { to, purpose, token, wait }).await)
        }
        Cmd::Broadcast { cmd } => {
            let r = match cmd {
                BroadcastCmd::Publish { conn, stream, title, state, variants, ttl, policy } => {
                    let vs: Result<Vec<_>> = if variants.is_empty() {
                        Ok(vec![broadcast_cli::parse_variant("main-opus,codec:audio/opus,transport:webrtc,wss://127.0.0.1:8443/dsip/webrtc/main")?])
                    } else {
                        variants.iter().map(|v| broadcast_cli::parse_variant(v)).collect()
                    };
                    let mut pol = serde_json::Map::new();
                    for kv in policy {
                        if let Some((k, v)) = kv.split_once('=') {
                            pol.insert(k.to_string(), v.into());
                        }
                    }
                    if pol.is_empty() {
                        pol.insert("redistribution".into(), "allowed-with-attribution".into());
                        pol.insert("transcoding".into(), "allowed".into());
                    }
                    broadcast_cli::publish(&conn.conn(), &stream, &title, &state, vs?, ttl, Value::Object(pol)).await
                }
                BroadcastCmd::Unpublish { conn, stream, publication } => broadcast_cli::unpublish(&conn.conn(), &stream, publication).await,
                BroadcastCmd::Subscribe { conn, target, events, expires_in, wait, codec, transport } => {
                    broadcast_cli::subscribe(&conn.conn(), &target, events, expires_in, wait, codec, transport).await
                }
                BroadcastCmd::Provenance { conn, stream, publication, operation, input, output, uri } => {
                    broadcast_cli::provenance(&conn.conn(), &stream, &publication, &operation, &input, &output, uri).await
                }
            };
            finish(r)
        }
        Cmd::Answer { opts, auto, first_contact, token } => {
            finish(console::run(opts.into_console(), console::Mode::Answer { auto, first_contact, tokens: token }).await)
        }
    }
    Ok(())
}

/// Console modes own a blocking stdin reader; exit explicitly so runtime shutdown never waits on it.
fn finish(r: Result<()>) -> ! {
    use std::io::Write as _;
    let code = match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load_key(p: &PathBuf) -> Result<KeyPair> {
    let text = std::fs::read_to_string(p)?;
    let text = text.trim();
    if text.len() != 64 {
        bail!("seed file must hold 64 hex chars");
    }
    let mut seed = [0u8; 32];
    for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
        seed[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(KeyPair::from_seed(seed))
}
