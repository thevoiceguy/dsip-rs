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

mod console;
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
    },
    /// Place a signed call through a relay.
    Call {
        #[command(flatten)]
        opts: ConnOpts,
        /// Callee identity or device DID.
        #[arg(long)]
        to: String,
    },
    /// Wait for calls through a relay.
    Answer {
        #[command(flatten)]
        opts: ConnOpts,
        /// Automatic policy: accept | screen | decline | none.
        #[arg(long, default_value = "none")]
        auto: String,
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
    /// Relay URL (wss://…).
    #[arg(long, default_value = "wss://127.0.0.1:8443/dsip")]
    relay: String,
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
        Cmd::Identity { cmd: IdentityCmd::Init { dir, name, fixture, controller_from } } => {
            let id = dsip_transport::identity::Identity::init(&dir, &name, fixture.as_deref(), controller_from.as_deref())?;
            println!("identity   {}", id.meta.identity);
            println!("device     {}", id.meta.device);
            println!("delegation {}/delegation.json (controller→device, dsip.signaling, 1 year)   §7.4", dir.display());
        }
        Cmd::Identity { cmd: IdentityCmd::Show { dir } } => {
            let id = dsip_transport::identity::Identity::load(&dir)?;
            println!("{}", serde_json::to_string_pretty(&id.meta)?);
            println!("delegation: {}", id.delegation.frame());
        }
        Cmd::Resolve { did } => {
            if let Some(pk) = dsip_core::did::public_from_did_key(&did) {
                println!("method     did:key (self-certifying; no network resolution)          §7.2, §8.5");
                println!("key        {}", dsip_core::did::multibase_ed25519(&pk));
                println!("kid        {}", dsip_core::did::did_key_kid(&pk));
                println!("signaling  — (did:key documents carry no service endpoints; reachability comes from hints or out-of-band)");
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
        Cmd::Call { opts, to } => console::run(opts.into_console(), console::Mode::Call { to }).await?,
        Cmd::Answer { opts, auto } => console::run(opts.into_console(), console::Mode::Answer { auto }).await?,
    }
    Ok(())
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
