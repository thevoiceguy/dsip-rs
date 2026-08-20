//! `dsip` — the DSIP PoC command line.
//!
//! Spec: §25.1 "CLI test tool". Subcommands: `keygen`, `sign`, `verify`,
//! `vectors run`. (`resolve`, `call`, `answer` arrive with `dsip-transport`.)

use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{self, Envelope};
use dsip_core::keys::KeyPair;

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

fn main() -> Result<()> {
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
