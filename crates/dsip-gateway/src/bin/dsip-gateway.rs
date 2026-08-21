//! Spec: none (infrastructure) — the daemon wires legs; the normative behaviour is in
//! `dsip-gateway`'s controller and tables.
//!
//! `dsip-gateway` daemon (round one): a SIP UAS/UAC on one side, a DSIP identity on the other,
//! the pure controller in between. This binary wires the legs; the protocol lives in the library.
//!
//! Round-one scope matches `impl/docs/dsip_gateway_plan.md` G2: a demo-grade daemon that runs the
//! SIP leg for real against siphond and hosts the controller. The DSIP leg's `Agent` wiring is
//! present as a library (`host::dsip_leg`); the daemon exercises the SIP half end to end.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::Mutex;

use dsip_gateway::host::call::{on_sip_event, Calls};
use dsip_gateway::host::sip_leg::SipLeg;

#[derive(Parser)]
#[command(about = "DSIP↔SIP/PSTN gateway (Phase 4, round one)")]
struct Opts {
    /// SIP listen address.
    #[arg(long, default_value = "127.0.0.1:5060")]
    sip_listen: std::net::SocketAddr,
    /// Local IP advertised in SDP.
    #[arg(long, default_value = "127.0.0.1")]
    local_ip: String,
    /// SIP user for the gateway's own URI.
    #[arg(long, default_value = "gateway")]
    sip_user: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "dsip_gateway=info".into())).init();
    let opts = Opts::parse();
    let (sip, mut rx) = SipLeg::new(opts.sip_listen, &opts.local_ip, &opts.sip_user).await?;
    let calls = Arc::new(Mutex::new(Calls::default()));
    tracing::info!("dsip-gateway round one up; SIP leg live. DSIP leg is library-only in this build.");
    while let Some(ev) = rx.recv().await {
        if let Err(e) = on_sip_event(&calls, &sip, ev).await {
            tracing::warn!("event: {e}");
        }
    }
    Ok(())
}
