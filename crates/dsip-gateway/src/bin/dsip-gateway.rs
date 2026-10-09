//! Spec: none (infrastructure) — the daemon wires legs; the normative behaviour is in
//! `dsip-gateway`'s controller and tables, and in `dsip-number` for the number side.
//!
//! `dsip-gateway` daemon: a SIP UAS/UAC on one side, a DSIP identity on the other, the pure controller in between.
//! Round one ran the SIP leg alone (`impl/docs/dsip_gateway_plan.md` G2); stage 4 of the Number Attestation
//! Profile adds the DSIP leg (an `Agent` on a relay) and the number side:
//!
//! - **PSTN → DSIP.** An inbound INVITE's `Identity` header is verified (G§5, N§4.1), the dialled number is routed
//!   by the operator's table or by a binding found on a `dsip-node` (N§6.1), and the DSIP invite carries the G§5
//!   `tel` claim. Nothing routes: `404 identity.unknown`.
//! - **DSIP → PSTN.** A DSIP invite names the number in `destination`; the caller's `tel` claims are checked
//!   against its identity, and the gateway asserts the attested number under its own STIR certificate when it
//!   may (N§4.1), crossing downgraded otherwise (G§7).
//!
//! Media is signalling-only on the DSIP side in this daemon (the in-process `round_trip` test proves the bridge).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use dsip_number::Route;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use dsip_gateway::host::call::{apply, on_dsip_event, on_sip_event, Call, Calls, Legs};
use dsip_gateway::host::media::RtpLeg;
use dsip_gateway::host::numbers::{e164, origid_for, Numbers};
use dsip_gateway::host::sip_leg::{SipEvent, SipLeg};

#[derive(Parser)]
#[command(about = "DSIP↔SIP/PSTN gateway (Gateway Profile 1.0; Number Attestation Profile draft N§4.1, N§6.1)")]
struct Opts {
    /// SIP listen address.
    #[arg(long, default_value = "127.0.0.1:5060")]
    sip_listen: std::net::SocketAddr,
    /// The trunk: where DSIP → PSTN INVITEs go (ip:port).
    #[arg(long)]
    sip_peer: Option<String>,
    /// Local IP advertised in SDP.
    #[arg(long, default_value = "127.0.0.1")]
    local_ip: String,
    /// SIP user for the gateway's own URI (the `From` when a caller's number is not attested).
    #[arg(long, default_value = "gateway")]
    sip_user: String,
    /// The gateway's DSIP identity directory (`dsip identity init`). Without it the SIP leg runs alone (round one).
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Relay URL for the DSIP leg.
    #[arg(long, default_value = "wss://127.0.0.1:8443/dsip")]
    relay: String,
    /// CA certificate (PEM) for the relay's TLS.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// DID documents (repeatable): callers' and callees' documents, resolved locally.
    #[arg(long = "did-document")]
    did_documents: Vec<PathBuf>,
    /// The relying-party binding policy (N§3.2): trust anchors, x5u chains, SPC numbers, status policy.
    #[arg(long)]
    tn_policy: Option<PathBuf>,
    /// The gateway's own STIR certificate: the x5u its chain is served at (with --sti-key; N§4.1).
    #[arg(long)]
    sti_x5u: Option<String>,
    /// The PKCS#8 PEM private key of that chain's leaf.
    #[arg(long)]
    sti_key: Option<PathBuf>,
    /// The operator's routes, `+15551234567=did:web:bob.example` (repeatable; N§6.1).
    #[arg(long = "route")]
    routes: Vec<String>,
    /// dsip-nodes (http://host:port, repeatable) to look dialled numbers up on (N§6 route 1).
    #[arg(long = "tn-node")]
    tn_nodes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "dsip_gateway=info".into()))
        .init();
    let opts = Opts::parse();
    let (sip, mut rx) = SipLeg::new(opts.sip_listen, &opts.local_ip, &opts.sip_user).await?;
    let calls = Arc::new(Mutex::new(Calls::default()));
    let numbers = Numbers::load(opts.tn_policy.as_deref(), opts.sti_x5u.clone(), opts.sti_key.as_deref(), &opts.routes, opts.tn_nodes.clone(), &opts.did_documents)?;
    println!("numbers   {} STI-CA anchor(s), {} x5u chain(s); {} configured route(s); {} node(s)   N§3.2, N§6.1",
             numbers.policy.trust_anchors.len(), numbers.policy.certificates.len(),
             numbers.configured.as_object().map(|o| o.len()).unwrap_or(0), numbers.nodes.len());
    if let Some(g) = &numbers.gateway {
        println!("sti       signing PASSporTs under {} for attested callers   N§4.1 (G§11 path c)", g.x5u);
    }

    let Some(dir) = &opts.identity else {
        tracing::info!("dsip-gateway round one up; SIP leg live. No --identity: the DSIP leg is not run.");
        while let Some(ev) = rx.recv().await {
            if let Err(e) = on_sip_event(&calls, &sip, ev, None).await {
                tracing::warn!("event: {e}");
            }
        }
        return Ok(());
    };
    let id = Identity::load(dir)?;
    println!("gateway   {}  (\"{}\")  device {}", id.meta.identity, id.meta.display_name, id.meta.device);
    let resolver = dsip_transport::resolver::build_resolver(&opts.did_documents, &[]).await?;
    let cfg = AgentConfig {
        relay_url: opts.relay.clone(),
        tls: dsip_transport::tls::client_config(opts.ca.as_deref())?,
        video: false,
        t_establish: None,
        t_ring: None,
        t_ring_local: None,
        first_contact_required: false,
        seal: false,
    };
    let mut agent = Agent::connect(id, cfg, resolver).await?;
    let my_did = agent.identity_did().to_string();
    println!("DSIP leg  on {}  relay {}   §13.2 hello bound", opts.relay, agent.relay().did);
    let trunk = opts.sip_peer.clone();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            Some(ev) = rx.recv() => {
                let r = match ev {
                    SipEvent::Invite { call_id, from_tn, to_user, remote, identity_header } => {
                        inbound_invite(&calls, &sip, &mut agent, &numbers, &opts.local_ip, &my_did, call_id, from_tn, to_user, remote, identity_header).await
                    }
                    ev => on_sip_event(&calls, &sip, ev, Some(&mut agent)).await,
                };
                if let Err(e) = r {
                    tracing::warn!("sip event: {e}");
                }
            }
            events = agent.next() => {
                for ev in events? {
                    if let Err(e) = dsip_event(&calls, &sip, &mut agent, &numbers, &opts.local_ip, trunk.as_deref(), ev).await {
                        tracing::warn!("dsip event: {e}");
                    }
                }
            }
            _ = tick.tick() => {
                agent.tick_and_handle().await?;
            }
        }
    }
}

/// PSTN → DSIP: verify the caller's PASSporT (G§5), route the dialled number (N§6.1), admit or refuse.
#[allow(clippy::too_many_arguments)]
async fn inbound_invite(
    calls: &Arc<Mutex<Calls>>,
    sip: &Arc<SipLeg>,
    agent: &mut Agent,
    numbers: &Numbers,
    local_ip: &str,
    my_did: &str,
    call_id: String,
    from_user: String,
    to_user: String,
    remote: Option<dsip_gateway::host::sip_leg::RemoteRtp>,
    identity_header: Option<String>,
) -> Result<()> {
    let now = dsip_transport::now_s();
    println!("← INVITE   from {from_user} to {to_user}  Identity: {}", if identity_header.is_some() { "present" } else { "none" });
    let pp = numbers.passport(identity_header.as_deref(), &from_user, &to_user, now);
    let from_tn = e164(&from_user).unwrap_or(from_user.clone());
    match (&pp.verified, pp.reason) {
        (true, _) => println!("passport  {from_tn} · STIR attestation {} (verified)   G§5, N§4.1", pp.attest),
        (false, Some(r)) if pp.attest != "none" => println!("passport  {from_tn} · STIR attestation {} (unverified: {r})   G§5", pp.attest),
        (false, r) => println!("passport  {from_tn} · no attestation ({})   G§5", r.unwrap_or("")),
    }
    let to_tn = e164(&to_user).unwrap_or(to_user.clone());
    let target = match numbers.route(&to_tn, now).await {
        Route::Configured(did) => {
            println!("route     {to_tn} → {did}  (configured)   N§6.1");
            did
        }
        Route::Binding(s) => {
            let by = s.attested_by.as_deref().map(|b| format!(", attested by {b}")).unwrap_or_default();
            println!("route     {to_tn} → {}  (binding{by}; the DID claims it back)   N§6.1, N§3.4", s.did);
            if !s.others.is_empty() {
                println!("  ⚠  {to_tn} is also bound to {} — the newer binding is used   N§7", s.others.join(", "));
            }
            s.did
        }
        Route::None => {
            println!("route     {to_tn} → nothing configured, no binding: identity.unknown (404)   N§6.1, G§4.2");
            return sip.reject(&call_id, 404, Some(1), "identity.unknown").await;
        }
    };
    let rtp = RtpLeg::bind(local_ip, 0, rand_ssrc(&call_id)).await?;
    let mut call = Call::inbound_via(&json!({"direction": "inbound", "gateway": my_did}), call_id.clone(), rtp, remote);
    call.dsip_target = Some(target);
    let identity = json!({"attest": pp.attest, "verified": pp.verified});
    let emits = call.step(&json!({"sip": {"request": "INVITE", "from_tn": from_tn, "identity": identity}}));
    apply(&mut call, emits, &mut Legs { sip, dsip: Some(agent) }).await?;
    calls.lock().await.0.insert(call_id, call);
    Ok(())
}

/// An event from the DSIP leg: a new invite (DSIP → PSTN, asserted per N§4.1) or a message on a known session.
#[allow(clippy::too_many_arguments)]
async fn dsip_event(
    calls: &Arc<Mutex<Calls>>,
    sip: &Arc<SipLeg>,
    agent: &mut Agent,
    numbers: &Numbers,
    local_ip: &str,
    trunk: Option<&str>,
    ev: AgentEvent,
) -> Result<()> {
    let AgentEvent::Received { message, identity, payload, .. } = ev else {
        match ev {
            AgentEvent::Rejected(code, detail) => tracing::warn!("rejected inbound frame: {code} {detail}"),
            AgentEvent::Emission(dsip_session::Emission::Refused(reason)) => tracing::warn!("engine refused a local event: {reason}"),
            _ => {}
        }
        return Ok(());
    };
    let sid = message.session_id().to_string();
    let offered = agent.endpoint().session(&sid).map(|s| s.state) == Some(dsip_session::SessionState::Offered);
    if message.msg_type == "invite" && offered {
        return outbound_invite(calls, sip, agent, numbers, local_ip, trunk, &sid, &identity, &payload).await;
    }
    let event = match message.msg_type.as_str() {
        "progress" => json!({"dsip": {"type": "progress"}}),
        "answer" => json!({"dsip": {"type": "answer", "answered_by": message.answered_by}}),
        "reject" => json!({"dsip": {"type": "reject", "reason": message.reason}}),
        "cancel" => json!({"dsip": {"type": "cancel"}}),
        "bye" => json!({"dsip": {"type": "bye", "reason": message.reason}}),
        "error" => {
            println!("← error    from {identity}: {} {}   (in reply to {})", message.reason.clone().unwrap_or_default(),
                     payload.get("detail").map(|d| d.to_string()).unwrap_or_default(), message.in_reply_to.clone().unwrap_or_default());
            return Ok(());
        }
        _ => return Ok(()),
    };
    println!("← {:<8} from {}  session …{}", message.msg_type, identity, &sid[sid.len().saturating_sub(8)..]);
    on_dsip_event(calls, sip, &sid, event, agent).await
}

/// DSIP → PSTN: the destination, the caller's attested number, the PASSporT when entitled (N§4.1), then the dial.
#[allow(clippy::too_many_arguments)]
async fn outbound_invite(
    calls: &Arc<Mutex<Calls>>,
    sip: &Arc<SipLeg>,
    agent: &mut Agent,
    numbers: &Numbers,
    local_ip: &str,
    trunk: Option<&str>,
    sid: &str,
    caller: &str,
    payload: &Value,
) -> Result<()> {
    let destination = payload.get("destination").and_then(Value::as_str).unwrap_or("");
    println!("← invite   from {caller}  destination {}  session …{}", if destination.is_empty() { "(none)" } else { destination }, &sid[sid.len().saturating_sub(8)..]);
    let (Some(to_tn), Some(trunk)) = (destination.strip_prefix("tel:").and_then(e164), trunk) else {
        println!("reject    no PSTN destination (or no --sip-peer trunk): identity.unknown   N§4.1, spec-gap 111");
        return agent.local(dsip_session::LocalEvent::Decline { session: sid.to_string(), reason: Some("identity.unknown".into()) }).await;
    };
    let claims = payload.pointer("/identity/claims").and_then(Value::as_array).cloned().unwrap_or_default();
    let a = numbers.assert(&claims, caller, &to_tn, dsip_transport::now_s(), &origid_for(sid));
    match (&a.from, &a.passport, a.reason) {
        (Some(tn), Some(p), _) => println!("assert    {tn} · PASSporT attest A under {} (orig {}, dest {}, origid {})   N§4.1",
                                            p.header["x5u"].as_str().unwrap_or(""), p.claims["orig"]["tn"], p.claims["dest"]["tn"][0], p.claims["origid"]),
        (Some(tn), None, r) => println!("assert    {tn} presented unsigned ({}) — crossing downgraded identity-not-assertable   N§4.1, G§7", r.unwrap_or("")),
        (None, _, r) => println!("assert    not assertable ({}) — From is the gateway's own; crossing downgraded identity-not-assertable   G§7", r.unwrap_or("")),
    }
    // G§7: name what the crossing loses, on the DSIP leg, before the call goes further (the session continues)
    let facts = json!({"direction": "outbound", "trunk_srtp": false, "identity_assertable": a.passport.is_some(), "policy_present": false});
    if let Some(detail) = dsip_gateway::downgrade_error_detail(&facts) {
        let supported = dsip_core::version::Supported::all_known();
        let err = json!({
            "dsip": dsip_core::version::version_block(&supported, &[dsip_transport::agent::PROFILE]),
            "type": "error", "to": caller, "session": sid,
            "reason": "gateway.downgraded", "detail": detail,
        });
        agent.send_payload(err, 30).await?;
        println!("→ error    gateway.downgraded {}   G§7", detail["losses"]);
    }
    let rtp = RtpLeg::bind(local_ip, 0, rand_ssrc(sid)).await?;
    let mut call = Call::outbound(format!("sip:{to_tn}@{trunk}"), rtp);
    call.dsip_session = Some(sid.to_string());
    call.from_tn = a.from.clone();
    call.identity_header = a.passport.as_ref().map(|p| p.identity_header());
    let emits = call.step(&json!({"dsip": {"type": "invite"}}));
    apply(&mut call, emits, &mut Legs { sip, dsip: Some(agent) }).await?;
    calls.lock().await.0.insert(sid.to_string(), call);
    Ok(())
}

fn rand_ssrc(seed: &str) -> u32 {
    seed.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193))
}
