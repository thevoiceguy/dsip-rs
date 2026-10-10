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
//! Media crosses too: the DSIP leg is a forge-webrtc peer connection per call (SDP in `transports[].sdp`,
//! candidates in signed `info`, §12.12), bridged to the SIP leg's RTP by `host::media::bridge` once both sides are
//! up (§14.1); a caller without media gets a signalling-only crossing.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use dsip_number::Route;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use dsip_gateway::host::call::{apply, on_dsip_event, on_rtp_dtmf, on_sip_event, Call, Calls, Legs};
use dsip_gateway::host::dsip_leg::DsipMedia;
use dsip_gateway::host::media::{bridge, RtpLeg};
use dsip_session::LocalEvent;
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
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(200)); // timers, candidate flushes, bridges
    let mut media = MediaTable::default();
    let (dtmf_tx, mut dtmf_rx) = tokio::sync::mpsc::unbounded_channel::<(String, dsip_gateway::host::media::DtmfEvent)>();

    loop {
        tokio::select! {
            Some(ev) = rx.recv() => {
                let r = match ev {
                    SipEvent::Invite { call_id, from_tn, to_user, remote, identity_header } => {
                        inbound_invite(&calls, &sip, &mut agent, &mut media, &numbers, &opts.local_ip, &my_did, call_id, from_tn, to_user, remote, identity_header).await
                    }
                    ev => {
                        if let SipEvent::Response { call_id, status, remote: Some(r) } = &ev {
                            if (200..300).contains(status) {
                                media.sip_remote(&calls, call_id, r.clone()).await;
                            }
                        }
                        on_sip_event(&calls, &sip, ev, Some(&mut agent)).await
                    }
                };
                if let Err(e) = r {
                    tracing::warn!("sip event: {e}");
                }
            }
            events = agent.next() => {
                for ev in events? {
                    if let Err(e) = dsip_event(&calls, &sip, &mut agent, &mut media, &numbers, &opts.local_ip, trunk.as_deref(), ev).await {
                        tracing::warn!("dsip event: {e}");
                    }
                }
            }
            Some((key, ev)) = dtmf_rx.recv() => {
                if let Err(e) = on_rtp_dtmf(&calls, &sip, &key, ev).await {
                    tracing::warn!("dtmf: {e}");
                }
            }
            _ = tick.tick() => {
                agent.tick_and_handle().await?;
                media.flush_candidates(&mut agent).await;
                media.start_bridges(&calls, &dtmf_tx).await;
                media.drop_ended(&calls).await;
            }
        }
    }
}

/// One call's media on the DSIP side (§12.12, §14.1): the peer connection, the candidates it gathered before the
/// session was ACTIVE, the Opus it receives (fed to the bridge), and whether the bridge has started.
struct CallMedia {
    pc: DsipMedia,
    pending: Vec<Value>,
    gathered: std::sync::Arc<std::sync::Mutex<Vec<forge_webrtc::IceCandidate>>>,
    rtp_tx: tokio::sync::mpsc::UnboundedSender<bytes::Bytes>,
    rtp_in: Option<tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>>,
    sip_remote: Option<dsip_gateway::host::sip_leg::RemoteRtp>,
    bridged: bool,
    end_sent: bool,
}

impl CallMedia {
    /// Start the event pump (candidates to `gathered`, inbound Opus to the bridge). Call once the SDP exchange has
    /// begun; before that forge has no event stream to take.
    fn pump(&mut self) {
        let Some(mut events) = self.pc.take_events() else { return };
        let (g, rtp_tx) = (self.gathered.clone(), self.rtp_tx.clone());
        tokio::spawn(async move {
            let mut n = 0u64;
            while let Some(e) = events.recv().await {
                match e {
                    forge_webrtc::PeerEvent::LocalCandidate(c) => g.lock().unwrap().push(c),
                    forge_webrtc::PeerEvent::Rtp(p) => {
                        n += 1;
                        if n == 1 || n % 200 == 0 {
                            tracing::debug!("peer connection: {n} RTP event(s) from the DSIP leg");
                        }
                        let _ = rtp_tx.send(p.payload.clone());
                    }
                    other => tracing::debug!("peer connection event: {other:?}"),
                }
            }
        });
    }
}

/// Media per DSIP session id.
#[derive(Default)]
struct MediaTable(std::collections::HashMap<String, CallMedia>);

impl MediaTable {
    /// A peer connection for a session. Its event pump starts with [`CallMedia::pump`], after the offer or answer:
    /// forge creates the transport, and with it the event stream, when the SDP exchange begins.
    async fn open(&mut self, sid: &str) -> anyhow::Result<&mut CallMedia> {
        let pc = DsipMedia::new().await?;
        let (rtp_tx, rtp_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        self.0.insert(sid.to_string(), CallMedia { pc, pending: vec![], gathered: Default::default(), rtp_tx, rtp_in: Some(rtp_rx),
                                                  sip_remote: None, bridged: false, end_sent: false });
        Ok(self.0.get_mut(sid).expect("inserted"))
    }

    /// The SIP side answered with its RTP endpoint: remember it for the bridge.
    async fn sip_remote(&mut self, calls: &Arc<Mutex<Calls>>, sip_call_id: &str, r: dsip_gateway::host::sip_leg::RemoteRtp) {
        let guard = calls.lock().await;
        let sid = guard.0.values().find(|c| c.sip_call_id() == Some(sip_call_id)).and_then(|c| c.dsip_session.clone());
        drop(guard);
        if let Some(m) = sid.and_then(|s| self.0.get_mut(&s)) {
            if let Some(rtp) = m.sip_remote.replace(r) {
                let _ = rtp;
            }
        }
    }

    /// §12.12: candidates gathered so far go out in a signed `info` once the session is ACTIVE.
    async fn flush_candidates(&mut self, agent: &mut Agent) {
        for (sid, m) in self.0.iter_mut() {
            if m.end_sent || agent.endpoint().session(sid).map(|s| s.state) != Some(dsip_session::SessionState::Active) {
                continue;
            }
            let fresh: Vec<Value> = std::mem::take(&mut *m.gathered.lock().unwrap()).into_iter()
                .map(|c| json!({"candidate": c.to_sdp_attribute(), "sdp_mid": "0", "sdp_m_line_index": 0})).collect();
            m.pending.extend(fresh);
            if m.pending.is_empty() {
                continue;
            }
            let batch = std::mem::take(&mut m.pending);
            let n = batch.len();
            agent.set_info_data(json!({"candidates": batch, "end_of_candidates": false}));
            if agent.local(LocalEvent::Info { session: sid.clone() }).await.is_ok() {
                println!("media     {n} ICE candidate(s) sent in a signed info   §12.12");
            }
        }
    }

    /// §14.1: once the DSIP media is connected and the SIP side's RTP endpoint is known, bridge the two.
    async fn start_bridges(&mut self, calls: &Arc<Mutex<Calls>>, dtmf: &tokio::sync::mpsc::UnboundedSender<(String, dsip_gateway::host::media::DtmfEvent)>) {
        for (sid, m) in self.0.iter_mut() {
            if m.bridged || !m.pc.connected() {
                continue;
            }
            let guard = calls.lock().await;
            let Some((key, call)) = guard.0.iter().find(|(_, c)| c.dsip_session.as_deref() == Some(sid)) else { continue };
            let Some(rtp) = call.rtp_handle() else { continue };
            let Some(remote) = m.sip_remote.clone().or_else(|| call.remote_rtp_handle()) else { continue };
            let key = key.clone();
            drop(guard);
            // the sender first: taking `rtp_in` before a sender exists would lose it for every later tick
            let Ok(sender) = m.pc.sender() else { continue };
            let Some(rtp_in) = m.rtp_in.take() else { continue };
            rtp.set_remote(remote.addr).await;
            let pcma = remote.payload_types.first() == Some(&8);
            let (dtx, mut drx) = tokio::sync::mpsc::unbounded_channel();
            let (dtmf, key2) = (dtmf.clone(), key.clone());
            tokio::spawn(async move { while let Some(e) = drx.recv().await { let _ = dtmf.send((key2.clone(), e)); } });
            let te = remote.telephone_event;
            tokio::spawn(async move { let _ = bridge(rtp_in, sender, rtp, pcma, te, Some(dtx)).await; });
            m.bridged = true;
            println!("media     bridged: DSIP Opus ⇄ trunk G.711 ({}), RTP to {}   §14.1, G§6", if pcma { "PCMA" } else { "PCMU" }, remote.addr);
        }
    }

    /// Close the media of sessions whose call has ended, and drop the ended calls from the table.
    async fn drop_ended(&mut self, calls: &Arc<Mutex<Calls>>) {
        let mut guard = calls.lock().await;
        let live: std::collections::HashSet<String> = guard.0.values().filter(|c| !c.ended()).filter_map(|c| c.dsip_session.clone()).collect();
        let ended: Vec<String> = guard.0.iter().filter(|(_, c)| c.ended()).map(|(k, _)| k.clone()).collect();
        for k in ended {
            guard.0.remove(&k);
        }
        drop(guard);
        let gone: Vec<String> = self.0.keys().filter(|k| !live.contains(*k)).cloned().collect();
        for k in gone {
            if let Some(mut m) = self.0.remove(&k) {
                m.pc.close();
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
    media: &mut MediaTable,
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
    // the gateway offers media toward the DSIP callee (§16.3): a peer connection per call, its SDP in the invite
    let sid_placeholder = format!("sip:{call_id}");
    match media.open(&sid_placeholder).await {
        Ok(m) => match m.pc.offer().await {
            Ok(offer) => {
                m.pump();
                call.offer_sdp = Some(offer); // set on the agent right before place_call (one pending slot)
            }
            Err(e) => tracing::warn!("media offer: {e}"),
        },
        Err(e) => tracing::warn!("media: {e}"),
    }
    let emits = call.step(&json!({"sip": {"request": "INVITE", "from_tn": from_tn, "identity": identity}}));
    apply(&mut call, emits, &mut Legs { sip, dsip: Some(agent) }).await?;
    if let (Some(sid), Some(m)) = (call.dsip_session.clone(), media.0.remove(&sid_placeholder)) {
        media.0.insert(sid, m); // now keyed by the session the invite got
    }
    calls.lock().await.0.insert(call_id, call);
    Ok(())
}

/// An event from the DSIP leg: a new invite (DSIP → PSTN, asserted per N§4.1) or a message on a known session.
#[allow(clippy::too_many_arguments)]
async fn dsip_event(
    calls: &Arc<Mutex<Calls>>,
    sip: &Arc<SipLeg>,
    agent: &mut Agent,
    media: &mut MediaTable,
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
        return outbound_invite(calls, sip, agent, media, numbers, local_ip, trunk, &sid, &identity, &payload).await;
    }
    // §16.3 / §12.12: the callee's SDP answer, and candidates in signed info, reach our peer connection
    if let Some(m) = media.0.get_mut(&sid) {
        if message.msg_type == "answer" {
            if let Some(sdp) = payload.pointer("/transports/0/sdp").and_then(Value::as_str) {
                if let Err(e) = m.pc.set_answer(sdp).await {
                    tracing::warn!("media answer: {e}");
                } else {
                    println!("media     remote WebRTC answer applied   §16.3");
                }
            }
        }
        if message.msg_type == "info" && payload["about"] == "transport:webrtc" {
            let cands = payload["data"]["candidates"].as_array().cloned().unwrap_or_default();
            for c in &cands {
                if let Some(s) = c["candidate"].as_str() {
                    m.pc.add_candidate(s).await.ok();
                }
            }
            println!("media     {} remote ICE candidate(s) applied from signed info   §12.12", cands.len());
            return Ok(());
        }
    }
    let event = match message.msg_type.as_str() {
        "progress" => json!({"dsip": {"type": "progress"}}),
        "answer" => json!({"dsip": {"type": "answer", "answered_by": message.answered_by}}),
        "reject" => json!({"dsip": {"type": "reject", "reason": message.reason}}),
        "cancel" => json!({"dsip": {"type": "cancel"}}),
        "bye" => json!({"dsip": {"type": "bye", "reason": message.reason}}),
        // G§9: DTMF from the DSIP caller crosses as a signed info about media:dtmf (the transport:webrtc infos were
        // handled above); the controller refuses any other `about`
        "info" => json!({"dsip": {"type": "info", "about": payload["about"], "data": payload["data"]}}),
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
    media: &mut MediaTable,
    numbers: &Numbers,
    local_ip: &str,
    trunk: Option<&str>,
    sid: &str,
    caller: &str,
    payload: &Value,
) -> Result<()> {
    let destination = payload.get("destination").and_then(Value::as_str).unwrap_or("");
    println!("← invite   from {caller}  destination {}  session …{}", if destination.is_empty() { "(none)" } else { destination }, &sid[sid.len().saturating_sub(8)..]);
    // the destination is a tel: E.164 URI (spec-gap 111): a local number without its `+` is not dialled under a guessed
    // country code, it is declined
    let (Some(to_tn), Some(trunk)) = (destination.strip_prefix("tel:").filter(|d| d.starts_with('+')).and_then(e164), trunk) else {
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
    // the caller's SDP offer (§16.3): answer it with a peer connection of our own, the SDP riding in our answer
    let mut answer_sdp: Option<String> = None;
    if let Some(offer) = payload.pointer("/transports/0/sdp").and_then(Value::as_str) {
        match media.open(sid).await {
            Ok(m) => match m.pc.answer(offer).await {
                Ok(answer) => {
                    m.pump();
                    answer_sdp = Some(answer);
                    println!("media     WebRTC answer prepared for the caller's offer   §16.3");
                }
                Err(e) => tracing::warn!("media answer: {e}"),
            },
            Err(e) => tracing::warn!("media: {e}"),
        }
    }
    let rtp = RtpLeg::bind(local_ip, 0, rand_ssrc(sid)).await?;
    let mut call = Call::outbound(format!("sip:{to_tn}@{trunk}"), rtp);
    call.dsip_session = Some(sid.to_string());
    call.answer_sdp = answer_sdp; // set on the agent right before accept (one pending slot, §16.3)
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
