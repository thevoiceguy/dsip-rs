//! The host loop: one `dsip-transport::Agent` and one `SipLeg`, a controller per call, wiring
//! events from each leg into `GatewayCall::step` and its emissions back out to real legs.
//!
//! Spec: none (infrastructure) — the normative decisions are all in [`crate::controller`]; this
//! is the plumbing that turns `{sip: …}` / `{dsip: …}` emissions into method calls on the legs
//! and media bridges. Round one: one outbound and one inbound call shape, audio only. Stage 4 of the
//! Number Attestation Profile wires the DSIP leg (an `Agent`) so the `{dsip: …}` emissions act: the
//! gateway places, alerts, answers, declines and hangs up DSIP sessions as the controller says.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use dsip_session::LocalEvent;
use dsip_transport::agent::Agent;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::info;

use crate::controller::GatewayCall;
use super::dsip_leg::DsipMedia;
use super::media::{DtmfEvent, RtpLeg};
use super::sip_leg::{RemoteRtp, SipEvent, SipLeg};

/// A live call: its controller, DSIP session id, SIP Call-ID, and media handles.
pub struct Call {
    ctrl: GatewayCall,
    /// The DSIP session id, once the DSIP leg has one.
    pub dsip_session: Option<String>,
    /// Inbound (PSTN → DSIP): the DID the controller's `place_call` invites (N§6.1).
    pub dsip_target: Option<String>,
    /// Outbound (DSIP → PSTN): the `From` user to present, when the caller's number was attested (N§4.1).
    pub from_tn: Option<String>,
    /// Outbound: the RFC 8224 `Identity` header value, when the gateway signed a PASSporT (N§4.1).
    pub identity_header: Option<String>,
    sip_call_id: Option<String>,
    media: Option<DsipMedia>,
    rtp: Option<Arc<RtpLeg>>,
    remote_rtp: Option<RemoteRtp>,
    /// The controller has signalled both legs are up.
    pub media_ready: bool,
    dial_target: Option<String>,
    /// The last SIP request the leg reported; the leg answers BYE, CANCEL and INFO itself, so the
    /// controller's `response` emission for those is not sent again (a `response` otherwise answers the INVITE).
    last_sip_request: Option<String>,
}

/// The gateway's live-call table, one per direction-initiating event.
#[derive(Default)]
pub struct Calls(pub HashMap<String, Call>);

/// Emit-handling context passed to `apply`.
pub struct Legs<'a> {
    /// The SIP leg.
    pub sip: &'a Arc<SipLeg>,
    /// The DSIP leg, when the host runs one (the daemon does; the round-trip test drives the DSIP side itself).
    pub dsip: Option<&'a mut Agent>,
}

/// Apply one controller emission list to the real legs. `key` is the call table key.
pub async fn apply(call: &mut Call, emits: Vec<Value>, legs: &mut Legs<'_>) -> Result<()> {
    for e in emits {
        if let Some(sip) = e.get("sip") {
            apply_sip(call, sip, legs).await?;
        } else if e.get("media").is_some() {
            // Media bridging is started by the host's media pump when both legs are up (round-trip
            // harness / daemon); the controller's `media` emission only marks readiness.
            call.media_ready = true;
        } else if let Some(dsip) = e.get("dsip") {
            match legs.dsip.as_deref_mut() {
                Some(agent) => apply_dsip(call, dsip, agent).await?,
                // No DSIP leg (the round-trip harness): log the emission so the trace is visible.
                None => info!("dsip emit: {dsip}"),
            }
        }
    }
    Ok(())
}

/// The controller's `{dsip: {local: …}}` emission as an `Agent` local event (§12 engine vocabulary).
///
/// Spec: G§3.1–G§3.2 (the DSIP leg actions per crossing event), §14.1 (`answered_by: gateway`).
async fn apply_dsip(call: &mut Call, d: &Value, agent: &mut Agent) -> Result<()> {
    let local = d.get("local").and_then(Value::as_str).unwrap_or("");
    if local == "place_call" {
        let Some(target) = call.dsip_target.clone() else { return Ok(()) };
        let claims = d.get("claims").and_then(Value::as_array).cloned().unwrap_or_default();
        agent.set_claims(claims);
        let sid = agent.place_call(&target).await?;
        println!("→ invite   to {target}  session …{}  (G§5 claim: {})", &sid[sid.len().saturating_sub(8)..], d.get("trust_basis").and_then(Value::as_str).unwrap_or(""));
        call.dsip_session = Some(sid);
        return Ok(());
    }
    let Some(session) = call.dsip_session.clone() else { return Ok(()) };
    let reason = d.get("reason").and_then(Value::as_str).map(String::from);
    let offered = agent.endpoint().session(&session).map(|s| s.state) == Some(dsip_session::SessionState::Offered);
    println!("→ dsip     {local}{}", reason.as_deref().map(|r| format!(" {r}")).unwrap_or_default());
    let ev = match local {
        "alert" => LocalEvent::Alert { session, ring_timeout: Some(60) },
        "accept" => {
            if offered {
                // the SIP side answered without ringing first: the §12 engine alerts before it answers
                agent.local(LocalEvent::Alert { session: session.clone(), ring_timeout: Some(60) }).await?;
            }
            LocalEvent::Accept { session, answered_by: Some("gateway".into()) } // §14.1
        }
        // a pre-answer refusal with the G§4 reason: `auto_reject` is the engine's own event for an offered session
        "auto_reject" if offered => LocalEvent::AutoReject { session, reason: reason.unwrap_or_else(|| "session.failed".into()) },
        "auto_reject" => LocalEvent::Decline { session, reason },
        "cancel" => LocalEvent::Cancel { session },
        "hangup" => LocalEvent::Hangup { session, reason },
        _ => {
            info!("dsip emit not carried by this host: {d}");
            return Ok(());
        }
    };
    agent.local(ev).await
}

async fn apply_sip(call: &mut Call, s: &Value, legs: &mut Legs<'_>) -> Result<()> {
    let Some(cid) = &call.sip_call_id else {
        // An outbound INVITE has no Call-ID yet: the string form "INVITE" triggers the dial.
        if s == "INVITE" {
            let rtp = call.rtp.as_ref().expect("rtp allocated before invite");
            let sdp = super::sip_leg::local_sdp(legs.sip.local_ip(), rtp.port(), "sendrecv");
            let target = call.dial_target.clone().unwrap_or_default();
            let cid = legs.sip.invite_from(&target, &sdp, call.from_tn.as_deref(), call.identity_header.as_deref()).await?;
            println!("→ INVITE   {target}  From {}  Identity: {}", call.from_tn.as_deref().unwrap_or("(the gateway's own)"),
                     if call.identity_header.is_some() { "SHAKEN PASSporT" } else { "none" });
            call.sip_call_id = Some(cid);
        }
        return Ok(());
    };
    match s {
        Value::String(k) if k == "ACK" => legs.sip.ack(cid, 200).await?,
        Value::String(k) if k == "CANCEL" => legs.sip.cancel(cid).await?,
        Value::String(k) if k == "INVITE" => {}
        Value::Object(o) => {
            if let Some(code) = o.get("response").and_then(Value::as_u64) {
                if call.last_sip_request.as_deref().is_some_and(|r| matches!(r, "BYE" | "CANCEL" | "INFO")) {
                    // answered by the leg on receipt; nothing to send
                } else if code == 100 { /* trying already sent by the leg */ }
                else if code == 180 { legs.sip.ringing(cid).await?; }
                else if (200..300).contains(&code) {
                    let rtp = call.rtp.as_ref().expect("rtp");
                    let dir = o.get("direction").and_then(Value::as_str).unwrap_or("sendrecv");
                    let sdp = super::sip_leg::local_sdp(legs.sip.local_ip(), rtp.port(), dir);
                    legs.sip.accept(cid, &sdp).await?;
                } else if code >= 300 {
                    let q = o.get("q850").and_then(Value::as_u64).map(|c| c as u32);
                    let reason = o.get("reason_header").and_then(|r| r.get("text")).and_then(Value::as_str).unwrap_or("gateway.mapped");
                    legs.sip.reject(cid, code as u16, q, reason).await?;
                }
            } else if let Some(req) = o.get("request").and_then(Value::as_str) {
                if req == "BYE" {
                    let q = o.get("q850").and_then(Value::as_u64).map(|c| c as u32);
                    let reason = o.get("reason_header").and_then(|r| r.get("text")).and_then(Value::as_str).unwrap_or("user.hangup");
                    legs.sip.bye(cid, q, reason).await?;
                } else if req == "INFO" {
                    let digits = o.get("dtmf").and_then(Value::as_str).unwrap_or("");
                    send_dtmf(legs.sip, call.rtp.as_ref(), call.remote_rtp.as_ref(), cid, digits, o.get("duration_ms").and_then(Value::as_u64)).await?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}


/// Put DTMF from the DSIP leg on the SIP side: RFC 4733 events when the trunk negotiated `telephone-event`
/// and the RTP leg is up, otherwise INFO dtmf-relay.
///
/// Spec: G§9 allows either carriage. Impl (spec-gap 70): RTP events are preferred when negotiated — they
/// are what trunks interoperate on; INFO dtmf-relay is the fallback for a trunk that offered no
/// `telephone-event`.
pub async fn send_dtmf(
    sip: &Arc<SipLeg>,
    rtp: Option<&Arc<RtpLeg>>,
    remote: Option<&RemoteRtp>,
    sip_call_id: &str,
    digits: &str,
    duration_ms: Option<u64>,
) -> Result<()> {
    match (rtp, remote.and_then(|r| r.telephone_event)) {
        (Some(rtp), Some(pt)) => {
            let ms = duration_ms.unwrap_or(super::sip_leg::DTMF_DEFAULT_DURATION_MS);
            for d in digits.chars() {
                rtp.send_event(d, ms, pt).await?;
            }
            Ok(())
        }
        _ => sip.info_dtmf(sip_call_id, digits, duration_ms).await,
    }
}

/// A DTMF event the media bridge decoded from the trunk's RTP (G§9): the controller sees it as a SIP-side
/// event with nothing to answer.
pub async fn on_rtp_dtmf(calls: &Arc<Mutex<Calls>>, sip: &Arc<SipLeg>, key: &str, ev: DtmfEvent) -> Result<()> {
    let mut guard = calls.lock().await;
    let event = json!({"sip": {"event": "dtmf", "dtmf": ev.digits, "duration_ms": ev.duration_ms}});
    let emits = guard.0.get_mut(key).map(|c| c.step(&event)).unwrap_or_default();
    if let Some(call) = guard.0.get_mut(key) {
        apply(call, emits, &mut Legs { sip, dsip: None }).await?;
    }
    Ok(())
}

impl Call {
    /// A fresh outbound (DSIP→PSTN) call.
    pub fn outbound(dial_target: String, rtp: Arc<RtpLeg>) -> Call {
        Call {
            ctrl: GatewayCall::new(&json!({"direction": "outbound"})),
            dsip_session: None,
            sip_call_id: None,
            media: None,
            rtp: Some(rtp),
            remote_rtp: None,
            media_ready: false,
            dial_target: Some(dial_target),
            last_sip_request: None,
            dsip_target: None,
            from_tn: None,
            identity_header: None,
        }
    }

    /// A fresh inbound (PSTN→DSIP) call.
    pub fn inbound(sip_call_id: String, rtp: Arc<RtpLeg>, remote: Option<RemoteRtp>) -> Call {
        Self::inbound_via(&json!({"direction": "inbound"}), sip_call_id, rtp, remote)
    }

    /// A fresh inbound call with the controller's context given: `{"direction": "inbound", "gateway": <our DID>}`
    /// names this gateway as the `verifier` of the G§5 claim.
    pub fn inbound_via(ctx: &Value, sip_call_id: String, rtp: Arc<RtpLeg>, remote: Option<RemoteRtp>) -> Call {
        Call {
            ctrl: GatewayCall::new(ctx),
            dsip_session: None,
            sip_call_id: Some(sip_call_id),
            media: None,
            rtp: Some(rtp),
            remote_rtp: remote,
            media_ready: false,
            dial_target: None,
            last_sip_request: None,
            dsip_target: None,
            from_tn: None,
            identity_header: None,
        }
    }

    /// Step the controller with a raw event and return the emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        self.ctrl.step(ev)
    }
}

// dial_target lives on Call; declared here to keep the struct literal above readable.
impl Call {
    /// Attach media (peer connection + rtp) once known.
    pub fn set_media(&mut self, media: DsipMedia) {
        self.media = Some(media);
    }
    /// Record the remote RTP endpoint from a SIP SDP.
    pub fn set_remote_rtp(&mut self, r: Option<RemoteRtp>) {
        self.remote_rtp = r;
    }
    /// The SIP Call-ID, if assigned.
    pub fn sip_call_id(&self) -> Option<&str> {
        self.sip_call_id.as_deref()
    }
    /// The SIP-side RTP leg, for the daemon's bridge.
    pub fn rtp_handle(&self) -> Option<Arc<RtpLeg>> {
        self.rtp.clone()
    }
    /// The trunk's RTP endpoint, when its SDP has been seen.
    pub fn remote_rtp_handle(&self) -> Option<RemoteRtp> {
        self.remote_rtp.clone()
    }
    /// Whether the controller has ended both legs.
    pub fn ended(&self) -> bool {
        let s = self.ctrl.snapshot();
        s["dsip"] == "ended" && matches!(s["sip"].as_str(), Some("terminated") | Some("idle"))
    }
}

/// A helper the SIP receive loop uses: find the call whose SIP Call-ID matches and step it. `dsip` is the DSIP
/// leg, when the host runs one. An INVITE for a call the table does not hold is left alone: the daemon admits
/// inbound calls itself (N§6.1 routing) before stepping them.
pub async fn on_sip_event(calls: &Arc<Mutex<Calls>>, sip: &Arc<SipLeg>, ev: SipEvent, dsip: Option<&mut Agent>) -> Result<()> {
    let mut guard = calls.lock().await;
    let (key, event): (Option<String>, Value) = match &ev {
        SipEvent::Response { call_id, status, remote } => {
            if let Some(r) = remote {
                for c in guard.0.values_mut() {
                    if c.sip_call_id() == Some(call_id.as_str()) {
                        c.set_remote_rtp(Some(r.clone()));
                    }
                }
            }
            (find_by_sip(&guard, call_id), json!({"sip": {"status": status, "sdp": remote.is_some()}}))
        }
        SipEvent::Invite { call_id, from_tn, .. } => (Some(call_id.clone()), json!({"sip": {"request": "INVITE", "from_tn": from_tn}})),
        SipEvent::Bye { call_id, q850 } => (find_by_sip(&guard, call_id), json!({"sip": {"request": "BYE", "q850": q850}})),
        SipEvent::Cancel { call_id } => (find_by_sip(&guard, call_id), json!({"sip": {"request": "CANCEL"}})),
        SipEvent::Ack { call_id } => (find_by_sip(&guard, call_id), json!({"sip": {"request": "ACK"}})),
        SipEvent::Info { call_id, digits, duration_ms } => {
            let mut s = json!({"request": "INFO", "dtmf": digits});
            if let Some(ms) = duration_ms {
                s["duration_ms"] = json!(ms);
            }
            (find_by_sip(&guard, call_id), json!({"sip": s}))
        }
    };
    let Some(key) = key else { return Ok(()) };
    if let Some(c) = guard.0.get_mut(&key) {
        c.last_sip_request = event["sip"]["request"].as_str().map(String::from);
    }
    let emits = guard.0.get_mut(&key).map(|c| c.step(&event)).unwrap_or_default();
    if let Some(call) = guard.0.get_mut(&key) {
        apply(call, emits, &mut Legs { sip, dsip }).await?;
    }
    Ok(())
}

/// Step the call that owns DSIP session `sid` with a `{dsip: …}` event and apply the emissions to both legs.
pub async fn on_dsip_event(calls: &Arc<Mutex<Calls>>, sip: &Arc<SipLeg>, sid: &str, event: Value, dsip: &mut Agent) -> Result<()> {
    let mut guard = calls.lock().await;
    let Some(key) = find_by_session(&guard, sid) else { return Ok(()) };
    let emits = guard.0.get_mut(&key).map(|c| c.step(&event)).unwrap_or_default();
    if let Some(call) = guard.0.get_mut(&key) {
        apply(call, emits, &mut Legs { sip, dsip: Some(dsip) }).await?;
    }
    Ok(())
}

fn find_by_sip(calls: &Calls, sip_call_id: &str) -> Option<String> {
    calls.0.iter().find(|(_, c)| c.sip_call_id() == Some(sip_call_id)).map(|(k, _)| k.clone())
}

/// The table key of the call whose DSIP session is `sid`.
pub fn find_by_session(calls: &Calls, sid: &str) -> Option<String> {
    calls.0.iter().find(|(_, c)| c.dsip_session.as_deref() == Some(sid)).map(|(k, _)| k.clone())
}
