//! The host loop: one `dsip-transport::Agent` and one `SipLeg`, a controller per call, wiring
//! events from each leg into `GatewayCall::step` and its emissions back out to real legs.
//!
//! Spec: none (infrastructure) — the normative decisions are all in [`crate::controller`]; this
//! is the plumbing that turns `{sip: …}` / `{dsip: …}` emissions into method calls on the legs
//! and media bridges. Round one: one outbound and one inbound call shape, audio only.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
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
    #[allow(dead_code)]
    dsip_session: Option<String>,
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
}

/// Apply one controller emission list to the real legs. `key` is the call table key.
pub async fn apply(call: &mut Call, emits: Vec<Value>, legs: &Legs<'_>) -> Result<()> {
    for e in emits {
        if let Some(sip) = e.get("sip") {
            apply_sip(call, sip, legs).await?;
        } else if e.get("media").is_some() {
            // Media bridging is started by the host's media pump when both legs are up (round-trip
            // harness / daemon); the controller's `media` emission only marks readiness.
            call.media_ready = true;
        } else if let Some(dsip) = e.get("dsip") {
            // Inbound direction: the controller tells the DSIP side to place a call / answer /
            // reject. In a full host these become `Agent` local events; round one logs them so the
            // trace is visible and the SIP side (the exercised half of G2) drives to completion.
            info!("dsip emit: {dsip}");
        }
    }
    Ok(())
}

async fn apply_sip(call: &mut Call, s: &Value, legs: &Legs<'_>) -> Result<()> {
    let Some(cid) = &call.sip_call_id else {
        // An outbound INVITE has no Call-ID yet: the string form "INVITE" triggers the dial.
        if s == "INVITE" {
            let rtp = call.rtp.as_ref().expect("rtp allocated before invite");
            let sdp = super::sip_leg::local_sdp(legs.sip.local_ip(), rtp.port(), "sendrecv");
            let target = call.dial_target.clone().unwrap_or_default();
            let cid = legs.sip.invite(&target, &sdp).await?;
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
        apply(call, emits, &Legs { sip }).await?;
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
        }
    }

    /// A fresh inbound (PSTN→DSIP) call.
    pub fn inbound(sip_call_id: String, rtp: Arc<RtpLeg>, remote: Option<RemoteRtp>) -> Call {
        Call {
            ctrl: GatewayCall::new(&json!({"direction": "inbound"})),
            dsip_session: None,
            sip_call_id: Some(sip_call_id),
            media: None,
            rtp: Some(rtp),
            remote_rtp: remote,
            media_ready: false,
            dial_target: None,
            last_sip_request: None,
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
}

/// A helper the SIP receive loop uses: find the call whose SIP Call-ID matches and step it.
pub async fn on_sip_event(calls: &Arc<Mutex<Calls>>, sip: &Arc<SipLeg>, ev: SipEvent) -> Result<()> {
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
        apply(call, emits, &Legs { sip }).await?;
    }
    Ok(())
}

fn find_by_sip(calls: &Calls, sip_call_id: &str) -> Option<String> {
    calls.0.iter().find(|(_, c)| c.sip_call_id() == Some(sip_call_id)).map(|(k, _)| k.clone())
}
