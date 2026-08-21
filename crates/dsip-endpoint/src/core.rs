//! The endpoint core: inbound verification → `dsip_session::Endpoint` → outbound payloads.
//!
//! Spec: §12 (the engine decides *what* to send), §14.2 (offer in invite,
//! selection in answer), §14.4 (screening: constrained `recvonly` selection),
//! §16.2–§16.3 (codec objects; SDP as a transport binding object under
//! `transport:webrtc`), §12.12 (`info` with `about: transport:webrtc` carries
//! ICE candidates), §19.4 (introduction/grant payloads), §7.4 (our delegation
//! rides in every header so peers learn and verify our identity — spec-gap 8).
//!
//! Impl (spec-gap 16): the WebRTC Media Binding document referenced by §12.12
//! and §16.3 does not exist yet. This core carries the SDP offer/answer as
//! `transports[].sdp` on `invite`/`update`/`answer` and trickle candidates as
//! `info.data.candidates` in the shape of the §12.12 example.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign_bytes, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::{version_block, Supported};
use dsip_session::endpoint::Grant;
use dsip_session::event::SendMsg;
use dsip_session::{Emission, Endpoint, EndpointConfig, Event, LocalEvent, Message};

use crate::verify::{verify_frame, SeenIds};

/// Interactive Media Profile identifier. Spec: §17.
pub const PROFILE: &str = "interactive-media/1.0";

/// Key material and claims of this endpoint.
#[derive(Clone)]
pub struct IdentityKeys {
    /// Controller DID (the identity).
    pub identity: String,
    /// Device key: signs everything on the wire.
    pub device: KeyPair,
    /// Controller→device delegation (§7.4), presented inline in every header.
    pub delegation: Envelope,
    /// Display name — a claim (§18.2).
    pub display_name: String,
}

/// Core configuration.
#[derive(Debug, Clone, Default)]
pub struct CoreConfig {
    /// Offer video in invites.
    pub video: bool,
    /// Timer overrides (seconds).
    pub t_establish: Option<i64>,
    /// T-Ring override.
    pub t_ring: Option<i64>,
    /// T-Ring-Local override.
    pub t_ring_local: Option<i64>,
    /// §19.4: reject invites from identities holding no grant.
    pub first_contact_required: bool,
}

/// Persisted first-contact state.
///
/// Spec: §19.4 — "The recipient's endpoint and relay record the grant; the grantee also holds the signed grant."
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ContactFile {
    /// Identities admitted without a grant.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Grants we issued.
    #[serde(default)]
    pub grants_issued: std::collections::BTreeMap<String, Grant>,
    /// Grants we hold.
    #[serde(default)]
    pub grants_held: std::collections::BTreeMap<String, Grant>,
    /// Learned device → identity mapping.
    #[serde(default)]
    pub identities: std::collections::BTreeMap<String, String>,
}

/// What the core hands back to its host.
#[derive(Debug)]
pub enum CoreEvent {
    /// Transmit this frame.
    Send {
        /// The exact text frame (one `ws/1.0` message).
        frame: String,
        /// Message type.
        msg_type: String,
        /// Session (or message id for session-less types).
        session: String,
        /// Destination DID.
        to: String,
    },
    /// An engine emission other than a send (timers, ui, media, drops, refusals).
    Emission(Emission),
    /// A verified inbound message was handed to the engine.
    Received {
        /// Abbreviated message.
        message: Message,
        /// The signer's identity (subject of a presented, valid delegation; else the signer).
        identity: String,
        /// `identity.display_name` claim, if any.
        display_name: Option<String>,
        /// The full decoded payload (hosts read SDP / candidates from it).
        payload: Value,
    },
    /// An inbound frame was rejected.
    Rejected {
        /// Verdict code (kebab-case).
        code: String,
        /// Human detail.
        detail: String,
    },
}

/// The core.
pub struct Core {
    keys: IdentityKeys,
    cfg: CoreConfig,
    supported: Supported,
    resolver: StaticResolver,
    ep: Endpoint,
    seen: SeenIds,
    /// Offers by session id (invite) or update id, ours and theirs.
    offers: HashMap<String, Value>,
    peer_delegations: Vec<Envelope>,
    pending_sdp: Option<String>,
    /// `identity.claims` to put on the next invite (a gateway's PSTN caller claim, §18.1).
    pending_claims: Vec<Value>,
    pending_info_data: Option<Value>,
    counter: u64,
}

impl Core {
    /// Create a core at clock `now` (seconds).
    pub fn new(keys: IdentityKeys, cfg: CoreConfig, resolver: StaticResolver, now: i64) -> Core {
        let mut c = EndpointConfig::from_vector(&json!({
            "self": {"device": keys.device.did(), "identity": keys.identity},
            "start": now,
        }));
        if let Some(t) = cfg.t_establish {
            c.t_establish = t.clamp(5, 60);
        }
        if let Some(t) = cfg.t_ring {
            c.t_ring = t.clamp(30, 300);
        }
        if let Some(t) = cfg.t_ring_local {
            c.t_ring_local = t.clamp(30, 300);
        }
        c.first_contact_required = cfg.first_contact_required;
        Core {
            keys,
            cfg,
            supported: Supported::all_known(),
            resolver,
            ep: Endpoint::new(c),
            seen: SeenIds::default(),
            offers: HashMap::new(),
            peer_delegations: vec![],
            pending_sdp: None,
            pending_claims: vec![],
            pending_info_data: None,
            counter: 0,
        }
    }

    /// Our keys.
    pub fn keys(&self) -> &IdentityKeys {
        &self.keys
    }

    /// Supported versions.
    pub fn supported(&self) -> &Supported {
        &self.supported
    }

    /// The engine.
    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    /// The engine, mutably (contacts seeding).
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.ep
    }

    /// Sign an application-built payload (publish, subscribe, provenance, …) with the device key,
    /// filling `id`/`from`/`issued_at`/`expires_at` when absent. A preset `from` equal to our identity
    /// is kept: the header delegation then binds the device signature to the identity (§7.4, spec-gap 8).
    pub fn sign_payload(&mut self, mut p: Value, now: i64, ttl: i64) -> Result<String> {
        if p.get("id").is_none() {
            p["id"] = self.new_id(now).into();
        }
        if p.get("from").and_then(Value::as_str) != Some(self.keys.identity.as_str()) {
            p["from"] = self.keys.device.did().into();
        }
        if p.get("issued_at").is_none() {
            p["issued_at"] = now.into();
        }
        if p.get("expires_at").is_none() {
            p["expires_at"] = (now + ttl).into();
        }
        Ok(sign_bytes(&serde_json::to_vec(&p)?, &self.keys.device, &self.keys.device.kid(), vec![self.keys.delegation.clone()]).frame())
    }

    /// A fresh ULID at `now` (seconds), unique within the second.
    pub fn new_id(&mut self, now: i64) -> String {
        self.counter = (self.counter + 1) % 1000;
        Ulid::generate_at((now as u64) * 1000 + self.counter).to_string()
    }

    /// SDP to embed in the next `invite`/`update`/`answer` transport descriptor (consumed on use).
    pub fn set_sdp(&mut self, sdp: Option<String>) {
        self.pending_sdp = sdp;
    }

    /// Claims for the next invite's `identity.claims` (§18.1: claims, never badges — e.g. a
    /// gateway's `tel` claim about a PSTN caller).
    pub fn set_claims(&mut self, claims: Vec<Value>) {
        self.pending_claims = claims;
    }

    /// `data` object for the next `info` (consumed on use).
    pub fn set_info_data(&mut self, data: Value) {
        self.pending_info_data = Some(data);
    }

    /// Pending introductions (id → identity).
    pub fn requests(&self) -> Vec<(String, String)> {
        self.ep.contacts.requests.iter().map(|(k, (i, _))| (k.clone(), i.clone())).collect()
    }

    // ------------------------------------------------------------ persistence

    /// Seed first-contact state.
    pub fn load_contacts(&mut self, file: &ContactFile) {
        for a in &file.allow {
            self.ep.contacts.allow.insert(a.clone());
        }
        self.ep.contacts.grants_issued = file.grants_issued.clone();
        self.ep.contacts.grants_held = file.grants_held.clone();
        for (d, i) in &file.identities {
            self.ep.learn_identity(d, i);
        }
    }

    /// Export first-contact state.
    pub fn contacts(&self) -> ContactFile {
        ContactFile {
            allow: self.ep.contacts.allow.iter().cloned().collect(),
            grants_issued: self.ep.contacts.grants_issued.clone(),
            grants_held: self.ep.contacts.grants_held.clone(),
            identities: self.ep.identities().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    // ------------------------------------------------------------ driving

    /// Advance the engine clock to `now`; due timers fire.
    pub fn tick(&mut self, now: i64) -> Result<Vec<CoreEvent>> {
        let delta = now - self.ep.now;
        if delta <= 0 {
            return Ok(vec![]);
        }
        let em = self.ep.step(&Event::Advance { advance: delta });
        self.handle(em, now)
    }

    /// A local request.
    pub fn local(&mut self, ev: LocalEvent, now: i64) -> Result<Vec<CoreEvent>> {
        let mut out = self.tick(now)?;
        let em = self.ep.step(&Event::Local(ev));
        out.extend(self.handle(em, now)?);
        Ok(out)
    }

    /// A frame arrived.
    pub fn inbound(&mut self, frame: &str, now: i64) -> Result<Vec<CoreEvent>> {
        let mut out = self.tick(now)?;
        let sem = dsip_schema::SemanticContext { supported: self.supported.clone(), ..Default::default() };
        let inbound = match verify_frame(frame, now, &self.resolver, &self.peer_delegations, &mut self.seen, &sem) {
            Ok(i) => i,
            Err(v) => {
                out.push(CoreEvent::Rejected {
                    code: v.code.map(|c| serde_json::to_value(c).ok()?.as_str().map(String::from)).flatten().unwrap_or_default(),
                    detail: v.detail.unwrap_or_default(),
                });
                return Ok(out);
            }
        };
        let p = inbound.verified.payload.clone();
        // Learn the signer's identity from a presented delegation, verified against the signer.
        let signer = inbound.verified.signer_did.clone();
        let mut identity = inbound.verified.identity.clone();
        for d in &inbound.verified.header.delegations {
            if let Some((subject, device)) = dsip_core::delegation::names(d) {
                if device == signer {
                    let ctx = Context::new(now, &self.resolver);
                    if dsip_core::delegation::verify_delegation(d, &subject, &device, &ctx).ok() {
                        identity = subject;
                        self.ep.learn_identity(&device, &identity);
                        if !self.peer_delegations.contains(d) {
                            self.peer_delegations.push(d.clone());
                        }
                    }
                }
            }
        }
        // Check 9: an answer must select from the offer we hold.
        if p["type"] == "answer" {
            let key = p.get("in_reply_to").and_then(Value::as_str).or(p.get("session").and_then(Value::as_str)).unwrap_or("");
            if let Some(offer) = self.offers.get(key) {
                if !dsip_schema::selection_is_subset(&p, offer) {
                    out.push(CoreEvent::Rejected { code: "selection-not-subset".into(), detail: key.into() });
                    return Ok(out);
                }
            }
        }
        // WebRTC Media Binding B§2.1: descriptors and SDP must agree. Checked only when SDP is
        // present — Impl: a signalling-only endpoint (no media stack) sends the descriptor without
        // `sdp`; a media-enabled host treats that absence as `media.offer-required` itself.
        let binding_failure = self.binding_check(&p);
        if p["type"] == "invite" || p["type"] == "update" {
            self.offers.insert(p["id"].as_str().unwrap_or("").to_string(), json!({"media": p["media"], "transports": p["transports"]}));
        }
        let msg = Message::from_payload(&p).context("payload shape")?;
        let display_name = p.pointer("/identity/display_name").and_then(Value::as_str).map(String::from);
        let session_scoped = !matches!(msg.msg_type.as_str(), "publish" | "unpublish" | "subscribe" | "notify" | "hello" | "reachability-hint" | "provenance" | "key-rotation");
        out.push(CoreEvent::Received { message: msg.clone(), identity, display_name, payload: p });
        if session_scoped {
            // Broadcast/subscription traffic (§9.3, §22) is handled by the host, not the §12 engine.
            let em = self.ep.step(&Event::Recv { recv: msg.clone() });
            out.extend(self.handle(em, now)?);
            if let Some((code, reason, detail)) = binding_failure {
                // B§8: an offer that fails the binding is rejected (`media.unsupported` …); a failed
                // answer ends that leg with `bye media.failed`.
                let sid = msg.session.clone().unwrap_or_else(|| msg.id.clone());
                let local = match msg.msg_type.as_str() {
                    "invite" => LocalEvent::AutoReject { session: sid, reason: reason.clone() },
                    "update" => LocalEvent::RejectUpdate { session: sid, in_reply_to: msg.id.clone(), reason: reason.clone() },
                    _ => LocalEvent::Hangup { session: sid, reason: Some(reason.clone()) },
                };
                out.push(CoreEvent::Rejected { code, detail: format!("{reason}: {detail}") });
                let em = self.ep.step(&Event::Local(local));
                out.extend(self.handle(em, now)?);
            }
        }
        Ok(out)
    }

    /// WebRTC Media Binding checks on an inbound offer or answer that carries SDP:
    /// `(code, reason token, detail)` on failure.
    fn binding_check(&self, p: &Value) -> Option<(String, String, String)> {
        let has_sdp = p.pointer("/transports/0/sdp").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !has_sdp {
            return None;
        }
        let verdict = match p["type"].as_str() {
            Some("invite") | Some("update") => dsip_webrtc_binding::check_offer(p),
            Some("answer") => {
                let key = p.get("in_reply_to").and_then(Value::as_str).or(p.get("session").and_then(Value::as_str)).unwrap_or("");
                let offer = self.offers.get(key)?;
                if offer.pointer("/transports/0/sdp").is_none() {
                    return None;
                }
                dsip_webrtc_binding::check_answer(offer, p)
            }
            _ => return None,
        };
        if verdict.ok() {
            return None;
        }
        let code = serde_json::to_value(verdict.code).ok()?.as_str()?.to_string();
        Some((code, verdict.reason.unwrap_or("media.unsupported").to_string(), verdict.detail.unwrap_or_default()))
    }

    fn handle(&mut self, emissions: Vec<Emission>, now: i64) -> Result<Vec<CoreEvent>> {
        let mut out = vec![];
        for e in emissions {
            match e {
                Emission::Send(m) => {
                    let env = self.build(&m, now)?;
                    out.push(CoreEvent::Send {
                        frame: env.frame(),
                        msg_type: m.msg_type.clone(),
                        session: m.session.clone().or_else(|| m.id.clone()).unwrap_or_default(),
                        to: m.to.clone(),
                    });
                }
                other => out.push(CoreEvent::Emission(other)),
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------ payload construction

    fn transport(&mut self) -> Value {
        let mut t = json!({"id": "transport:webrtc", "ice": "trickle"});
        if let Some(sdp) = self.pending_sdp.take() {
            t["sdp"] = sdp.into(); // §16.3: SDP as a transport binding object (spec-gap 16)
        }
        t
    }

    fn media_offer(&mut self, with_video: bool) -> Value {
        let mut media = vec![json!({"type": "audio", "direction": "sendrecv",
            "codecs": [{"id": "codec:audio/opus", "sample_rates": [48000], "channels": [1, 2]}]})];
        if with_video {
            media.push(json!({"type": "video", "direction": "sendrecv", "codecs": [{"id": "codec:video/h264", "profiles": ["baseline"]}]}));
        }
        json!({"media": media, "transports": [self.transport()]})
    }

    /// A selection from `offer`: first codec per descriptor; screening → audio `recvonly` only (§14.4).
    fn selection(offer: &Value, screening: bool, sdp: Option<String>) -> Value {
        let mut media = vec![];
        for m in offer["media"].as_array().into_iter().flatten() {
            if screening && m["type"] != "audio" {
                continue;
            }
            let direction = if screening { "recvonly" } else { m["direction"].as_str().unwrap_or("sendrecv") };
            let codec = m["codecs"].as_array().and_then(|c| c.first()).cloned().unwrap_or(json!({}));
            let mut d = json!({"type": m["type"], "direction": direction, "codecs": [{"id": codec["id"]}]});
            if let Some(p) = m.get("purpose") {
                d["purpose"] = p.clone();
            }
            media.push(d);
        }
        let offered = offer["transports"].as_array().and_then(|t| t.first()).cloned().unwrap_or(json!({"id": "transport:webrtc"}));
        let mut t = json!({"id": offered["id"]});
        if let Some(s) = sdp {
            t["sdp"] = s.into();
        }
        json!({"media": media, "transports": [t]})
    }

    fn build(&mut self, m: &SendMsg, now: i64) -> Result<Envelope> {
        let session = m.session.clone().unwrap_or_default();
        let id = m.id.clone().unwrap_or_else(|| if m.msg_type == "invite" { session.clone() } else { self.new_id(now) });
        let profiles: &[&str] = if m.msg_type == "error" { &[] } else { &[PROFILE] };
        let mut p = json!({
            "dsip": version_block(&self.supported, profiles),
            "type": m.msg_type, "id": id, "from": self.keys.device.did(), "to": m.to,
        });
        if let Some(s) = &m.session {
            if m.msg_type != "invite" {
                p["session"] = s.clone().into();
            }
        }
        for (k, v) in &m.extra {
            p[*k] = v.clone();
        }
        let mut ttl = 30;
        match m.msg_type.as_str() {
            "introduction" => {
                // §19.4: media-less, session-less; identity and purpose are claims; up to 7 days validity
                p["identity"] = json!({"display_name": self.keys.display_name, "claims": []});
                ttl = 604_800;
            }
            "grant" => {}
            "invite" => {
                let offer = self.media_offer(self.cfg.video);
                self.offers.insert(session.clone(), offer.clone());
                p["intent"] = "interactive".into();
                p["identity"] = json!({"display_name": self.keys.display_name, "claims": std::mem::take(&mut self.pending_claims)});
                p["media"] = offer["media"].clone();
                p["transports"] = offer["transports"].clone();
                p["policy"] = json!({"recording": "consent-required", "ai_processing": "denied"});
            }
            "progress" => {
                p["status"] = m.status.clone().unwrap_or_else(|| "ringing".into()).into();
                if let Some(rt) = m.ring_timeout {
                    p["ring_timeout"] = rt.into();
                }
            }
            "answer" => {
                let key = m.in_reply_to.clone().unwrap_or_else(|| session.clone());
                let offer = self.offers.get(&key).cloned().unwrap_or_else(|| self.media_offer(false));
                let screening = m.answered_by.as_deref() == Some("screening");
                let sel = Self::selection(&offer, screening, self.pending_sdp.take());
                p["answered_by"] = m.answered_by.clone().unwrap_or_else(|| "user".into()).into();
                p["media"] = sel["media"].clone();
                p["transports"] = sel["transports"].clone();
                if let Some(irt) = &m.in_reply_to {
                    p["in_reply_to"] = irt.clone().into();
                }
            }
            "reject" | "cancel" | "bye" | "error" => {
                p["reason"] = m.reason.clone().unwrap_or_else(|| "session.failed".into()).into();
                if let Some(irt) = &m.in_reply_to {
                    p["in_reply_to"] = irt.clone().into();
                }
            }
            "update" => {
                // Escalation offer (§14.4 step 3): full sendrecv from this sender; video only when this
                // endpoint actually offers it, so the descriptors match the SDP the media leg re-offers
                // (WebRTC Media Binding B§2.1).
                let offer = self.media_offer(self.cfg.video);
                self.offers.insert(id.clone(), offer.clone());
                p["media"] = offer["media"].clone();
                p["transports"] = offer["transports"].clone();
                if let Some(ab) = &m.answered_by {
                    p["answered_by"] = ab.clone().into();
                }
            }
            "info" => {
                p["about"] = "transport:webrtc".into();
                p["data"] = self.pending_info_data.take().unwrap_or_else(|| json!({"candidates": [], "end_of_candidates": true}));
            }
            other => anyhow::bail!("engine asked to send unsupported type {other}"),
        }
        p["issued_at"] = now.into();
        p["expires_at"] = (now + ttl).into();
        // The device signs; its delegation rides in the header so peers can learn and verify the identity (spec-gap 8).
        Ok(sign_bytes(&serde_json::to_vec(&p)?, &self.keys.device, &self.keys.device.kid(), vec![self.keys.delegation.clone()]))
    }
}
