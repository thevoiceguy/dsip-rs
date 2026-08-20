//! The endpoint agent: a `dsip_session::Endpoint` driven over a live `ws/1.0` connection.
//!
//! Spec: §12 (the engine), §13.2 (delivery over one connection, many
//! sessions), §14.2 (invite carries an offer; answer is a selection), §14.4
//! (screening selection), §16.2 (structured media descriptors), §12.12
//! (`info` carries transport data). The agent owns payload construction:
//! the engine decides *what* to send; this module decides *what it contains*.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign_bytes, Envelope};
use dsip_core::ulid::Ulid;
use dsip_core::version::{version_block, Supported};
use dsip_session::event::SendMsg;
use dsip_session::{Emission, Endpoint, EndpointConfig, Event, LocalEvent, Message};

use crate::conn::{ConnectParams, Connection};
use crate::identity::Identity;
use crate::verify::{verify_frame, SeenIds};
use crate::{now_s, BACKOFF};

/// Interactive Media Profile identifier. Spec: §17.
pub const PROFILE: &str = "interactive-media/1.0";

/// Something the application should know about.
#[derive(Debug)]
pub enum AgentEvent {
    /// An engine emission that is not a send (timers, ui, media, drops, refusals).
    Emission(Emission),
    /// We sent an envelope (type, session, to).
    Sent {
        /// Message type.
        msg_type: String,
        /// Session.
        session: String,
        /// Destination.
        to: String,
    },
    /// A verified inbound message was handed to the engine.
    Received {
        /// The abbreviated message.
        message: Message,
        /// The signer's identity (subject of a presented, valid delegation, or the signer itself).
        identity: String,
        /// Display name claim from `identity.display_name`, if any.
        display_name: Option<String>,
    },
    /// An inbound frame was rejected (code, detail).
    Rejected(String, String),
    /// Connection dropped and was re-established after `attempts` tries.
    Reconnected {
        /// Attempts.
        attempts: u32,
    },
}

/// Agent configuration.
pub struct AgentConfig {
    /// Relay URL.
    pub relay_url: String,
    /// TLS trust.
    pub tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// Offer video in invites.
    pub video: bool,
    /// Timer overrides (seconds).
    pub t_establish: Option<i64>,
    /// T-Ring override.
    pub t_ring: Option<i64>,
    /// T-Ring-Local override.
    pub t_ring_local: Option<i64>,
}

/// The agent.
pub struct Agent {
    id: Identity,
    cfg: AgentConfig,
    supported: Supported,
    resolver: StaticResolver,
    conn: Connection,
    ep: Endpoint,
    seen: SeenIds,
    /// Offers by session id (invite) or update id, ours and theirs, for building selections and checking subsets.
    offers: HashMap<String, Value>,
    /// Delegations learned from peers' headers (device → delegation), verified at use.
    peer_delegations: Vec<Envelope>,
    /// Pending `answered_by` for the next answer we build per session.
    events: Vec<AgentEvent>,
}

impl Agent {
    /// Connect and bind.
    pub async fn connect(id: Identity, cfg: AgentConfig, resolver: StaticResolver) -> Result<Agent> {
        let supported = Supported::default();
        let mut seen = SeenIds::default();
        let conn = Connection::connect(&Self::params(&id, &cfg, &supported), &resolver, &mut seen).await?;
        let ep = Endpoint::new(Self::ep_config(&id, &cfg));
        Ok(Agent { id, cfg, supported, resolver, conn, ep, seen, offers: HashMap::new(), peer_delegations: vec![], events: vec![] })
    }

    fn params<'a>(id: &'a Identity, cfg: &AgentConfig, supported: &Supported) -> ConnectParams<'a> {
        ConnectParams {
            url: cfg.relay_url.clone(),
            tls: cfg.tls.clone(),
            device: &id.device,
            on_behalf_of: Some(id.meta.identity.clone()),
            delegations: vec![id.delegation.clone()],
            supported: supported.clone(),
        }
    }

    fn ep_config(id: &Identity, cfg: &AgentConfig) -> EndpointConfig {
        let mut c = EndpointConfig::from_vector(&json!({
            "self": {"device": id.meta.device, "identity": id.meta.identity},
            "start": now_s(),
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
        c
    }

    /// Relay identity and capabilities.
    pub fn relay(&self) -> &crate::conn::RelayInfo {
        &self.conn.relay
    }

    /// Our device DID.
    pub fn device_did(&self) -> &str {
        &self.id.meta.device
    }

    /// Our identity DID.
    pub fn identity_did(&self) -> &str {
        &self.id.meta.identity
    }

    /// Read-only engine access (for printing state).
    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    /// Close the connection gracefully (WebSocket close + TLS close_notify).
    pub async fn close(&mut self) {
        self.conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "bye").await;
    }

    // ------------------------------------------------------------ local actions

    /// Place a call; returns the new session id.
    pub async fn place_call(&mut self, to: &str) -> Result<String> {
        let sid = Ulid::generate().to_string();
        self.local(LocalEvent::PlaceCall { session: sid.clone(), to: to.to_string() }).await?;
        Ok(sid)
    }

    /// Drive a local event through the engine and act on its emissions.
    pub async fn local(&mut self, ev: LocalEvent) -> Result<()> {
        self.tick_and_handle().await?;
        let emissions = self.ep.step(&Event::Local(ev));
        self.handle(emissions).await
    }

    /// Advance the engine clock to wall time (fires due timers) and act on emissions.
    pub async fn tick_and_handle(&mut self) -> Result<()> {
        let delta = now_s() - self.ep.now;
        if delta > 0 {
            let emissions = self.ep.step(&Event::Advance { advance: delta });
            self.handle(emissions).await?;
        }
        Ok(())
    }

    /// Wait for the next thing to happen (inbound frame, timer, or connection loss) and return
    /// the accumulated application events. Reconnects with backoff on connection loss.
    pub async fn next(&mut self) -> Result<Vec<AgentEvent>> {
        loop {
            if !self.events.is_empty() {
                return Ok(std::mem::take(&mut self.events));
            }
            let wait = self.ep.next_deadline().map(|d| (d - now_s()).max(0) as u64).unwrap_or(3600);
            tokio::select! {
                frame = self.conn.recv() => match frame {
                    Ok(Some(text)) => self.inbound(&text).await?,
                    Ok(None) => self.reconnect().await?,
                    Err(e) => {
                        tracing::warn!("connection error: {e}");
                        self.reconnect().await?;
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(wait.max(1))) => {}
            }
            self.tick_and_handle().await?;
        }
    }

    async fn reconnect(&mut self) -> Result<()> {
        // §13.2: exponential backoff with jitter, fresh hello; sessions are unaffected.
        let (mut delay, factor, max) = BACKOFF;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let jitter = Duration::from_millis((now_s() as u64 * 7919 + attempts as u64 * 104_729) % (delay * 1000));
            tokio::time::sleep(jitter).await;
            match Connection::connect(&Self::params(&self.id, &self.cfg, &self.supported), &self.resolver, &mut self.seen).await {
                Ok(c) => {
                    self.conn = c;
                    self.events.push(AgentEvent::Reconnected { attempts });
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("reconnect attempt {attempts} failed: {e}");
                    delay = (delay * factor as u64).min(max);
                }
            }
        }
    }

    // ------------------------------------------------------------ inbound

    async fn inbound(&mut self, frame: &str) -> Result<()> {
        let sem = dsip_schema::SemanticContext { supported: self.supported.clone(), ..Default::default() };
        let inbound = match verify_frame(frame, now_s(), &self.resolver, &self.peer_delegations, &mut self.seen, &sem) {
            Ok(i) => i,
            Err(v) => {
                self.events.push(AgentEvent::Rejected(format!("{:?}", v.code), v.detail.unwrap_or_default()));
                return Ok(());
            }
        };
        let p = &inbound.verified.payload;
        // Learn the signer's identity from a presented delegation (header), verified against the signer.
        let signer = inbound.verified.signer_did.clone();
        let mut identity = inbound.verified.identity.clone();
        for d in &inbound.verified.header.delegations {
            if let Some((subject, device)) = dsip_core::delegation::names(d) {
                if device == signer {
                    let ctx = dsip_core::envelope::Context::new(now_s(), &self.resolver);
                    if dsip_core::delegation::verify_delegation(d, &subject, &device, &ctx).ok() {
                        identity = subject;
                        if !self.peer_delegations.contains(d) {
                            self.peer_delegations.push(d.clone());
                        }
                    }
                }
            }
        }
        // Subset check for answers against the offer we hold (check 9)
        if p["type"] == "answer" {
            let key = p.get("in_reply_to").and_then(Value::as_str).or(p.get("session").and_then(Value::as_str)).unwrap_or("");
            if let Some(offer) = self.offers.get(key) {
                if !dsip_schema::selection_is_subset(p, offer) {
                    self.events.push(AgentEvent::Rejected("selection-not-subset".into(), key.into()));
                    return Ok(());
                }
            }
        }
        // Remember offers we receive (invite/update) so our answers select from them
        if p["type"] == "invite" || p["type"] == "update" {
            self.offers.insert(p["id"].as_str().unwrap_or("").to_string(), json!({"media": p["media"], "transports": p["transports"]}));
        }
        let msg = Message::from_payload(p).context("payload shape")?;
        let display_name = p.pointer("/identity/display_name").and_then(Value::as_str).map(String::from);
        self.events.push(AgentEvent::Received { message: msg.clone(), identity, display_name });
        self.tick_and_handle().await?;
        let emissions = self.ep.step(&Event::Recv { recv: msg });
        self.handle(emissions).await
    }

    // ------------------------------------------------------------ outbound

    async fn handle(&mut self, emissions: Vec<Emission>) -> Result<()> {
        for e in emissions {
            match e {
                Emission::Send(m) => {
                    let env = self.build(&m)?;
                    self.conn.send(&env).await?;
                    self.events.push(AgentEvent::Sent { msg_type: m.msg_type.clone(), session: m.session.clone(), to: m.to.clone() });
                }
                other => self.events.push(AgentEvent::Emission(other)),
            }
        }
        Ok(())
    }

    fn media_offer(&self) -> Value {
        let mut media = vec![json!({"type": "audio", "direction": "sendrecv",
            "codecs": [{"id": "codec:audio/opus", "sample_rates": [48000], "channels": [1, 2]}]})];
        if self.cfg.video {
            media.push(json!({"type": "video", "direction": "sendrecv", "codecs": [{"id": "codec:video/h264", "profiles": ["baseline"]}]}));
        }
        json!({"media": media, "transports": [{"id": "transport:webrtc", "ice": "trickle"}]})
    }

    /// A selection from `offer`: first codec per descriptor; screening → audio recvonly only (§14.4).
    fn selection(offer: &Value, screening: bool) -> Value {
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
        let transport = offer["transports"].as_array().and_then(|t| t.first()).cloned().unwrap_or(json!({"id": "transport:webrtc"}));
        json!({"media": media, "transports": [{"id": transport["id"]}]})
    }

    fn build(&mut self, m: &SendMsg) -> Result<Envelope> {
        let now = now_s();
        let id = m.id.clone().unwrap_or_else(|| if m.msg_type == "invite" { m.session.clone() } else { Ulid::generate().to_string() });
        let profiles: &[&str] = if m.msg_type == "error" { &[] } else { &[PROFILE] };
        let mut p = json!({
            "dsip": version_block(&self.supported, profiles),
            "type": m.msg_type, "id": id, "from": self.id.meta.device, "to": m.to,
        });
        if m.msg_type != "invite" {
            p["session"] = m.session.clone().into();
        }
        match m.msg_type.as_str() {
            "invite" => {
                let offer = self.media_offer();
                self.offers.insert(m.session.clone(), offer.clone());
                p["intent"] = "interactive".into();
                p["identity"] = json!({"display_name": self.id.meta.display_name, "claims": []});
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
                let key = m.in_reply_to.clone().unwrap_or_else(|| m.session.clone());
                let offer = self.offers.get(&key).cloned().unwrap_or_else(|| self.media_offer());
                let screening = m.answered_by.as_deref() == Some("screening");
                let sel = Self::selection(&offer, screening);
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
                // Offer escalation: full sendrecv audio (+ video) from this sender
                let mut offer = self.media_offer();
                if !self.cfg.video {
                    offer["media"].as_array_mut().expect("array").push(json!({"type": "video", "direction": "sendrecv",
                        "codecs": [{"id": "codec:video/h264", "profiles": ["baseline"]}]}));
                }
                self.offers.insert(id.clone(), offer.clone());
                p["media"] = offer["media"].clone();
                p["transports"] = offer["transports"].clone();
                if let Some(ab) = &m.answered_by {
                    p["answered_by"] = ab.clone().into();
                }
            }
            "info" => {
                p["about"] = "transport:webrtc".into();
                p["data"] = json!({"candidates": [], "end_of_candidates": true});
            }
            other => anyhow::bail!("engine asked to send unsupported type {other}"),
        }
        p["issued_at"] = now.into();
        p["expires_at"] = (now + 30).into();
        // The device signs; its delegation rides in the header so peers can learn and verify the identity (spec-gap 8).
        Ok(sign_bytes(&serde_json::to_vec(&p)?, &self.id.device, &self.id.device.kid(), vec![self.id.delegation.clone()]))
    }
}
