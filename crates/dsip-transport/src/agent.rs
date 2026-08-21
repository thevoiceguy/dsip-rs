//! The native agent: a [`dsip_endpoint::Core`] over a live `ws/1.0` connection with file persistence.
//!
//! Spec: §13.2 (one connection, many sessions; reconnection with a fresh
//! `hello`), §19.4 (grants persist across restarts). All protocol logic lives in
//! `dsip-endpoint`; this module adds the socket, the wall clock, and the disk.

use std::time::Duration;

use anyhow::Result;

use dsip_core::did::StaticResolver;
use dsip_core::version::Supported;
use dsip_endpoint::{ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys};
use dsip_session::{Emission, Endpoint, LocalEvent, Message};

use crate::conn::{ConnectParams, Connection};
use crate::identity::Identity;
use crate::verify::SeenIds;
use crate::{now_s, BACKOFF};

/// Interactive Media Profile identifier. Spec: §17.
pub const PROFILE: &str = dsip_endpoint::core::PROFILE;

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
        /// The signer's identity.
        identity: String,
        /// Display name claim, if any.
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
    /// §19.4: reject invites from identities holding no grant.
    pub first_contact_required: bool,
}

/// The agent.
pub struct Agent {
    id: Identity,
    cfg: AgentConfig,
    supported: Supported,
    resolver: StaticResolver,
    conn: Connection,
    core: Core,
    events: Vec<AgentEvent>,
}

impl Agent {
    /// Connect and bind.
    pub async fn connect(id: Identity, cfg: AgentConfig, resolver: StaticResolver) -> Result<Agent> {
        let supported = Supported::default();
        let mut seen = SeenIds::default();
        let conn = Connection::connect(&Self::params(&id, &cfg, &supported), &resolver, &mut seen).await?;
        let keys = IdentityKeys {
            identity: id.meta.identity.clone(),
            device: id.device.clone(),
            delegation: id.delegation.clone(),
            display_name: id.meta.display_name.clone(),
        };
        let core_cfg = CoreConfig {
            video: cfg.video,
            t_establish: cfg.t_establish,
            t_ring: cfg.t_ring,
            t_ring_local: cfg.t_ring_local,
            first_contact_required: cfg.first_contact_required,
        };
        let mut core = Core::new(keys, core_cfg, resolver.clone(), now_s());
        // Seed persisted contacts (§19.4) so grants survive restarts.
        let file: ContactFile =
            std::fs::read(id.dir.join("contacts.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        core.load_contacts(&file);
        Ok(Agent { id, cfg, supported, resolver, conn, core, events: vec![] })
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

    /// Persist first-contact state to the identity directory.
    pub fn save_contacts(&self) -> Result<()> {
        std::fs::write(self.id.dir.join("contacts.json"), serde_json::to_string_pretty(&self.core.contacts())?)?;
        Ok(())
    }

    /// Pending introductions (id → identity).
    pub fn requests(&self) -> Vec<(String, String)> {
        self.core.requests()
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
        self.core.endpoint()
    }

    /// Close the connection gracefully (WebSocket close + TLS close_notify).
    pub async fn close(&mut self) {
        self.conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "bye").await;
    }

    // ------------------------------------------------------------ local actions

    /// Place a call; returns the new session id.
    pub async fn place_call(&mut self, to: &str) -> Result<String> {
        let sid = self.core.new_id(now_s());
        self.local(LocalEvent::PlaceCall { session: sid.clone(), to: to.to_string() }).await?;
        Ok(sid)
    }

    /// A fresh ULID.
    pub fn new_id(&mut self) -> String {
        self.core.new_id(now_s())
    }

    /// Drive a local event through the core and act on its output.
    pub async fn local(&mut self, ev: LocalEvent) -> Result<()> {
        let out = self.core.local(ev, now_s())?;
        self.dispatch(out).await
    }

    /// Advance the engine clock to wall time (fires due timers) and act on emissions.
    pub async fn tick_and_handle(&mut self) -> Result<()> {
        let out = self.core.tick(now_s())?;
        self.dispatch(out).await
    }

    async fn dispatch(&mut self, out: Vec<CoreEvent>) -> Result<()> {
        for e in out {
            match e {
                CoreEvent::Send { frame, msg_type, session, to } => {
                    let env = dsip_core::envelope::Envelope::from_frame(&frame).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
                    self.conn.send(&env).await?;
                    self.events.push(AgentEvent::Sent { msg_type, session, to });
                }
                CoreEvent::Emission(em) => self.events.push(AgentEvent::Emission(em)),
                CoreEvent::Received { message, identity, display_name, .. } => {
                    self.events.push(AgentEvent::Received { message, identity, display_name })
                }
                CoreEvent::Rejected { code, detail } => self.events.push(AgentEvent::Rejected(code, detail)),
            }
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
            let wait = self.core.endpoint().next_deadline().map(|d| (d - now_s()).max(0) as u64).unwrap_or(3600);
            tokio::select! {
                frame = self.conn.recv() => match frame {
                    Ok(Some(text)) => {
                        let out = self.core.inbound(&text, now_s())?;
                        self.dispatch(out).await?;
                    }
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
        let mut seen = SeenIds::default();
        loop {
            attempts += 1;
            let jitter = Duration::from_millis((now_s() as u64 * 7919 + attempts as u64 * 104_729) % (delay * 1000));
            tokio::time::sleep(jitter).await;
            match Connection::connect(&Self::params(&self.id, &self.cfg, &self.supported), &self.resolver, &mut seen).await {
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
}
