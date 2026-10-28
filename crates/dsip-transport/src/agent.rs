//! The native agent: a [`dsip_endpoint::Core`] over a live `ws/1.0` connection with file persistence.
//!
//! Spec: §13.2 (one connection, many sessions; reconnection with a fresh
//! `hello`), §19.4 (grants persist across restarts). All protocol logic lives in
//! `dsip-endpoint`; this module adds the socket, the wall clock, and the disk.

use std::time::Duration;


use dsip_core::did::StaticResolver;
use dsip_core::version::Supported;
use dsip_endpoint::{CallCommand, CallEvent, CallOut, Calls, CallsConfig, Command, ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys,
                    Invite, MediaRequest, MediaResult, PresenceSealing};
use dsip_session::{Emission, Endpoint, LocalEvent, Message};

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::conn::{ConnectParams, Connection, Dialer};
use crate::resolver::{DidResolver, DidWebResolver};
use crate::identity::Identity;
use crate::verify::SeenIds;
use crate::error::Result;
use crate::{now_s, BACKOFF};

/// Interactive Media Profile identifier. Spec: §17.
pub const PROFILE: &str = dsip_endpoint::core::PROFILE;

/// Something the application should know about.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // an event is built once and consumed at once; boxing the message would cost an allocation per event
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
        /// Full decoded payload (SDP, candidates, policy live here).
        payload: serde_json::Value,
    },
    /// An inbound frame was rejected (code, detail).
    Rejected(String, String),
    /// Connection dropped and was re-established after `attempts` tries.
    Reconnected {
        /// Attempts.
        attempts: u32,
    },
    /// Media work for the host, from the call glue ([`AgentConfig::calls`]); SDP results go back through
    /// [`Agent::media`].
    Media(MediaRequest),
    /// Something about a call, from the call glue.
    Call(CallEvent),
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
    /// §10.4: seal outbound session bodies (`sealed-body/1.0`). Inbound sealed bodies are opened either way.
    pub seal: bool,
    /// §8.1: how to fetch a `did:web` document an inbound frame needs and the agent does not hold. `None` fetches
    /// over HTTPS ([`DidWebResolver`]).
    pub did_resolver: Option<Arc<dyn DidResolver>>,
    /// Run the call glue ([`dsip_endpoint::calls`]): the agent then answers by policy and asks for media work with
    /// [`AgentEvent::Media`]; calls are placed with [`Agent::place`] and driven with [`Agent::call`]. `None` leaves
    /// all of that to the host.
    pub calls: Option<CallsConfig>,
    /// How to reach the relay: `None` dials [`AgentConfig::relay_url`] over `wss`; a [`Dialer`] supplies the stream
    /// instead (an embedded relay; `dsip-testkit`), for the first connection and every reconnect.
    pub dialer: Option<Arc<dyn Dialer>>,
    /// P§12: seal this device's presence records for these scopes (`main` and audience tags, [`audience_tag`]) and put
    /// keys in the grants it issues. `None` seals nothing; the keys of grants held open either way.
    pub presence: Option<PresenceSealing>,
}

/// The wire tag of the audience `id`'s identity labels `label` (P§12.1): the label stays on the subject's devices.
pub fn audience_tag(id: &Identity, label: &str) -> String {
    dsip_core::presence_seal::audience_tag(&dsip_core::hpke::x25519_from_ed25519_seed(&id.controller.seed()), &id.meta.identity, label)
}

type Resolution = (String, std::result::Result<dsip_core::did::DidDocument, dsip_core::did::ResolveError>);

/// The agent.
pub struct Agent {
    id: Identity,
    cfg: AgentConfig,
    supported: Supported,
    resolver: StaticResolver,
    conn: Connection,
    core: Core,
    calls: Option<Calls>,
    events: Vec<AgentEvent>,
    did_resolver: Arc<dyn DidResolver>,
    resolved_tx: mpsc::UnboundedSender<Resolution>,
    resolved_rx: mpsc::UnboundedReceiver<Resolution>,
    /// §13.2: the relay said `transport.replaced` on this connection; its close is then not an unexpected loss
    replaced: bool,
    /// ... and the connection has closed: [`Agent::next`] returns [`Error::Replaced`] once its events are handed over
    replaced_closed: bool,
}

impl Agent {
    /// Connect and bind.
    pub async fn connect(id: Identity, cfg: AgentConfig, resolver: StaticResolver) -> Result<Agent> {
        let supported = Supported::all_known();
        let mut seen = SeenIds::default();
        let conn = Connection::dial(cfg.dialer.as_deref(), &Self::params(&id, &cfg, &supported), &resolver, &mut seen).await?;
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
            seal: cfg.seal,
            resolve_on_demand: true,
            presence: cfg.presence.clone(),
            unseal_keys: vec![
                (id.meta.identity.clone(), dsip_core::hpke::x25519_from_ed25519_seed(&id.controller.seed())),
                (id.device.did(), dsip_core::hpke::x25519_from_ed25519_seed(&id.device.seed())),
            ],
        };
        let mut core = Core::new(keys, core_cfg, resolver.clone(), now_s());
        // Seed persisted contacts (§19.4) so grants survive restarts.
        let file: ContactFile =
            std::fs::read(id.dir.join("contacts.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        core.load_contacts(&file);
        // P§7, P§12.5: our relay is the presence authority; the core sends it the revocations a share's end needs
        core.set_authority(Some(conn.relay.did.clone()));
        let did_resolver = cfg.did_resolver.clone().unwrap_or_else(|| Arc::new(DidWebResolver::new()));
        let (resolved_tx, resolved_rx) = mpsc::unbounded_channel();
        let calls = cfg.calls.map(Calls::new);
        Ok(Agent { id, cfg, supported, resolver, conn, core, calls, events: vec![], did_resolver, resolved_tx, resolved_rx, replaced: false, replaced_closed: false })
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
        let path = self.id.dir.join("contacts.json");
        crate::error::file(&path, std::fs::write(&path, serde_json::to_string_pretty(&self.core.contacts())?))
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
        self.place_call_with(to, Invite::default()).await
    }

    /// Place a call with what the host adds to the invite (SDP, claims, patch); returns the new session id.
    pub async fn place_call_with(&mut self, to: &str, invite: Invite) -> Result<String> {
        let sid = self.core.new_id(now_s());
        self.command(Command::PlaceCall { session: sid.clone(), to: to.to_string(), invite }).await?;
        Ok(sid)
    }

    /// A fresh ULID.
    pub fn new_id(&mut self) -> String {
        self.core.new_id(now_s())
    }

    /// Sign and send an application-built payload (publish / subscribe / provenance, …).
    pub async fn send_payload(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        let frame = self.core.sign_payload(payload, now_s(), ttl)?;
        let env = dsip_core::envelope::Envelope::from_frame(&frame)?;
        self.conn.send(&env).await?;
        Ok(frame)
    }

    /// Verify a record carried inside another message (a presence record in a `notify` body): its payload and the
    /// identity its signer acts for. Spec: P§3.
    pub fn verify_record(&self, frame: &str) -> Option<(serde_json::Value, String)> {
        self.core.verify_record(frame, now_s())
    }

    /// Withdraw a grant we issued (§19.4): the core sends a signed `grant-revocation` to our relay, the authority, for
    /// it and every grant of its rotation chain, so the relay ends what they admitted there (P§7, P§12.5), and rotates
    /// the keys it carried. Returns whether we had issued it.
    pub async fn revoke_grant(&mut self, grant: &str) -> Result<bool> {
        if !self.core.endpoint().contacts.grants_issued.contains_key(grant) {
            return Ok(false);
        }
        self.local(LocalEvent::Revoke { grant: grant.to_string() }).await?;
        Ok(true)
    }

    /// Replace a live grant we issued with one that follows it (§19.4, spec-gap 150): the old grant's revocation to our
    /// relay, which ends what it admitted there (P§7), then the new grant, sent to the same grantee. Returns `false`,
    /// sending nothing, when we issued no live grant `grant` or `presence_audience` is not a P§6 token.
    pub async fn regrant(&mut self, grant: &str, id: String, scope: Vec<String>, valid_until: i64, presence_audience: Option<String>) -> Result<bool> {
        let live = self.endpoint().contacts.grants_issued.get(grant).is_some_and(|g| g.valid_until > now_s());
        if !live || presence_audience.as_deref().is_some_and(|a| !dsip_core::is_presence_audience(a)) {
            return Ok(false);
        }
        // the core revokes the old grant and its chain at our relay before the new grant goes (P§7)
        self.local(LocalEvent::Regrant { grant: grant.to_string(), id, scope, valid_until, presence_audience }).await?;
        Ok(true)
    }

    /// The held grants from `target` to present when watching its presence (`subscribe` `claims`). Spec: P§6.
    pub fn presence_claims(&self, target: &str) -> Vec<serde_json::Value> {
        self.core.presence_claims(target, now_s())
    }

    /// Whether `device` presented a delegation granting `capability` (Recording Profile C§6).
    pub fn peer_has_capability(&self, device: &str, capability: &str) -> bool {
        self.core.peer_has_capability(device, capability, crate::now_s())
    }

    /// This side's recording declaration from now on (Recording Profile C§3).
    pub fn set_recording(&mut self, declaration: Option<serde_json::Value>) {
        self.core.set_recording(declaration);
    }

    /// Sign and send one of this device's presence records (a `Publisher` payload), sealed when its scope is
    /// ([`AgentConfig::presence`]). Returns the frame. Spec: P§3, P§12.2.
    pub async fn send_presence(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        let frame = self.core.sign_presence(payload, now_s(), ttl)?;
        self.conn.send(&dsip_core::envelope::Envelope::from_frame(&frame)?).await?;
        Ok(frame)
    }

    /// The key `kid` of `subject`'s presence records: ours derived, a grantor's from its grants (P§12.4).
    pub fn presence_key(&self, subject: &str, kid: &str) -> Option<[u8; 32]> {
        self.core.presence_key(subject, kid)
    }

    /// The wire tag of the audience our identity labels `label` (P§12.1).
    pub fn audience_tag(&self, label: &str) -> String {
        audience_tag(&self.id, label)
    }

    /// A verified record of our own identity, from our own watch: a sibling's higher epoch is adopted and the grants
    /// that carry it are re-granted (P§12.5).
    pub async fn own_record(&mut self, record: &serde_json::Value) -> Result<()> {
        let out = self.core.own_record(record, now_s())?;
        self.dispatch(out).await
    }

    /// Seal outbound session bodies from now on, or stop (§10.4).
    pub fn set_seal(&mut self, on: bool) {
        self.core.set_seal(on);
    }

    /// Place a call through the call glue; returns the new session id. With media, the invite goes once the host
    /// answers the [`MediaRequest::Offer`].
    pub async fn place(&mut self, to: &str, invite: Invite) -> Result<String> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let (sid, out) = calls.place(&mut self.core, to, invite, now_s())?;
        self.act(out).await?;
        Ok(sid)
    }

    /// Do what the application asks of a call, through the call glue.
    pub async fn call(&mut self, cmd: CallCommand) -> Result<()> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let out = calls.command(&mut self.core, cmd, now_s())?;
        self.act(out).await
    }

    /// Hand the call glue the result of a [`MediaRequest`], or a local ICE candidate.
    pub async fn media(&mut self, result: MediaResult) -> Result<()> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let out = calls.media(&mut self.core, result, now_s())?;
        self.act(out).await
    }

    /// Drive a local event through the core and act on its output.
    pub async fn local(&mut self, ev: LocalEvent) -> Result<()> {
        self.command(Command::Engine(ev)).await
    }

    /// Drive a host request through the core and act on its output.
    pub async fn command(&mut self, cmd: Command) -> Result<()> {
        let out = self.core.command(cmd, now_s())?;
        self.dispatch(out).await
    }

    /// Advance the engine clock to wall time (fires due timers) and act on emissions.
    pub async fn tick_and_handle(&mut self) -> Result<()> {
        let out = self.core.tick(now_s())?;
        self.dispatch(out).await
    }

    /// Act on the core's output, through the call glue when it runs.
    async fn dispatch(&mut self, out: Vec<CoreEvent>) -> Result<()> {
        let out = match self.calls.as_mut() {
            Some(calls) => calls.observe(&mut self.core, out, now_s())?,
            None => out.into_iter().map(CallOut::Core).collect(),
        };
        self.act(out).await
    }

    async fn act(&mut self, out: Vec<CallOut>) -> Result<()> {
        for o in out {
            let e = match o {
                CallOut::Core(e) => e,
                CallOut::Media(m) => {
                    self.events.push(AgentEvent::Media(m));
                    continue;
                }
                CallOut::Call(c) => {
                    self.events.push(AgentEvent::Call(c));
                    continue;
                }
            };
            match e {
                CoreEvent::Send { frame, msg_type, session, to } => {
                    let env = dsip_core::envelope::Envelope::from_frame(&frame)?;
                    self.conn.send(&env).await?;
                    self.events.push(AgentEvent::Sent { msg_type, session, to });
                }
                CoreEvent::Emission(em) => self.events.push(AgentEvent::Emission(em)),
                CoreEvent::Received { message, identity, display_name, payload } => {
                    if payload["type"] == "error" && payload["reason"] == "transport.replaced" && identity == self.conn.relay.did {
                        self.replaced = true; // §13.2: our relay is about to close this connection
                    }
                    self.events.push(AgentEvent::Received { message, identity, display_name, payload })
                }
                CoreEvent::Rejected { code, detail } => self.events.push(AgentEvent::Rejected(code, detail)),
                CoreEvent::Resolve { did } => {
                    // Fetched off the loop; the outcome comes back through `next`.
                    let (r, tx) = (Arc::clone(&self.did_resolver), self.resolved_tx.clone());
                    tokio::spawn(async move {
                        let result = r.resolve(&did).await;
                        if let Err(e) = &result {
                            tracing::warn!("resolving {did}: {e}");
                        }
                        let _ = tx.send((did, result));
                    });
                }
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
            if self.replaced_closed {
                return Err(crate::Error::Replaced { relay: self.conn.relay.did.clone() });
            }
            let wait = self.core.next_deadline().map(|d| (d - now_s()).max(0) as u64).unwrap_or(3600);
            tokio::select! {
                frame = self.conn.recv() => match frame {
                    Ok(Some(text)) => {
                        let out = self.core.inbound(&text, now_s())?;
                        self.dispatch(out).await?;
                    }
                    // §13.2: a connection the relay replaced is not reconnected; that would replace the other one
                    Ok(None) | Err(_) if self.replaced => {
                        self.replaced_closed = true;
                        continue;
                    }
                    Ok(None) => self.reconnect().await?,
                    Err(e) => {
                        tracing::warn!("connection error: {e}");
                        self.reconnect().await?;
                    }
                },
                Some((did, result)) = self.resolved_rx.recv() => {
                    if let Ok(doc) = &result {
                        self.resolver.insert(doc.clone()); // held for reconnects too (relay hello)
                    }
                    let out = self.core.resolved(&did, result, now_s())?;
                    self.dispatch(out).await?;
                }
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
            match Connection::dial(self.cfg.dialer.as_deref(), &Self::params(&self.id, &self.cfg, &self.supported), &self.resolver, &mut seen).await {
                Ok(c) => {
                    self.conn = c;
                    self.core.set_authority(Some(self.conn.relay.did.clone()));
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
