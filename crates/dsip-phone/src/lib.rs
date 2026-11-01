//! `dsip-phone` — a phone: place calls, take them, hang up. What most calling applications hold.
//!
//! ```no_run
//! # async fn demo() -> Result<(), dsip_phone::Error> {
//! use dsip_phone::{Outcome, Phone};
//!
//! let me = dsip_phone::Identity::load(std::path::Path::new("alice"))?;
//! let phone = Phone::builder().identity(me).relay("wss://relay.example:8443/dsip").build().await?;
//! let mut call = phone.call("did:key:z6Mk…").await?;
//! match call.outcome().await {
//!     Outcome::Answered { answered_by } => {
//!         println!("answered ({answered_by}): media is flowing");
//!         call.hang_up();
//!     }
//!     Outcome::Ended { reason } => println!("not reached: {reason}"),
//! }
//! # Ok(()) }
//! ```
//!
//! A [`Phone`] runs its agent ([`dsip_transport::agent::Agent`]) and the media legs on a task of its own; the
//! application holds handles. [`Phone::call`] returns a [`Call`]; incoming calls arrive from [`Phone::incoming`] as
//! [`IncomingCall`]s to accept, screen or decline. Every protocol decision stays where it was: the endpoint core and
//! the call glue (`dsip_endpoint::calls`) choose what is sent, when media starts, and how a call answers by policy.
//!
//! Spec: §12.4 (a call's states: placed, ringing, answered, ended), §12.11 (cancel before the answer, bye after),
//! §14.1 (media only after the signed answer, done by the call glue), §14.3 (`answered_by`), §14.4 (screening).
//!
//! Impl: a call's state is read from the endpoint's session after each step; the reason it ended is the `reason` of
//! the message that ended it, or the engine's `Ended` emission in that step, or `unknown`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify};

pub use dsip_endpoint::calls::AcceptPolicy;
pub use dsip_endpoint::{AnswerPolicy, Invite};
pub use dsip_transport::agent::AgentConfig;
pub use dsip_transport::conn::Dialer;
pub use dsip_transport::identity::Identity;

mod error;
mod run;

pub use error::{Error, Result};

/// What media a phone has.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum Media {
    /// No media: calls are signalled, offers carry no SDP.
    #[default]
    None,
    /// Native WebRTC audio, one leg per call made from this configuration (a screening leg sends nothing, §14.4).
    #[cfg(feature = "media")]
    Native(dsip_media::MediaConfig),
}

/// Where a call is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallState {
    /// Placed; not yet ringing anywhere.
    Calling,
    /// Ringing: the callee's device alerts, or this incoming call waits on the user.
    Ringing,
    /// Answered (`answered_by`, §14.3).
    Answered {
        /// The `answered_by` token: `user`, `screening`, `gateway`, …
        answered_by: String,
    },
    /// Over.
    Ended {
        /// The reason token (§15), e.g. `user.hangup`, `user.busy`, `transport.no-response`.
        reason: String,
    },
}

/// How a call turned out: answered, or ended without an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It was answered.
    Answered {
        /// The `answered_by` token (§14.3).
        answered_by: String,
    },
    /// It ended without an answer.
    Ended {
        /// The reason token (§15).
        reason: String,
    },
}

/// What the phone's task is asked to do.
#[allow(clippy::large_enum_variant)] // a command is built once and consumed at once, as the agent's events are
enum Cmd {
    Place { to: String, invite: Invite, via: Option<String>, reply: oneshot::Sender<Result<Call>> },
    Call(dsip_endpoint::CallCommand),
    HangUp(String),
    Close,
}

/// The way to the phone's task.
#[derive(Clone)]
struct Line {
    cmds: mpsc::UnboundedSender<Cmd>,
    wake: Arc<Notify>,
}

impl Line {
    fn send(&self, cmd: Cmd) -> bool {
        let sent = self.cmds.send(cmd).is_ok();
        self.wake.notify_one();
        sent
    }
}

/// A phone: one device bound to its relay.
pub struct Phone {
    line: Line,
    relay_url: String,
    hints: Option<dsip_transport::hints::HintsClient>,
    incoming: Mutex<mpsc::UnboundedReceiver<IncomingCall>>,
    identity: String,
    device: String,
    task: Mutex<Option<tokio::task::JoinHandle<Result<()>>>>,
}

impl Phone {
    /// Start building a phone.
    pub fn builder() -> PhoneBuilder {
        PhoneBuilder::default()
    }

    /// The identity DID: what callers address.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The device DID.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Call `to` (an identity, ringing every device it has bound, or one device).
    pub async fn call(&self, to: &str) -> Result<Call> {
        self.call_with(to, Invite::default()).await
    }

    /// Call `to` with what the host adds to the invite (claims, the PSTN number asked of a gateway).
    ///
    /// With [`PhoneBuilder::hints`], a callee that has no DID document (a `did:key`) is looked up on the hints tier
    /// first (§8.1: discovery before the invite; a hint is used only for an identity with no document, rule 6): when
    /// its hint names another relay, the call goes through that relay ([`Call::via`]).
    pub async fn call_with(&self, to: &str, invite: Invite) -> Result<Call> {
        let via = self.relay_for(to).await;
        let (reply, answer) = oneshot::channel();
        if !self.line.send(Cmd::Place { to: to.into(), invite, via, reply }) {
            return Err(Error::Closed);
        }
        answer.await.map_err(|_| Error::Closed)?
    }

    /// The relay a callee's hint names, when it is not ours (§8.1).
    async fn relay_for(&self, to: &str) -> Option<String> {
        let hints = self.hints.as_ref()?;
        if !to.starts_with("did:key:") {
            return None; // §8.1 rule 6: an identity with a document is reached as its document says, never by a hint
        }
        let hint = hints.lookup(to, &dsip_core::did::StaticResolver::default(), dsip_transport::now_s()).await?;
        let relay = dsip_transport::hints::relay_of(&hint)?;
        tracing::info!("hint for {to}: relay {relay}, seq {}, signed by {} (a hint, not authority, §8.1)", hint.seq, hint.signer);
        (relay != self.relay_url).then_some(relay)
    }

    /// The next incoming call; `None` once the phone has closed.
    pub async fn incoming(&self) -> Option<IncomingCall> {
        self.incoming.lock().await.recv().await
    }

    /// Unbind and stop. Calls still up end `transport.closed` on this side.
    pub async fn close(&self) -> Result<()> {
        self.line.send(Cmd::Close);
        match self.task.lock().await.take() {
            Some(task) => task.await.map_err(|_| Error::Closed)?,
            None => Ok(()),
        }
    }
}

/// Builds a [`Phone`].
#[derive(Default)]
pub struct PhoneBuilder {
    identity: Option<Identity>,
    relay: Option<String>,
    tls: Option<Arc<rustls::ClientConfig>>,
    dialer: Option<Arc<dyn Dialer>>,
    answer: AnswerPolicy,
    recording: Option<AcceptPolicy>,
    media: Media,
    configure: Option<Configure>,
    hints: Option<dsip_transport::hints::HintsClient>,
}

/// An adjustment to the agent configuration ([`PhoneBuilder::configure`]).
type Configure = Box<dyn FnOnce(&mut AgentConfig) + Send>;

impl PhoneBuilder {
    /// The identity and device the phone acts as (required).
    pub fn identity(mut self, id: Identity) -> PhoneBuilder {
        self.identity = Some(id);
        self
    }

    /// The relay's `wss://` URL (required unless a [`PhoneBuilder::dialer`] reaches it).
    pub fn relay(mut self, url: &str) -> PhoneBuilder {
        self.relay = Some(url.into());
        self
    }

    /// Trust for the relay's certificate; native roots when unset.
    pub fn tls(mut self, tls: Arc<rustls::ClientConfig>) -> PhoneBuilder {
        self.tls = Some(tls);
        self
    }

    /// Reach the relay through this instead of dialing `wss` (an embedded relay, `dsip-testkit`).
    pub fn dialer(mut self, dialer: Arc<dyn Dialer>) -> PhoneBuilder {
        self.dialer = Some(dialer);
        self
    }

    /// What happens to an incoming call; [`AnswerPolicy::Ring`] when unset.
    pub fn answer(mut self, policy: AnswerPolicy) -> PhoneBuilder {
        self.answer = policy;
        self
    }

    /// What to do when the other side declares recording (C§4); asking the user when unset.
    pub fn recording(mut self, policy: AcceptPolicy) -> PhoneBuilder {
        self.recording = Some(policy);
        self
    }

    /// The phone's media; none when unset.
    pub fn media(mut self, media: Media) -> PhoneBuilder {
        self.media = media;
        self
    }

    /// Look callees up on these hints nodes before calling them: one bound to another relay is called through it
    /// (§8.1, [`Phone::call_with`]).
    pub fn hints(mut self, hints: dsip_transport::hints::HintsClient) -> PhoneBuilder {
        self.hints = Some(hints);
        self
    }

    /// Adjust the agent configuration the builder made (timers, sealing, first contact) before it connects.
    pub fn configure(mut self, f: impl FnOnce(&mut AgentConfig) + Send + 'static) -> PhoneBuilder {
        self.configure = Some(Box::new(f));
        self
    }

    /// Connect, bind, and start the phone's task. Call within a Tokio runtime.
    pub async fn build(self) -> Result<Phone> {
        let id = self.identity.ok_or(Error::Missing("identity"))?;
        let relay_url = match (self.relay, &self.dialer) {
            (Some(u), _) => u,
            (None, Some(_)) => "wss://relay.invalid/dsip".into(),
            (None, None) => return Err(Error::Missing("relay")),
        };
        let home = relay_url.clone();
        let has_media = !matches!(self.media, Media::None);
        let mut calls = dsip_endpoint::CallsConfig { media: has_media, answer: self.answer, ..Default::default() };
        if let Some(r) = self.recording {
            calls.recording = r;
        }
        let mut cfg = AgentConfig {
            relay_url,
            tls: self.tls,
            video: false,
            t_establish: None,
            t_ring: None,
            t_ring_local: None,
            first_contact_required: false,
            seal: false,
            did_resolver: None,
            calls: Some(calls),
            dialer: self.dialer,
            presence: None,
            peer_dialer: None,
        };
        if let Some(f) = self.configure {
            f(&mut cfg);
        }
        let agent = dsip_transport::agent::Agent::connect(id, cfg, dsip_core::did::StaticResolver::default()).await?;
        let (identity, device) = (agent.identity_did().to_string(), agent.device_did().to_string());
        let (cmds, cmds_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        let line = Line { cmds, wake: agent.waker() };
        let task = tokio::spawn(run::Runner::new(agent, cmds_rx, line.clone(), incoming_tx, self.media).run());
        Ok(Phone { line, relay_url: home, hints: self.hints, incoming: Mutex::new(incoming), identity, device, task: Mutex::new(Some(task)) })
    }
}

/// A call, placed or taken.
pub struct Call {
    session: String,
    via: Option<String>,
    state: watch::Receiver<CallState>,
    error: Arc<std::sync::Mutex<Option<String>>>,
    heard: Arc<std::sync::atomic::AtomicBool>,
    line: Line,
}

impl Call {
    /// The session id.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The relay the call goes through when it is not this phone's own: the one the callee's hint named (§8.1).
    pub fn via(&self) -> Option<&str> {
        self.via.as_deref()
    }

    /// Where the call is now.
    pub fn state(&self) -> CallState {
        self.state.borrow().clone()
    }

    /// The reason of the last signed `error` about this call, if one came: a relay that could not route the invite
    /// says so (`transport.unknown-recipient`, `transport.routing-refused`, §13.2). An error changes no state (§12.7
    /// rule 6): the call still ends by its timers, T-Establish for one never answered (§12.9).
    pub fn error(&self) -> Option<String> {
        self.error.lock().map(|e| e.clone()).unwrap_or(None)
    }

    /// Whether media from the other side has arrived: the first RTP packet, decrypted (native media only).
    pub fn media_received(&self) -> bool {
        self.heard.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Wait for the next change of state; the state it changed to, or `None` once the phone has closed.
    pub async fn changed(&mut self) -> Option<CallState> {
        self.state.changed().await.ok()?;
        Some(self.state())
    }

    /// Wait until the call is answered or ends.
    pub async fn outcome(&mut self) -> Outcome {
        loop {
            match self.state() {
                CallState::Answered { answered_by } => return Outcome::Answered { answered_by },
                CallState::Ended { reason } => return Outcome::Ended { reason },
                _ => {}
            }
            if self.state.changed().await.is_err() {
                return Outcome::Ended { reason: "transport.closed".into() };
            }
        }
    }

    /// Wait until the call ends; its reason.
    pub async fn ended(&mut self) -> String {
        loop {
            if let CallState::Ended { reason } = self.state() {
                return reason;
            }
            if self.state.changed().await.is_err() {
                return "transport.closed".into();
            }
        }
    }

    /// End the call: cancel it before the answer, decline it while it rings here, hang up after (§12.11).
    pub fn hang_up(&self) {
        self.line.send(Cmd::HangUp(self.session.clone()));
    }

    /// Ask the call glue for anything else ([`dsip_endpoint::CallCommand`]: escalate from screening, re-offer, accept
    /// or decline a declared recording, …).
    pub fn command(&self, cmd: dsip_endpoint::CallCommand) {
        self.line.send(Cmd::Call(cmd));
    }
}

/// A call coming in.
pub struct IncomingCall {
    /// The call.
    pub call: Call,
    /// The caller's identity, as verified (§7.4).
    pub from: String,
    /// The caller's display name: a claim, not verified (§18.2).
    pub display_name: Option<String>,
}

impl IncomingCall {
    /// Answer (`answered_by` `user`).
    pub fn accept(self) -> Call {
        self.call.command(dsip_endpoint::CallCommand::Accept { session: self.call.session.clone() });
        self.call
    }

    /// Answer in screening mode: a leg that sends nothing (§14.4); escalate later with
    /// [`dsip_endpoint::CallCommand::Escalate`].
    pub fn screen(self) -> Call {
        self.call.command(dsip_endpoint::CallCommand::Screen { session: self.call.session.clone() });
        self.call
    }

    /// Decline.
    pub fn decline(self) {
        self.call.command(dsip_endpoint::CallCommand::Decline { session: self.call.session.clone() });
    }
}
