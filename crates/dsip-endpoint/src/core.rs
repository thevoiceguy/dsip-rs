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

use crate::error::{Error, Result};
use crate::verify::{verify_frame_with, SeenIds};

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
    /// §10.4: seal outbound session bodies to the addressee's key agreement key when it can be resolved.
    pub seal: bool,
    /// §10.4: X25519 secrets this endpoint opens sealed bodies with, by the DID they belong to (its identity and
    /// its device); the one matching an inbound payload's `to` is used.
    pub unseal_keys: Vec<(String, [u8; 32])>,
    /// §8.1: when a frame is signed, or carries a delegation issued, under a `did:web` whose document the core does
    /// not hold, hold the frame and ask the host for the document ([`CoreEvent::Resolve`]) instead of verifying
    /// without it. The host answers with [`Core::resolved`]. A host that cannot fetch leaves this off.
    pub resolve_on_demand: bool,
}

/// Seconds a frame waits for the documents it needs before it is verified without them (and rejected).
pub const RESOLVE_WAIT_S: i64 = 10;
/// Seconds after a failed fetch before the core asks for the same DID again.
pub const RESOLVE_RETRY_S: i64 = 60;
/// Frames held at once, and DIDs asked for at once. A frame is held before its signature can be checked, so any
/// sender can cause a fetch (§8.4); past these bounds a frame is verified at once, as without on-demand resolution.
pub const RESOLVE_MAX_HELD: usize = 64;
/// See [`RESOLVE_MAX_HELD`].
pub const RESOLVE_MAX_PENDING: usize = 16;

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
    /// Pending introductions received, id → `[identity, device]` (§19.4 requests surface); a grant after a restart
    /// needs them.
    #[serde(default)]
    pub requests: std::collections::BTreeMap<String, (String, String)>,
    /// Introductions sent and not yet answered, id → recipient identity; a grant arriving after a restart needs them.
    #[serde(default)]
    pub pending_sent: std::collections::BTreeMap<String, String>,
    /// Out-of-band contact tokens issued and unused, token → grant id (single use; §19.4).
    #[serde(default)]
    pub tokens: std::collections::BTreeMap<String, String>,
    /// The signed grants we hold, by grant id, as compact serializations (`protected.payload.signature`): what a
    /// grantee presents where a grant is checked as a credential — a mailbox's `key-package-fetch` (M§14.2).
    ///
    /// Spec: §19.4 — "the grantee also holds the signed grant".
    #[serde(default)]
    pub grant_frames: std::collections::BTreeMap<String, String>,
}

/// What the core hands back to its host.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // an event is built once and consumed at once; boxing the message would cost an allocation per event
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
    /// Fetch the DID document of `did` (a `did:web`) and pass the outcome to [`Core::resolved`]. Emitted only with
    /// [`CoreConfig::resolve_on_demand`]; the frame that needs it is held meanwhile.
    Resolve {
        /// The DID.
        did: String,
    },
}

/// A frame held until the documents it needs arrive.
struct Held {
    frame: String,
    since: i64,
    dids: Vec<String>,
}

/// What a host adds to an invite it places.
#[derive(Debug, Clone, Default)]
pub struct Invite {
    /// The SDP offer, carried as the transport binding object (§16.3).
    pub sdp: Option<String>,
    /// `identity.claims` (§18.1: claims, never badges; e.g. a gateway's PSTN caller claim, a `tel` binding N§4).
    pub claims: Vec<Value>,
    /// Changes to this invite's offer.
    pub patch: InvitePatch,
}

/// Changes to one invite's offer.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct InvitePatch {
    /// Every media descriptor's `direction` (Recording Profile C§6: a recording session offers `sendonly`).
    #[serde(default)]
    pub direction: Option<String>,
    /// `recording_session` metadata (Recording Profile C§6).
    #[serde(default)]
    pub recording_session: Option<Value>,
    /// The PSTN number asked of the gateway named by `to` (N§4.1).
    #[serde(default)]
    pub destination: Option<Value>,
}

impl InvitePatch {
    fn is_empty(&self) -> bool {
        *self == InvitePatch::default()
    }
}

/// A host request: an engine event, with the data the host supplies for the message it sends.
///
/// Spec: none (infrastructure) — the engine events are [`LocalEvent`]; this adds what a host supplies beside them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Command {
    /// Place a call (`invite`).
    PlaceCall {
        /// Session (= invite) id.
        session: String,
        /// Addressed identity or device DID.
        to: String,
        /// What the host adds to the invite.
        invite: Invite,
    },
    /// Answer an offered session.
    Accept {
        /// Session id.
        session: String,
        /// `answered_by` (default `user`, §14.3).
        answered_by: Option<String>,
        /// The SDP answer (§16.3).
        sdp: Option<String>,
    },
    /// Send an `update`.
    Update {
        /// Session id.
        session: String,
        /// Update id.
        id: String,
        /// Optional role-transition signal (§14.4).
        answered_by: Option<String>,
        /// The SDP re-offer (§16.3).
        sdp: Option<String>,
    },
    /// Answer the peer's outstanding update.
    AnswerUpdate {
        /// Session id.
        session: String,
        /// The update id.
        in_reply_to: String,
        /// `answered_by` (default `user`).
        answered_by: Option<String>,
        /// The SDP answer (§16.3).
        sdp: Option<String>,
    },
    /// Send an `info` to the WebRTC binding (§12.12).
    Info {
        /// Session id.
        session: String,
        /// Its `data`, e.g. `{candidates, end_of_candidates}` (B§4).
        data: Value,
    },
    /// Any other engine event; it carries nothing from the host.
    Engine(LocalEvent),
}

impl From<LocalEvent> for Command {
    fn from(ev: LocalEvent) -> Command {
        Command::Engine(ev)
    }
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
    /// Signed grants held, by id, compact (§19.4; presented as credentials, M§14.2).
    grant_frames: std::collections::BTreeMap<String, String>,
    peer_delegations: Vec<Envelope>,
    /// `delegation-revocation` records this endpoint holds (§7.4, v0.8): applied to every verification.
    revocations: Vec<Envelope>,
    pending_sdp: Option<String>,
    /// Video codec ids the next offer lists (B§3.4 registry ids); a host sets them from the SDP it will supply.
    video_codecs: Vec<String>,
    /// This side's recording declaration (Recording Profile C§3), carried on every invite, answer and update.
    recording: Option<serde_json::Value>,
    /// Changes to the invite being placed (C§6, N§4.1).
    invite_patch: Option<InvitePatch>,
    /// `identity.claims` to put on the next invite (a gateway's PSTN caller claim, §18.1).
    pending_claims: Vec<Value>,
    pending_info_data: Option<Value>,
    counter: u64,
    /// Frames waiting for documents ([`CoreConfig::resolve_on_demand`]).
    held: Vec<Held>,
    /// DIDs asked of the host and not yet answered.
    resolving: std::collections::HashSet<String>,
    /// DIDs whose fetch failed, until when the core does not ask again.
    failed: HashMap<String, i64>,
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
            grant_frames: Default::default(),
            peer_delegations: vec![],
            revocations: vec![],
            pending_sdp: None,
            video_codecs: vec!["codec:video/h264".into()],
            recording: None,
            invite_patch: None,
            pending_claims: vec![],
            pending_info_data: None,
            counter: 0,
            held: vec![],
            resolving: Default::default(),
            failed: HashMap::new(),
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

    /// The X25519 key agreement key of `did`: converted from a `did:key`, or the `keyAgreement` of a resolved document.
    ///
    /// Spec: §10.4 rule 3, §7.2, §8.1 — never from a hint.
    fn key_agreement_of(&self, did: &str) -> Option<[u8; 32]> {
        match dsip_core::did::public_from_did_key(did) {
            Some(public) => dsip_core::hpke::x25519_from_ed25519_public(&public),
            None => dsip_core::did::Resolver::resolve(&self.resolver, did)?.x25519_key_agreement(),
        }
    }

    /// The unseal key for an inbound frame: the configured secret of the DID its payload is addressed `to`.
    ///
    /// Spec: §10.4 — a sealed body opens with the key of the DID in `to`.
    fn unseal_key_for(&self, frame: &str) -> Option<[u8; 32]> {
        if self.cfg.unseal_keys.is_empty() {
            return None;
        }
        let env = Envelope::from_frame(frame).ok()?;
        let p: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload)?).ok()?;
        let to = p.get("to")?.as_str()?;
        self.cfg.unseal_keys.iter().find(|(did, _)| did == to).map(|(_, sk)| *sk)
    }

    /// A fresh ULID at `now` (seconds), unique within the second.
    pub fn new_id(&mut self, now: i64) -> String {
        self.counter = (self.counter + 1) % 1000;
        Ulid::generate_at((now as u64) * 1000 + self.counter).to_string()
    }

    /// Seal outbound session bodies from now on, or stop (§10.4; a sender MAY resend in clear after
    /// `session.unsupported-critical-extension`).
    pub fn set_seal(&mut self, on: bool) {
        self.cfg.seal = on;
    }

    /// Whether outbound session bodies are sealed (§10.4).
    pub fn seal(&self) -> bool {
        self.cfg.seal
    }

    /// This side's recording declaration, `{state, recorder, purpose?}`, from now on (Recording Profile C§3): it
    /// rides on every `invite`, `answer` and `update` this endpoint sends; `None` sends none (meaning `off`).
    pub fn set_recording(&mut self, declaration: Option<serde_json::Value>) {
        self.recording = declaration;
    }


    /// Hold a DID document for resolution from now on (§8.1: a document is the authority for its DID; the host
    /// obtained it, as the CLI does with `--did-document`). `did:web` signers verify against it.
    pub fn add_document(&mut self, doc: dsip_core::did::DidDocument) {
        self.resolver.insert(doc);
    }

    /// Hold a `delegation-revocation` record: every later verification applies it (§7.4, v0.8: a verifier finds
    /// revocations "in any store they hold, however obtained").
    pub fn hold_revocation(&mut self, rev: Envelope) {
        if !self.revocations.contains(&rev) {
            self.revocations.push(rev);
        }
    }

    /// Whether `device` presented a delegation, verified now, that grants `capability` (e.g. `dsip.record`,
    /// Recording Profile C§6: the recording party checks its recorder before sending media).
    pub fn peer_has_capability(&self, device: &str, capability: &str, now: i64) -> bool {
        let ctx = Context::new(now, &self.resolver);
        self.peer_delegations.iter().any(|d| {
            dsip_core::delegation::names(d).is_some_and(|(subject, dev)| {
                dev == device && dsip_core::delegation::verify_delegation_for(d, &subject, &dev, capability, &ctx).ok()
            })
        })
    }


    /// Whether the next `invite`/`update` offers video (B§2.1: the descriptors must match the SDP the host
    /// supplies, and a host decides that per call).
    pub fn set_video(&mut self, video: bool) {
        self.cfg.video = video;
    }

    /// The video codecs the next offer lists, as registry ids (`codec:video/vp8`, …): they must have an `rtpmap`
    /// in the SDP the host supplies (B§3.4), so a host sets them from that SDP. Empty keeps the default (H.264).
    pub fn set_video_codecs(&mut self, ids: Vec<String>) {
        if !ids.is_empty() {
            self.video_codecs = ids;
        }
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
        self.ep.contacts.requests = file.requests.clone();
        self.ep.contacts.pending_sent = file.pending_sent.clone();
        self.ep.contacts.tokens = file.tokens.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.grant_frames = file.grant_frames.clone();
    }

    /// Export first-contact state.
    pub fn contacts(&self) -> ContactFile {
        ContactFile {
            allow: self.ep.contacts.allow.iter().cloned().collect(),
            grants_issued: self.ep.contacts.grants_issued.clone(),
            grants_held: self.ep.contacts.grants_held.clone(),
            identities: self.ep.identities().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            requests: self.ep.contacts.requests.clone(),
            pending_sent: self.ep.contacts.pending_sent.clone(),
            tokens: self.ep.contacts.tokens.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            grant_frames: self.grant_frames.clone(),
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
        let mut out = self.handle(em, now)?;
        // Frames that waited too long are verified with what the core holds.
        let (late, waiting): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held).into_iter().partition(|h| now - h.since >= RESOLVE_WAIT_S);
        self.held = waiting;
        for h in late {
            for did in &h.dids {
                if self.resolving.remove(did) {
                    self.failed.insert(did.clone(), now + RESOLVE_RETRY_S);
                }
            }
            out.extend(self.verify_inbound(&h.frame, now, false)?);
        }
        Ok(out)
    }

    /// When [`Core::tick`] next has work: the engine's next timer, or the time a held frame stops waiting.
    pub fn next_deadline(&self) -> Option<i64> {
        let held = self.held.iter().map(|h| h.since + RESOLVE_WAIT_S).min();
        match (self.ep.next_deadline(), held) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The outcome of a [`CoreEvent::Resolve`]: the document is held from now on (§8.1), and every frame that was
    /// waiting only for documents now held or failed is verified again.
    pub fn resolved(&mut self, did: &str, result: std::result::Result<dsip_core::did::DidDocument, dsip_core::did::ResolveError>, now: i64) -> Result<Vec<CoreEvent>> {
        self.resolving.remove(did);
        match result {
            Ok(doc) if doc.id == did => {
                self.failed.remove(did);
                self.resolver.insert(doc);
            }
            _ => {
                self.failed.insert(did.to_string(), now + RESOLVE_RETRY_S);
            }
        }
        let mut out = self.tick(now)?;
        let (ready, waiting): (Vec<Held>, Vec<Held>) =
            std::mem::take(&mut self.held).into_iter().partition(|h| h.dids.iter().all(|d| !self.resolving.contains(d)));
        self.held = waiting;
        for h in ready {
            out.extend(self.verify_inbound(&h.frame, now, true)?);
        }
        Ok(out)
    }

    /// A local request that carries nothing from the host (see [`Core::command`] for those that do).
    pub fn local(&mut self, ev: LocalEvent, now: i64) -> Result<Vec<CoreEvent>> {
        self.command(Command::Engine(ev), now)
    }

    /// A host request. What it carries goes into the message the engine sends for it, and only that message: a
    /// refused request leaves nothing behind for a later one.
    pub fn command(&mut self, cmd: Command, now: i64) -> Result<Vec<CoreEvent>> {
        let mut out = self.tick(now)?;
        let ev = match cmd {
            Command::PlaceCall { session, to, invite } => {
                self.pending_sdp = invite.sdp;
                self.pending_claims = invite.claims;
                self.invite_patch = (!invite.patch.is_empty()).then_some(invite.patch);
                LocalEvent::PlaceCall { session, to }
            }
            Command::Accept { session, answered_by, sdp } => {
                self.pending_sdp = sdp;
                LocalEvent::Accept { session, answered_by }
            }
            Command::Update { session, id, answered_by, sdp } => {
                self.pending_sdp = sdp;
                LocalEvent::Update { session, id, answered_by }
            }
            Command::AnswerUpdate { session, in_reply_to, answered_by, sdp } => {
                self.pending_sdp = sdp;
                LocalEvent::AnswerUpdate { session, in_reply_to, answered_by }
            }
            Command::Info { session, data } => {
                self.pending_info_data = Some(data);
                LocalEvent::Info { session }
            }
            Command::Engine(ev) => ev,
        };
        let em = self.ep.step(&Event::Local(ev));
        let handled = self.handle(em, now);
        self.pending_sdp = None;
        self.pending_claims.clear();
        self.invite_patch = None;
        self.pending_info_data = None;
        out.extend(handled?);
        Ok(out)
    }

    /// A frame arrived.
    pub fn inbound(&mut self, frame: &str, now: i64) -> Result<Vec<CoreEvent>> {
        let mut out = self.tick(now)?;
        out.extend(self.verify_inbound(frame, now, true)?);
        Ok(out)
    }

    /// Verify a record carried inside another message, such as a presence record in a `notify` body, and return its
    /// payload and the identity its signer acts for: the subject of a delegation it presents for itself (§7.4), else the
    /// signer. Nothing is recorded: the frame is not marked seen and no identity is learned. `None` when it does not
    /// verify, or names a `did:web` document the core does not hold.
    ///
    /// Spec: P§3 (a subscriber verifies each record independently of the authority), §10.2, §7.4.
    pub fn verify_record(&self, frame: &str, now: i64) -> Option<(Value, String)> {
        let mut seen = crate::verify::SeenIds::default();
        let sem = dsip_schema::SemanticContext { supported: self.supported.clone(), ..Default::default() };
        let inbound = verify_frame_with(frame, now, &self.resolver, &self.peer_delegations, &self.revocations, &mut seen, &sem).ok()?;
        let signer = inbound.verified.signer_did.clone();
        let ctx = Context::new(now, &self.resolver);
        let identity = inbound
            .verified
            .header
            .delegations
            .iter()
            .find_map(|d| {
                let (subject, device) = dsip_core::delegation::names(d)?;
                (device == signer && dsip_core::delegation::verify_delegation(d, &subject, &device, &ctx).ok()).then_some(subject)
            })
            .unwrap_or(signer);
        Some((inbound.verified.payload, identity))
    }

    /// The grants we hold from `target` that let us watch its presence, as `subscribe` `claims` entries
    /// `{"type": "dsip-grant", "grant": <the signed grant envelope>}`: live (`valid_until` after `now`), with
    /// `dsip.subscribe` in their scope, and whose signed bytes we kept.
    ///
    /// Spec: §9.3, P§6 (a grant presented in `claims` admits a presence subscriber), §19.4.
    pub fn presence_claims(&self, target: &str, now: i64) -> Vec<Value> {
        self.ep
            .contacts
            .grants_held
            .iter()
            .filter(|(_, g)| g.identity == target && g.valid_until > now && g.scope.iter().any(|s| s == "dsip.subscribe"))
            .filter_map(|(id, _)| {
                let mut parts = self.grant_frames.get(id)?.split('.');
                let (protected, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
                Some(json!({"type": "dsip-grant", "grant": {"protected": protected, "payload": payload, "signature": signature}}))
            })
            .collect()
    }

    /// A signed `grant-revocation` for a grant we issued, addressed to our authority (`to`), or `None` when we issued no
    /// grant `grant`. The host sends it before revoking the grant locally ([`LocalEvent::Revoke`]).
    ///
    /// Spec: §19.4, P§7 (spec-gap 147).
    pub fn grant_revocation(&mut self, grant: &str, authority: &str, now: i64) -> Result<Option<String>> {
        let Some(g) = self.ep.contacts.grants_issued.get(grant).cloned() else { return Ok(None) };
        let p = json!({"dsip": dsip_core::version::version_block(&self.supported, &[]), "type": "grant-revocation", "to": authority,
                       "grant": grant, "grantee": g.identity, "valid_until": g.valid_until});
        self.sign_payload(p, now, 30).map(Some)
    }

    fn rejected(&self, v: dsip_core::Verdict, mut out: Vec<CoreEvent>) -> Vec<CoreEvent> {
        out.push(CoreEvent::Rejected {
            code: v.code.and_then(|c| serde_json::to_value(c).ok()?.as_str().map(String::from)).unwrap_or_default(),
            detail: v.detail.unwrap_or_default(),
        });
        out
    }

    /// Verify `frame` and act on it. With `may_hold`, a frame naming a `did:web` document the core does not hold, and
    /// may still fetch, is held instead ([`CoreConfig::resolve_on_demand`]).
    fn verify_inbound(&mut self, frame: &str, now: i64, may_hold: bool) -> Result<Vec<CoreEvent>> {
        let mut out = vec![];
        // Held before verification, so nothing about the frame (its id as seen, a learned identity) is recorded until
        // it is verified with the documents it names. Without them a did:web signer fails `kid-unresolvable`, and a
        // did:web delegation is not learned (the frame then counts as from the bare device).
        if may_hold && self.cfg.resolve_on_demand {
            let dids: Vec<String> = dsip_core::did::missing_web_dids(frame, &self.resolver)
                .into_iter()
                .filter(|d| self.failed.get(d).is_none_or(|until| now >= *until))
                .collect();
            let new = dids.iter().filter(|d| !self.resolving.contains(*d)).count();
            if !dids.is_empty() && self.held.len() < RESOLVE_MAX_HELD && self.resolving.len() + new <= RESOLVE_MAX_PENDING {
                for did in &dids {
                    if self.resolving.insert(did.clone()) {
                        out.push(CoreEvent::Resolve { did: did.clone() });
                    }
                }
                self.held.push(Held { frame: frame.to_string(), since: now, dids });
                return Ok(out);
            }
        }
        let sem = dsip_schema::SemanticContext {
            supported: self.supported.clone(),
            unseal_key: self.unseal_key_for(frame),
            ..Default::default()
        };
        let inbound = match verify_frame_with(frame, now, &self.resolver, &self.peer_delegations, &self.revocations, &mut self.seen, &sem) {
            Ok(i) => i,
            Err(v) => {
                // Spec: §12.4 — an invalid invite gets "Send `error` or silently drop per policy".
                // Impl: drop, for every frame that fails verification (decided 2026-10-02): a reply would tell
                // a prober the identity exists and is reachable. Relays, which MUST reply (§13.3), still
                // give a sealed-body sender its `session.unsupported-critical-extension` (§10.4 fallback).
                return Ok(self.rejected(v, out));
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
        let msg = Message::from_payload(&p).ok_or(Error::PayloadShape("not a session message"))?;
        let display_name = p.pointer("/identity/display_name").and_then(Value::as_str).map(String::from);
        let session_scoped = !matches!(msg.msg_type.as_str(), "publish" | "unpublish" | "subscribe" | "notify" | "hello" | "reachability-hint" | "provenance" | "key-rotation" | "presence" | "grant-revocation");
        out.push(CoreEvent::Received { message: msg.clone(), identity, display_name, payload: p });
        if session_scoped {
            // Broadcast/subscription traffic (§9.3, §22) is handled by the host, not the §12 engine.
            let em = self.ep.step(&Event::Recv { recv: msg.clone() });
            if msg.msg_type == "grant" && self.ep.contacts.grants_held.contains_key(&msg.id) {
                // §19.4: the grantee holds the signed grant — the bytes as received, for presenting as a credential
                if let Ok(env) = Envelope::from_frame(frame) {
                    self.grant_frames.insert(msg.id.clone(), format!("{}.{}.{}", env.protected, env.payload, env.signature));
                }
            }
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
                offer.pointer("/transports/0/sdp")?;
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
            let codecs: Vec<Value> = self
                .video_codecs
                .iter()
                .map(|id| if id == "codec:video/h264" { json!({"id": id, "profiles": ["baseline"]}) } else { json!({"id": id}) })
                .collect();
            media.push(json!({"type": "video", "direction": "sendrecv", "codecs": codecs}));
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
            // §14.2 subset rule: an offered sendonly is answered recvonly and vice versa (C§6: a recorder receives)
            let direction = if screening {
                "recvonly"
            } else {
                match m["direction"].as_str().unwrap_or("sendrecv") {
                    "sendonly" => "recvonly",
                    "recvonly" => "sendonly",
                    other => other,
                }
            };
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
                if let Some(patch) = self.invite_patch.take() {
                    if let Some(d) = &patch.direction {
                        for m in p["media"].as_array_mut().into_iter().flatten() {
                            m["direction"] = d.as_str().into();
                        }
                    }
                    if let Some(rs) = patch.recording_session {
                        p["recording_session"] = rs; // C§6
                    }
                    if let Some(d) = patch.destination {
                        p["destination"] = d; // N§4.1: a tel URI for the gateway named by `to`
                    }
                    self.offers.insert(session.clone(), json!({"media": p["media"], "transports": p["transports"]}));
                }
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
            other => return Err(Error::UnsupportedType(other.to_string())),
        }
        if matches!(m.msg_type.as_str(), "invite" | "answer" | "update") {
            if let Some(r) = &self.recording {
                p["recording"] = r.clone(); // C§3: the sender's side, signed with the envelope
            }
        }
        p["issued_at"] = now.into();
        p["expires_at"] = (now + ttl).into();
        if self.cfg.seal {
            // §10.4: seal to the DID in `to` when its key agreement key resolves (did:key, or a document key); else clear
            if let Some(pk) = p["to"].as_str().and_then(|to| self.key_agreement_of(to)) {
                dsip_schema::sealed::seal(&mut p, &pk, &rand::random());
            }
        }
        // The device signs; its delegation rides in the header so peers can learn and verify the identity (spec-gap 8).
        Ok(sign_bytes(&serde_json::to_vec(&p)?, &self.keys.device, &self.keys.device.kid(), vec![self.keys.delegation.clone()]))
    }
}
