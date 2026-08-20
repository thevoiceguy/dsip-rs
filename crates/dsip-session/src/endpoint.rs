//! The endpoint state engine: every session this device participates in.
//!
//! Spec: §12.4 (states and transitions), §12.5 (cancel/answer race), §12.6
//! (glare), §12.7 (forked answers, initiator side), §12.8 (renegotiation),
//! §12.9 (timers), §12.10 (`progress`/queued timing), §12.11 (`cancel`),
//! §12.12 (`info`), §14.3–§14.4 (`answered_by`, screening).
//!
//! Every `Impl (spec-gap N)` comment has an entry in `impl/docs/spec-gaps.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dsip_core::registry::{effective_answered_by, effective_progress_status, resolve_reason, INFO_ABOUT};

use crate::event::{Emission, Event, LocalEvent, SendMsg};
use crate::message::Message;

/// T-Establish default and bounds (seconds). Spec: §12.9.
pub const T_ESTABLISH: (i64, i64, i64) = (15, 5, 60);
/// T-Ring default and bounds (seconds). Spec: §12.9.
pub const T_RING: (i64, i64, i64) = (120, 30, 300);
/// T-Queue hard cap (seconds). Spec: §12.9, §12.10.
pub const T_QUEUE_CAP: i64 = 1800;
/// T-Ring-Local default and bounds (seconds). Spec: §12.9.
pub const T_RING_LOCAL: (i64, i64, i64) = (120, 30, 300);
/// Consecutive re-queue limit. Spec: §12.10 (RECOMMENDED: 3).
pub const MAX_CONSECUTIVE_REQUEUES: u32 = 3;

fn clamp(v: i64, (_, lo, hi): (i64, i64, i64)) -> i64 {
    v.clamp(lo, hi)
}

/// Which side of the session this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Sent the invite.
    Initiator,
    /// Received the invite.
    Responder,
}

/// Session states.
///
/// Spec: §12.4 — initiator: IDLE, INVITING, PROCEEDING, ACTIVE, ENDING, ENDED;
/// responder: IDLE, OFFERED, ALERTING, ACTIVE, ENDED. IDLE is the absence of a
/// session. Impl (spec-gap 13): ENDING is collapsed into ENDED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(missing_docs)]
pub enum SessionState {
    Inviting,
    Proceeding,
    Offered,
    Alerting,
    Active,
    Ended,
}

/// Direction of an outstanding update relative to this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// We sent it (RENEGOTIATING sub-state, §12.8 rule 2).
    Outbound,
    /// The peer sent it; we owe an answer/reject.
    Inbound,
}

/// The one outstanding update a session may have (§12.8 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outstanding {
    /// Update id.
    pub id: String,
    /// Direction.
    pub direction: Direction,
}

/// Per-session state.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session id (= invite id, §12.2).
    pub id: String,
    /// Role.
    pub role: Role,
    /// State.
    pub state: SessionState,
    /// DID we address session messages to.
    pub peer: String,
    /// Initiator: the identity/device the invite addressed.
    pub invite_to: Option<String>,
    /// Responder: the invite's `expires_at`.
    pub invite_expires_at: Option<i64>,
    /// Initiator: the device whose answer was accepted.
    pub answered_device: Option<String>,
    /// Outstanding update, if any.
    pub outstanding: Option<Outstanding>,
    cancelled: bool,
    was_active: bool,
    post_answer_seen: bool,
    queue_count: u32,
}

impl Session {
    fn new(id: &str, role: Role, state: SessionState, peer: &str) -> Session {
        Session {
            id: id.into(),
            role,
            state,
            peer: peer.into(),
            invite_to: None,
            invite_expires_at: None,
            answered_device: None,
            outstanding: None,
            cancelled: false,
            was_active: false,
            post_answer_seen: false,
            queue_count: 0,
        }
    }

    /// RENEGOTIATING sub-state: our update is outstanding (§12.8 rule 2).
    pub fn renegotiating(&self) -> bool {
        matches!(&self.outstanding, Some(o) if o.direction == Direction::Outbound)
    }

    /// The README snapshot shape.
    pub fn snapshot(&self) -> Value {
        json!({
            "role": self.role,
            "state": self.state,
            "renegotiating": self.renegotiating(),
            "outstanding_update": self.outstanding,
        })
    }
}

#[derive(Debug, Clone)]
struct Timer {
    name: &'static str,
    session: String,
    deadline: i64,
    seq: u64,
}

/// Endpoint configuration.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// This device's DID.
    pub device: String,
    /// The identity this device acts for.
    pub identity: String,
    /// Known device→identity mapping (for glare detection, §12.6).
    pub identities: HashMap<String, String>,
    /// Clock at construction.
    pub start: i64,
    /// T-Establish (clamped to bounds).
    pub t_establish: i64,
    /// T-Ring (clamped to bounds).
    pub t_ring: i64,
    /// T-Ring-Local (clamped to bounds).
    pub t_ring_local: i64,
}

impl EndpointConfig {
    /// From a state vector's `context`.
    pub fn from_vector(ctx: &Value) -> EndpointConfig {
        let t = |k: &str, d: (i64, i64, i64)| clamp(ctx.pointer(&format!("/timers/{k}")).and_then(Value::as_i64).unwrap_or(d.0), d);
        EndpointConfig {
            device: ctx.pointer("/self/device").and_then(Value::as_str).unwrap_or("").into(),
            identity: ctx.pointer("/self/identity").and_then(Value::as_str).unwrap_or("").into(),
            identities: ctx
                .get("identities")
                .and_then(Value::as_object)
                .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                .unwrap_or_default(),
            start: ctx.get("start").and_then(Value::as_i64).unwrap_or(0),
            t_establish: t("t_establish", T_ESTABLISH),
            t_ring: t("t_ring", T_RING),
            t_ring_local: t("t_ring_local", T_RING_LOCAL),
        }
    }
}

/// The endpoint: sessions, timers, clock.
///
/// Spec: §12.4 "each endpoint maintains a per-session state machine; there is no shared network state."
pub struct Endpoint {
    cfg: EndpointConfig,
    /// Current clock (seconds).
    pub now: i64,
    sessions: HashMap<String, Session>,
    timers: Vec<Timer>,
    seq: u64,
    out: Vec<Emission>,
}

impl Endpoint {
    /// Create an endpoint.
    pub fn new(cfg: EndpointConfig) -> Endpoint {
        let now = cfg.start;
        Endpoint { cfg, now, sessions: HashMap::new(), timers: vec![], seq: 0, out: vec![] }
    }

    /// Look up a session.
    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Snapshot of the named sessions (`null` for unknown), README shape.
    pub fn snapshot(&self, ids: impl IntoIterator<Item = String>) -> Value {
        let mut m = serde_json::Map::new();
        for id in ids {
            m.insert(id.clone(), self.sessions.get(&id).map(Session::snapshot).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    /// Seconds until the next timer fires, if any (for a real scheduler).
    pub fn next_deadline(&self) -> Option<i64> {
        self.timers.iter().map(|t| t.deadline).min()
    }

    /// Drive one event; returns the emissions in order.
    pub fn step(&mut self, event: &Event) -> Vec<Emission> {
        self.out.clear();
        match event {
            Event::Advance { advance } => self.advance(*advance),
            Event::Recv { recv } => self.recv(recv),
            Event::Local(l) => self.local(l),
        }
        std::mem::take(&mut self.out)
    }

    // ------------------------------------------------------------ helpers

    fn identity_of<'a>(&'a self, did: &'a str) -> &'a str {
        self.cfg.identities.get(did).map(String::as_str).unwrap_or(did)
    }

    fn emit(&mut self, e: Emission) {
        self.out.push(e);
    }

    fn send(&mut self, m: SendMsg) {
        self.out.push(Emission::Send(m));
    }

    fn send_simple(&mut self, msg_type: &str, to: &str, session: &str, reason: Option<&str>) {
        self.send(SendMsg {
            msg_type: msg_type.into(),
            to: to.into(),
            session: session.into(),
            reason: reason.map(String::from),
            ..Default::default()
        });
    }

    fn error(&mut self, m: &Message, reason: &str) {
        self.send(SendMsg {
            msg_type: "error".into(),
            to: m.from.clone(),
            session: m.session.clone().unwrap_or_default(),
            reason: Some(reason.into()),
            in_reply_to: Some(m.id.clone()),
            ..Default::default()
        });
    }

    fn ui(&mut self, kind: &'static str) {
        self.emit(Emission::Ui { kind, field: None });
    }

    fn ui_with(&mut self, kind: &'static str, key: &'static str, v: &str) {
        self.emit(Emission::Ui { kind, field: Some((key, v.to_string())) });
    }

    fn running(&self, sid: &str, name: &str) -> bool {
        self.timers.iter().any(|t| t.session == sid && t.name == name)
    }

    fn start_timer(&mut self, sid: &str, name: &'static str, seconds: i64) {
        self.timers.retain(|t| !(t.session == sid && t.name == name));
        self.seq += 1;
        self.timers.push(Timer { name, session: sid.into(), deadline: self.now + seconds, seq: self.seq });
        self.emit(Emission::Timer { action: "start", name, seconds: Some(seconds) });
    }

    fn stop_timer(&mut self, sid: &str, name: &'static str) {
        if self.running(sid, name) {
            self.timers.retain(|t| !(t.session == sid && t.name == name));
            self.emit(Emission::Timer { action: "stop", name, seconds: None });
        }
    }

    fn stop_all(&mut self, sid: &str) {
        for name in ["T-Establish", "T-Ring", "T-Queue", "T-Ring-Local"] {
            self.stop_timer(sid, name);
        }
    }

    /// Terminal transition: stop timers, discard any pending update (§12.8 rule 6), optional media stop, ui ended.
    fn end(&mut self, sid: &str, ui_reason: Option<&str>, media_stop: bool) {
        self.stop_all(sid);
        if let Some(s) = self.sessions.get_mut(sid) {
            s.outstanding = None;
            s.state = SessionState::Ended;
        }
        if media_stop {
            self.emit(Emission::Media("stop"));
        }
        if let Some(r) = ui_reason {
            self.ui_with("ended", "reason", r);
        }
    }

    // ------------------------------------------------------------ clock

    /// Advance the clock; due timers fire in deadline order (ties by start order).
    pub fn advance(&mut self, seconds: i64) {
        let target = self.now + seconds;
        loop {
            let Some(t) = self.timers.iter().filter(|t| t.deadline <= target).min_by_key(|t| (t.deadline, t.seq)).cloned()
            else {
                break;
            };
            self.now = t.deadline;
            self.timers.retain(|x| x.seq != t.seq);
            self.fire(&t);
        }
        self.now = target;
    }

    fn fire(&mut self, t: &Timer) {
        self.emit(Emission::Timer { action: "fire", name: t.name, seconds: None });
        let Some(s) = self.sessions.get(&t.session).cloned() else { return };
        match (t.name, s.state) {
            ("T-Establish" | "T-Ring" | "T-Queue", SessionState::Inviting | SessionState::Proceeding) => {
                // §12.9: on expiry, cancel with reason session.timeout
                self.stop_all(&s.id);
                self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &s.id, Some("session.timeout"));
                self.sessions.get_mut(&s.id).expect("exists").cancelled = true;
                self.end(&s.id, Some("session.timeout"), false);
            }
            ("T-Ring-Local", SessionState::Alerting) => {
                // §12.9: on expiry, reject with reason user.no-answer
                self.send_simple("reject", &s.peer, &s.id, Some("user.no-answer"));
                self.end(&s.id, Some("user.no-answer"), false);
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ local events

    fn local(&mut self, ev: &LocalEvent) {
        if let LocalEvent::PlaceCall { session, to } = ev {
            let mut s = Session::new(session, Role::Initiator, SessionState::Inviting, to);
            s.invite_to = Some(to.clone());
            self.sessions.insert(session.clone(), s);
            self.send_simple("invite", to, session, None);
            let t = self.cfg.t_establish;
            self.start_timer(session, "T-Establish", t); // §12.9: started on sending invite
            return;
        }
        let Some(s) = self.sessions.get(ev.session()).cloned() else {
            self.emit(Emission::Refused("unknown-session"));
            return;
        };
        let sid = s.id.clone();
        match ev {
            LocalEvent::PlaceCall { .. } => unreachable!(),
            LocalEvent::Cancel { .. } => {
                if s.role == Role::Initiator && matches!(s.state, SessionState::Inviting | SessionState::Proceeding) {
                    self.stop_all(&sid);
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("user.cancelled"));
                    let m = self.sessions.get_mut(&sid).expect("exists");
                    m.cancelled = true;
                    m.state = SessionState::Ended;
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::Hangup { .. } => {
                if s.state == SessionState::Active {
                    // Impl (spec-gap 13): ENDING collapsed into ENDED
                    self.stop_all(&sid);
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    self.send_simple("bye", &s.peer, &sid, Some("user.hangup"));
                    self.emit(Emission::Media("stop"));
                    self.sessions.get_mut(&sid).expect("exists").state = SessionState::Ended;
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::Alert { ring_timeout, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Offered {
                    if self.now > s.invite_expires_at.unwrap_or(i64::MAX) {
                        // §12.4/§12.9: invite expires_at passed before alerting began
                        self.send_simple("reject", &s.peer, &sid, Some("session.expired"));
                        self.end(&sid, None, false);
                        return;
                    }
                    self.send(SendMsg {
                        msg_type: "progress".into(),
                        to: s.peer.clone(),
                        session: sid.clone(),
                        status: Some("ringing".into()),
                        ring_timeout: *ring_timeout,
                        ..Default::default()
                    });
                    self.sessions.get_mut(&sid).expect("exists").state = SessionState::Alerting;
                    // §12.9: T-Ring-Local SHOULD be ≤ the advertised ring_timeout
                    let secs = ring_timeout.map(|r| clamp(r, T_RING_LOCAL)).unwrap_or(self.cfg.t_ring_local);
                    self.start_timer(&sid, "T-Ring-Local", secs);
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::AutoReject { reason, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Offered {
                    self.send_simple("reject", &s.peer, &sid, Some(reason));
                    self.end(&sid, None, false);
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::Accept { answered_by, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Alerting {
                    self.stop_all(&sid);
                    self.send(SendMsg {
                        msg_type: "answer".into(),
                        to: s.peer.clone(),
                        session: sid.clone(),
                        answered_by: Some(answered_by.clone().unwrap_or_else(|| "user".into())),
                        ..Default::default()
                    });
                    let m = self.sessions.get_mut(&sid).expect("exists");
                    m.state = SessionState::Active;
                    m.was_active = true;
                    self.emit(Emission::Media("start"));
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::Decline { .. } => {
                if s.role == Role::Responder && s.state == SessionState::Alerting {
                    self.stop_all(&sid);
                    self.send_simple("reject", &s.peer, &sid, Some("user.declined"));
                    self.end(&sid, None, false);
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
            LocalEvent::Update { id, answered_by, .. } => {
                if s.state != SessionState::Active {
                    self.emit(Emission::Refused("invalid-state"));
                } else if s.outstanding.is_some() {
                    self.emit(Emission::Refused("update-pending")); // §12.8 rule 2: one outstanding, both directions
                } else {
                    self.send(SendMsg {
                        msg_type: "update".into(),
                        to: s.peer.clone(),
                        session: sid.clone(),
                        id: Some(id.clone()),
                        answered_by: answered_by.clone(),
                        ..Default::default()
                    });
                    self.sessions.get_mut(&sid).expect("exists").outstanding =
                        Some(Outstanding { id: id.clone(), direction: Direction::Outbound });
                }
            }
            LocalEvent::AnswerUpdate { in_reply_to, .. } | LocalEvent::RejectUpdate { in_reply_to, .. } => {
                let pending_inbound = s.state == SessionState::Active
                    && matches!(&s.outstanding, Some(o) if o.direction == Direction::Inbound && &o.id == in_reply_to);
                if !pending_inbound {
                    self.emit(Emission::Refused("no-pending-update"));
                    return;
                }
                match ev {
                    LocalEvent::AnswerUpdate { answered_by, .. } => {
                        self.send(SendMsg {
                            msg_type: "answer".into(),
                            to: s.peer.clone(),
                            session: sid.clone(),
                            answered_by: Some(answered_by.clone().unwrap_or_else(|| "user".into())),
                            in_reply_to: Some(in_reply_to.clone()),
                            ..Default::default()
                        });
                        self.emit(Emission::Media("apply_update"));
                    }
                    LocalEvent::RejectUpdate { reason, .. } => {
                        self.send(SendMsg {
                            msg_type: "reject".into(),
                            to: s.peer.clone(),
                            session: sid.clone(),
                            reason: Some(reason.clone()),
                            in_reply_to: Some(in_reply_to.clone()),
                            ..Default::default()
                        });
                    }
                    _ => unreachable!(),
                }
                self.sessions.get_mut(&sid).expect("exists").outstanding = None;
            }
            LocalEvent::Info { .. } => {
                if s.state == SessionState::Active {
                    self.send_simple("info", &s.peer, &sid, None);
                } else {
                    self.emit(Emission::Refused("invalid-state"));
                }
            }
        }
    }

    // ------------------------------------------------------------ received messages

    fn recv(&mut self, m: &Message) {
        let t = m.msg_type.as_str();
        if t == "invite" {
            return self.recv_invite(m);
        }
        if t == "error" {
            let r = m.reason.clone().unwrap_or_default();
            self.ui_with("error", "reason", &r);
            return;
        }
        let Some(s) = m.session.as_ref().and_then(|sid| self.sessions.get(sid)).cloned() else {
            self.error(m, "session.unknown-session"); // §12.2
            return;
        };
        if s.state == SessionState::Ended {
            if t == "answer" && s.role == Role::Initiator && m.in_reply_to.is_none() {
                // §12.5 rule 3 / §12.7 rule 4: late answers to a finished attempt
                let reason = if s.cancelled {
                    "session.cancelled"
                } else if s.was_active {
                    "session.already-answered"
                } else {
                    "session.failed" // Impl (spec-gap 12)
                };
                self.send_simple("bye", &m.from, &s.id, Some(reason));
            } else {
                self.emit(Emission::Drop("ended-session"));
            }
            return;
        }
        if s.role == Role::Responder && s.state == SessionState::Active && t != "cancel" {
            self.sessions.get_mut(&s.id).expect("exists").post_answer_seen = true;
        }
        match t {
            "progress" => self.recv_progress(&s, m),
            "answer" => self.recv_answer(&s, m),
            "reject" => self.recv_reject(&s, m),
            "cancel" => self.recv_cancel(&s, m),
            "update" => self.recv_update(&s, m),
            "info" => self.recv_info(&s, m),
            "bye" => self.recv_bye(&s, m),
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_invite(&mut self, m: &Message) {
        let sid = m.id.clone();
        // §12.6 glare: an outbound invite to the identity this invite comes from
        let from_identity = self.identity_of(&m.from).to_string();
        let glare = self
            .sessions
            .values()
            .find(|s| {
                s.role == Role::Initiator
                    && matches!(s.state, SessionState::Inviting | SessionState::Proceeding)
                    && self.identity_of(s.invite_to.as_deref().unwrap_or("")) == from_identity
            })
            .cloned();
        if glare.is_none() {
            if let Some(existing) = self.sessions.get(&sid) {
                if existing.state == SessionState::Ended {
                    self.emit(Emission::Drop("ended-session"));
                } else {
                    let probe = Message { session: Some(sid.clone()), ..m.clone() };
                    self.error(&probe, "session.invalid-state");
                }
                return;
            }
        }
        if let Some(g) = glare {
            if g.id < sid {
                // We win: reject the inbound losing invite; proceed as initiator.
                self.send_simple("reject", &m.from, &sid, Some("session.glare"));
                self.sessions.insert(sid.clone(), Session::new(&sid, Role::Responder, SessionState::Ended, &m.from));
                return;
            }
            // We lose (or pathological equal id): withdraw our invite.
            // Impl (spec-gap 2): the loser withdraws via `cancel session.glare`.
            self.stop_all(&g.id);
            self.send_simple("cancel", g.invite_to.as_deref().unwrap_or(""), &g.id, Some("session.glare"));
            let gm = self.sessions.get_mut(&g.id).expect("exists");
            gm.cancelled = true;
            gm.state = SessionState::Ended;
            self.ui_with("ended", "reason", "session.glare");
            if g.id == sid {
                // §12.6: equal ids — both invites rejected; MAY retry after 1–4 s
                self.send_simple("reject", &m.from, &sid, Some("session.glare"));
                self.ui("glare_retry");
                return;
            }
        }
        let mut s = Session::new(&sid, Role::Responder, SessionState::Offered, &m.from);
        s.invite_to = m.to.clone();
        s.invite_expires_at = m.expires_at;
        self.sessions.insert(sid, s);
        self.ui("offered");
    }

    fn recv_progress(&mut self, s: &Session, m: &Message) {
        if s.role != Role::Initiator || !matches!(s.state, SessionState::Inviting | SessionState::Proceeding) {
            return self.error(m, "session.invalid-state");
        }
        let sid = s.id.clone();
        let status = effective_progress_status(m.status.as_deref().unwrap_or("")).to_string();
        self.stop_timer(&sid, "T-Establish"); // §12.9: stopped by first progress
        self.sessions.get_mut(&sid).expect("exists").state = SessionState::Proceeding;
        self.ui_with("progress", "status", &status);
        match status.as_str() {
            "ringing" => {
                self.sessions.get_mut(&sid).expect("exists").queue_count = 0;
                self.stop_timer(&sid, "T-Queue"); // §12.10: subsequent ringing cancels T-Queue
                if let Some(rt) = m.ring_timeout {
                    // §12.9: responder MAY extend via ring_timeout; honored up to the upper bound.
                    // Impl (spec-gap 4): a ringing progress carrying ring_timeout (re)starts T-Ring.
                    self.start_timer(&sid, "T-Ring", clamp(rt, T_RING));
                } else if !self.running(&sid, "T-Ring") {
                    let t = self.cfg.t_ring;
                    self.start_timer(&sid, "T-Ring", t);
                }
            }
            "queued" => {
                let sm = self.sessions.get_mut(&sid).expect("exists");
                sm.queue_count += 1;
                if sm.queue_count > MAX_CONSECUTIVE_REQUEUES {
                    // Impl (spec-gap 11): exceeding the re-queue limit is treated as T-Queue expiry.
                    self.stop_all(&sid);
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("session.timeout"));
                    self.sessions.get_mut(&sid).expect("exists").cancelled = true;
                    self.end(&sid, Some("session.timeout"), false);
                    return;
                }
                self.stop_timer(&sid, "T-Ring"); // §12.10: queued suspends T-Ring
                self.start_timer(&sid, "T-Queue", m.queue_timeout.unwrap_or(T_QUEUE_CAP).min(T_QUEUE_CAP));
            }
            _ => {
                // Impl (spec-gap 4): trying/forwarded start T-Ring as the backstop.
                if !self.running(&sid, "T-Ring") && !self.running(&sid, "T-Queue") {
                    let t = self.cfg.t_ring;
                    self.start_timer(&sid, "T-Ring", t);
                }
            }
        }
    }

    fn recv_answer(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        if s.role != Role::Initiator && !(s.state == SessionState::Active && m.in_reply_to.is_some()) {
            // Responders only ever receive answers to their own updates (§12.8 rule 1)
            return self.error(m, "session.invalid-state");
        }
        match s.state {
            SessionState::Inviting | SessionState::Proceeding => {
                if m.in_reply_to.is_some() {
                    return self.error(m, "session.invalid-state");
                }
                // §12.7 rule 2: first accepted answer establishes the session
                self.stop_all(&sid);
                {
                    let sm = self.sessions.get_mut(&sid).expect("exists");
                    sm.state = SessionState::Active;
                    sm.was_active = true;
                    sm.answered_device = Some(m.from.clone());
                    sm.peer = m.from.clone();
                }
                self.emit(Emission::Media("start"));
                let ab = effective_answered_by(m.answered_by.as_deref().unwrap_or("")).to_string();
                self.ui_with("answered", "answered_by", &ab);
                if s.invite_to.as_deref() != Some(m.from.as_str()) {
                    // §12.4/§12.7 rule 3; Impl (spec-gap 5): forked inferred from answer.from ≠ invite.to
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("session.answered-elsewhere"));
                }
            }
            SessionState::Active => {
                if let Some(irt) = &m.in_reply_to {
                    if matches!(&s.outstanding, Some(o) if o.direction == Direction::Outbound && &o.id == irt) {
                        self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                        self.emit(Emission::Media("apply_update"));
                    } else {
                        self.emit(Emission::Drop("stale-update-reply"));
                    }
                } else if s.answered_device.as_deref() != Some(m.from.as_str()) {
                    // §12.7 rule 4: later answer from another leg
                    self.send_simple("bye", &m.from, &sid, Some("session.already-answered"));
                } else {
                    self.error(m, "session.invalid-state");
                }
            }
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_reject(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "reject").effective;
        if s.role == Role::Initiator
            && matches!(s.state, SessionState::Inviting | SessionState::Proceeding)
            && m.in_reply_to.is_none()
        {
            self.end(&sid, Some(&reason), false);
            return;
        }
        if s.state == SessionState::Active {
            if let Some(irt) = &m.in_reply_to {
                if matches!(&s.outstanding, Some(o) if o.direction == Direction::Outbound && &o.id == irt) {
                    // §12.8 rule 5: rejected update leaves the session in its prior state
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    self.ui_with("update_rejected", "reason", &reason);
                } else {
                    self.emit(Emission::Drop("stale-update-reply"));
                }
                return;
            }
        }
        self.error(m, "session.invalid-state");
    }

    fn recv_cancel(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "cancel").effective;
        if s.role != Role::Responder {
            return self.error(m, "session.invalid-state");
        }
        match s.state {
            SessionState::Offered => self.end(&sid, Some(&reason), false),
            SessionState::Alerting => {
                self.stop_all(&sid);
                if reason != "session.answered-elsewhere" {
                    // §12.4/§12.11: answered-elsewhere MUST NOT surface as a missed call
                    self.ui("missed_call");
                }
                self.end(&sid, Some(&reason), false);
            }
            SessionState::Active => {
                if !s.post_answer_seen {
                    // §12.5 rule 2: crossed cancel — teardown, no error. Impl (spec-gap 1).
                    self.end(&sid, Some(&reason), true);
                } else {
                    // §12.4/§12.11: cancel for an ACTIVE session
                    self.error(m, "session.invalid-state");
                }
            }
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_update(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state");
        }
        if let Some(o) = &s.outstanding {
            match o.direction {
                Direction::Outbound => {
                    // §12.8 rule 3: update glare → smaller id proceeds
                    if o.id < m.id {
                        self.send(SendMsg {
                            msg_type: "reject".into(),
                            to: m.from.clone(),
                            session: sid,
                            reason: Some("session.glare".into()),
                            in_reply_to: Some(m.id.clone()),
                            ..Default::default()
                        });
                        return;
                    }
                    self.ui_with("update_rejected", "reason", "session.glare");
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                }
                Direction::Inbound => {
                    // §12.8 rule 4; Impl (spec-gap 3): both discarded
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    self.error(m, "session.update-pending");
                    return;
                }
            }
        }
        self.sessions.get_mut(&sid).expect("exists").outstanding =
            Some(Outstanding { id: m.id.clone(), direction: Direction::Inbound });
        self.ui("update_offered");
        if let Some(ab) = &m.answered_by {
            // §14.4 step 3: escalation signal
            let ab = effective_answered_by(ab).to_string();
            self.ui_with("answered", "answered_by", &ab);
        }
    }

    fn recv_info(&mut self, s: &Session, m: &Message) {
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state"); // §12.12: ACTIVE-only
        }
        match m.about.as_deref() {
            Some(a) if INFO_ABOUT.contains(&a) => self.emit(Emission::Info { about: a.to_string() }),
            _ => self.emit(Emission::Drop("unknown-about")), // §12.12: never critical
        }
    }

    fn recv_bye(&mut self, s: &Session, m: &Message) {
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state");
        }
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "bye").effective;
        self.end(&s.id.clone(), Some(&reason), true);
    }
}
