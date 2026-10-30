//! The relay's status page (`--status-listen`): bound devices, sessions as this relay has seen them, the
//! store-and-forward queues against their budget, what it refused and why, and what it holds in memory.
//!
//! Spec: none (infrastructure). A relay sees a session's signaling only (§12): a session is *ringing* from its
//! `invite` until an answer or the attempt's outcome, *answered* until a `bye` or `cancel`. Media never crosses the
//! relay, so a call whose `bye` never came here is dropped as `stale` after [`ANSWERED_STALE_S`] of silence.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use dsip_transport::status::{Metrics, Page, JSON_TYPE, METRICS_TYPE};

use crate::State;

/// A ringing session with no answer or outcome seen for this long is dropped as `stale` (an invite lives far less).
pub const RINGING_STALE_S: i64 = 600;
/// An answered session with no signaling seen for this long is dropped as `stale` (its `bye` went elsewhere or
/// never came).
pub const ANSWERED_STALE_S: i64 = 12 * 3600;

/// A session as this relay has seen it.
#[derive(Debug, Clone)]
pub struct Session {
    state: &'static str,
    from: String,
    to: String,
    started: i64,
    answered: Option<i64>,
    last: i64,
}

/// Counters since the relay started, and the sessions it is following.
#[derive(Debug, Default)]
pub struct Stats {
    started: i64,
    frames_in: BTreeMap<String, u64>,
    refused: BTreeMap<(String, String), u64>,
    binds: u64,
    unbinds: u64,
    tls_failed: u64,
    sessions: BTreeMap<String, Session>,
    sessions_started: u64,
    sessions_answered: u64,
    sessions_ended: BTreeMap<&'static str, u64>,
}

impl Stats {
    /// Counters from `now`.
    pub fn new(now: i64) -> Stats {
        Stats { started: now, ..Default::default() }
    }

    /// A verified frame from a bound device, by type.
    pub fn frame_in(&mut self, msg_type: &str) {
        *self.frames_in.entry(msg_type.to_string()).or_default() += 1;
    }

    /// A refusal this relay signed (or a `hello` it closed on), by reason token and the detail's code token.
    pub fn refused(&mut self, reason: &str, detail: Option<&str>) {
        let code = detail.map(|d| d.split(':').next().unwrap_or("").trim().to_string()).unwrap_or_default();
        *self.refused.entry((reason.to_string(), code)).or_default() += 1;
    }

    /// A device bound.
    pub fn bound(&mut self) {
        self.binds += 1;
    }

    /// A device's connection ended.
    pub fn unbound(&mut self) {
        self.unbinds += 1;
    }

    /// A TLS handshake failed.
    pub fn tls_failed(&mut self) {
        self.tls_failed += 1;
    }

    /// A session message this relay is about to route: follow the session's state.
    pub fn observe(&mut self, msg_type: &str, session: &str, from: &str, to: &str, now: i64) {
        if session.is_empty() {
            return;
        }
        match msg_type {
            "invite" => {
                if !self.sessions.contains_key(session) {
                    self.sessions_started += 1;
                    self.sessions.insert(session.to_string(), Session { state: "ringing", from: from.into(), to: to.into(), started: now, answered: None, last: now });
                }
            }
            "answer" => {
                if let Some(s) = self.sessions.get_mut(session) {
                    if s.state == "ringing" {
                        s.state = "answered";
                        s.answered = Some(now);
                        self.sessions_answered += 1;
                    }
                    s.last = now;
                }
            }
            "bye" => self.end(session, "bye"),
            // a cancel ends an attempt still ringing; after an answer it only stops the other legs (§12.5)
            "cancel" if self.sessions.get(session).is_some_and(|s| s.state == "ringing") => self.end(session, "cancel"),
            _ => {
                if let Some(s) = self.sessions.get_mut(session) {
                    s.last = now;
                }
            }
        }
    }

    /// The attempt's outcome was a reject, or no leg answered (§12.7 rule 6): the session never started.
    pub fn attempt_failed(&mut self, session: &str, how: &'static str) {
        if self.sessions.get(session).is_some_and(|s| s.state == "ringing") {
            self.end(session, how);
        }
    }

    fn end(&mut self, session: &str, how: &'static str) {
        if self.sessions.remove(session).is_some() {
            *self.sessions_ended.entry(how).or_default() += 1;
        }
    }

    /// Drop sessions this relay will not hear the end of.
    pub fn prune(&mut self, now: i64) {
        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now - s.last > if s.state == "ringing" { RINGING_STALE_S } else { ANSWERED_STALE_S })
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.end(&k, "stale");
        }
    }
}

fn count(st: &State, state: &str) -> usize {
    st.stats.sessions.values().filter(|s| s.state == state).count()
}

/// The `/status` JSON.
pub fn status(st: &State, now: i64, detail: bool) -> Value {
    let s = &st.stats;
    let queued: usize = st.tracker.inbox.values().map(Vec::len).sum();
    let (attempts, invites) = st.tracker.held();
    let mut v = json!({
        "relay": st.key.did(),
        "version": env!("CARGO_PKG_VERSION"),
        "now": now,
        "uptime_s": now - s.started,
        "scope": match &st.served { Some(set) => json!({"private": set.len()}), None => json!("open") },
        "connections": {"devices_bound": st.devices.len(), "identities_bound": st.identities.values().filter(|d| !d.is_empty()).count()},
        "sessions": {
            "ringing": count(st, "ringing"), "answered": count(st, "answered"),
            "started_total": s.sessions_started, "answered_total": s.sessions_answered, "ended_total": s.sessions_ended,
        },
        "queues": {
            "recipients": st.tracker.inbox.values().filter(|q| !q.is_empty()).count(), "envelopes": queued,
            "bytes": st.queued_bytes(), "budget_bytes": st.queue_budget_bytes,
            "inbox_cap": st.inbox_cap, "offline_retention_s": st.offline_retention,
        },
        "introductions": {"limit": st.intro_limit, "window_s": st.intro_window},
        "totals": {
            "binds": s.binds, "unbinds": s.unbinds, "tls_failed": s.tls_failed,
            "frames_in": s.frames_in,
            "refused": s.refused.iter().map(|((r, c), n)| json!({"reason": r, "detail": c, "count": n})).collect::<Vec<_>>(),
        },
        "held": {
            "frames": st.frames.len(), "attempts": attempts, "invites": invites,
            "reject_frames": st.reject_frames.len(), "intro_keys": st.intro_log.len(),
            "publications": st.records.len(), "revocations": st.revocations.len(),
        },
    });
    if detail {
        v["sessions"]["list"] = s
            .sessions
            .iter()
            .map(|(id, x)| json!({"session": id, "state": x.state, "from": x.from, "to": x.to, "age_s": now - x.started,
                "answered_s": x.answered.map(|a| now - a), "idle_s": now - x.last}))
            .collect();
        v["connections"]["identities"] = st
            .identities
            .iter()
            .filter(|(_, d)| !d.is_empty())
            .map(|(i, d)| (i.clone(), json!(d.iter().collect::<Vec<_>>())))
            .collect::<serde_json::Map<_, _>>()
            .into();
        v["queues"]["by_recipient"] = st
            .tracker
            .inbox
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(to, q)| {
                let next = q.iter().map(|m| m.deadline).min().unwrap_or(now);
                (to.clone(), json!({"envelopes": q.len(), "types": q.iter().map(|m| m.message.msg_type.as_str()).collect::<Vec<_>>(), "next_drop_in_s": next - now}))
            })
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    v
}

/// The `/metrics` text.
pub fn metrics(st: &State, now: i64) -> String {
    let s = &st.stats;
    let mut m = Metrics::default();
    m.gauge("dsip_relay_uptime_seconds", "Seconds since the relay started.", &[], now - s.started);
    m.gauge("dsip_relay_devices_bound", "Devices bound now (§13.2).", &[], st.devices.len() as i64);
    m.gauge("dsip_relay_identities_bound", "Identities with at least one bound device.", &[], st.identities.values().filter(|d| !d.is_empty()).count() as i64);
    for state in ["ringing", "answered"] {
        m.gauge("dsip_relay_sessions", "Sessions this relay is following, by state.", &[("state", state)], count(st, state) as i64);
    }
    m.counter("dsip_relay_sessions_started_total", "Sessions whose invite this relay routed.", &[], s.sessions_started);
    m.counter("dsip_relay_sessions_answered_total", "Sessions answered.", &[], s.sessions_answered);
    for (how, n) in &s.sessions_ended {
        m.counter("dsip_relay_sessions_ended_total", "Sessions ended, by how (bye, cancel, reject, no-response, stale).", &[("how", how)], *n);
    }
    let queued: usize = st.tracker.inbox.values().map(Vec::len).sum();
    m.gauge("dsip_relay_queued_envelopes", "Envelopes held for offline recipients (§13.3).", &[], queued as i64);
    m.gauge("dsip_relay_queued_bytes", "Bytes held for offline recipients.", &[], st.queued_bytes() as i64);
    m.gauge("dsip_relay_queue_budget_bytes", "The store-and-forward budget (--queue-budget-bytes).", &[], st.queue_budget_bytes as i64);
    m.counter("dsip_relay_binds_total", "Devices bound since start.", &[], s.binds);
    m.counter("dsip_relay_unbinds_total", "Device connections ended since start.", &[], s.unbinds);
    m.counter("dsip_relay_tls_failed_total", "TLS handshakes that failed.", &[], s.tls_failed);
    for (t, n) in &s.frames_in {
        m.counter("dsip_relay_frames_in_total", "Verified frames from bound devices, by type.", &[("type", t)], *n);
    }
    for ((r, c), n) in &s.refused {
        m.counter("dsip_relay_refused_total", "Refusals, by reason token and detail code.", &[("reason", r), ("detail", c)], *n);
    }
    let (attempts, invites) = st.tracker.held();
    for (what, n) in [("frames", st.frames.len()), ("attempts", attempts), ("invites", invites),
        ("reject_frames", st.reject_frames.len()), ("intro_keys", st.intro_log.len())] {
        m.gauge("dsip_relay_held", "Entries held in memory, by table.", &[("table", what)], n as i64);
    }
    m.finish()
}

/// Answer one status request.
pub async fn render(state: std::sync::Arc<tokio::sync::Mutex<State>>, page: Page) -> (&'static str, String) {
    let mut st = state.lock().await;
    let now = dsip_transport::now_s();
    st.advance();
    match page {
        Page::Status { detail } => (JSON_TYPE, format!("{:#}\n", status(&st, now, detail))),
        Page::Metrics => (METRICS_TYPE, metrics(&st, now)),
        Page::Admin { command, .. } => (JSON_TYPE, format!("{:#}\n", admin(&st, &command, now))),
    }
}

/// The admin commands, for the binary's `admin` subcommand.
pub const ADMIN_COMMANDS: &[dsip_transport::admin::Command] = &[dsip_transport::admin::Command {
    name: "bindings",
    about: "The devices bound now: identity, device, the address each bound from, and for how long",
    arg: None,
    write: false,
    show: show_bindings,
}];

fn admin(st: &State, command: &str, now: i64) -> Value {
    match command {
        "bindings" => {
            let mut rows: Vec<_> = st.bound_at.iter().filter(|(d, _)| st.devices.contains_key(*d)).collect();
            rows.sort_by(|a, b| (&a.1 .0, a.0).cmp(&(&b.1 .0, b.0)));
            json!({
                "devices_bound": rows.len(),
                "identities_bound": st.identities.values().filter(|d| !d.is_empty()).count(),
                "bindings": rows.iter().map(|(device, (identity, peer, since))| json!({"identity": identity, "device": device,
                    "peer": peer, "bound_s": now - since,
                    "queued": st.tracker.inbox.get(*device).map_or(0, Vec::len)})).collect::<Vec<_>>(),
            })
        }
        _ => json!({"error": format!("no admin command {command:?} (bindings)")}),
    }
}

fn show_bindings(v: &Value) -> String {
    let mut out = format!("{} devices bound, {} identities\n", v["devices_bound"], v["identities_bound"]);
    let mut last = "";
    for b in v["bindings"].as_array().into_iter().flatten() {
        let identity = b["identity"].as_str().unwrap_or("?");
        if identity != last {
            out += &format!("{identity}\n");
            last = identity;
        }
        let s = b["bound_s"].as_i64().unwrap_or(0);
        let since = if s < 120 { format!("{s} s") } else if s < 7200 { format!("{} min", s / 60) } else { format!("{} h", s / 3600) };
        out += &format!("  {}  from {}, bound {since}\n", b["device"].as_str().unwrap_or("?"), b["peer"].as_str().unwrap_or("?"));
    }
    out
}
