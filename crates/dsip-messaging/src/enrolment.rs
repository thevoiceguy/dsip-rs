//! Whom a mailbox service serves, and when an enrolment ends.
//!
//! Spec: M§4.1 ("Whom a mailbox serves", "When an enrolment ends"), M§4.4 (a registered device completed a verified
//! `hello` within `mls_retention_s`), M§5.7 (`release`), M§16 (`mailbox.not-served`, `mailbox.not-enrolled`).
//!
//! Impl: pinned by the `enrolment-trace` vectors (spec-gaps 115, 130). The machine decides; the host acts on what it
//! emits: `enrolled` creates the identity's mailbox, `released` deletes everything held for it and closes its bindings.

use serde_json::{json, Value};

use crate::hub::MLS_RETENTION_S;

/// The service's view of the identities it serves: configured ones, and those enrolled within the operator's bound.
///
/// Spec: M§4.1. Configured identities are always served and never count against the bound. Any other identity enrols
/// with its first owner operation while fewer than `serve_any` are enrolled; past the bound its owner operations are
/// refused `mailbox.not-served`. An enrolment ends by `mailbox-config` `release: true` (a configured identity is refused
/// `mailbox.not-enrolled`) or, when the operator chose idle expiry (a MAY), once no device of the identity has
/// completed a verified `hello` within `mls_retention_s` (M§4.4).
#[derive(Debug, Clone)]
pub struct Enrolment {
    now: i64,
    configured: Vec<String>,
    serve_any: usize,
    expire_idle: bool,
    retention: i64,
    /// Enrolled identities in enrolment order, each with the time of its last verified `hello`.
    enrolled: Vec<(String, i64)>,
}

impl Enrolment {
    /// A machine from a vector `context`: `now`, `configured`, `serve_any` (default 0: enrolment closed),
    /// `expire_idle` (default false), `mls_retention_s` (default [`MLS_RETENTION_S`]).
    pub fn new(ctx: &Value) -> Enrolment {
        Enrolment {
            now: ctx["now"].as_i64().unwrap_or(0),
            configured: ctx["configured"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            serve_any: ctx["serve_any"].as_u64().unwrap_or(0) as usize,
            expire_idle: ctx["expire_idle"].as_bool().unwrap_or(false),
            retention: ctx["mls_retention_s"].as_i64().unwrap_or(MLS_RETENTION_S),
            enrolled: vec![],
        }
    }

    /// Whether `identity` is served now: configured or enrolled.
    pub fn serves(&self, identity: &str) -> bool {
        self.configured.iter().any(|c| c == identity) || self.enrolled.iter().any(|(e, _)| e == identity)
    }

    /// The enrolled identities, in enrolment order.
    pub fn enrolled(&self) -> Vec<String> {
        self.enrolled.iter().map(|(e, _)| e.clone()).collect()
    }

    /// An owner operation (`sync`, `key-packages`, `mailbox-config` without `release`) on a verified binding.
    ///
    /// Spec: M§4.1 — enrols within the bound, else `mailbox.not-served`.
    pub fn owner_op(&mut self, identity: &str, device: &str, id: &str) -> Vec<Value> {
        if self.serves(identity) {
            return vec![];
        }
        if self.enrolled.len() >= self.serve_any {
            return error(device, id, "mailbox.not-served");
        }
        // enrolment happens on a verified binding: it counts as a hello
        self.enrolled.push((identity.to_string(), self.now));
        vec![json!({"enrolled": {"identity": identity}})]
    }

    /// `mailbox-config` with `release: true`.
    ///
    /// Spec: M§4.1, M§5.7 — `accepted`, then `released`; a configured identity is refused `mailbox.not-enrolled`, and
    /// one not served `mailbox.not-served` (a release never enrols).
    pub fn release(&mut self, identity: &str, device: &str, id: &str) -> Vec<Value> {
        if self.configured.iter().any(|c| c == identity) {
            return error(device, id, "mailbox.not-enrolled");
        }
        let Some(i) = self.enrolled.iter().position(|(e, _)| e == identity) else {
            return error(device, id, "mailbox.not-served");
        };
        self.enrolled.remove(i);
        vec![
            json!({"accepted": {"to": device, "in_reply_to": id}}),
            json!({"released": {"identity": identity, "cause": "owner"}}),
        ]
    }

    /// The operator ends `identity`'s enrolment (`dsip-mailbox admin release`): its place is free at once. Whether it
    /// was enrolled; a configured identity is not, and ends by leaving the configuration.
    ///
    /// Impl (spec-gap 164): M§4.1 names two ends of an enrolment, the identity's release and idle expiry. An operator
    /// ending one is a third, with the same effect as a release: everything held for the identity is deleted and its
    /// bindings closed (the host acts on `true` as on `released`). Not a trace event; the vectors pin the two the spec
    /// names.
    pub fn end(&mut self, identity: &str) -> bool {
        let Some(i) = self.enrolled.iter().position(|(e, _)| e == identity) else { return false };
        self.enrolled.remove(i);
        true
    }

    /// Whether `identity` is one of the operator's configured identities.
    pub fn is_configured(&self, identity: &str) -> bool {
        self.configured.iter().any(|c| c == identity)
    }

    /// A verified `hello` of a device of `identity`.
    ///
    /// Spec: M§4.4 — the device is registered again for `mls_retention_s`. A binding alone enrols nothing (M§4.1).
    pub fn hello(&mut self, identity: &str) -> Vec<Value> {
        let now = self.now;
        if let Some((_, seen)) = self.enrolled.iter_mut().find(|(e, _)| e == identity) {
            *seen = now;
        }
        vec![]
    }

    /// Time passes; with idle expiry, enrolled identities without a registered device are released.
    ///
    /// Spec: M§4.1, M§4.4 — registered while the last `hello` is within `mls_retention_s`, so at exactly the bound the
    /// enrolment stays. Released in enrolment order.
    pub fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        if !self.expire_idle {
            return vec![];
        }
        let now = self.now;
        let retention = self.retention;
        let (idle, kept): (Vec<_>, Vec<_>) = self.enrolled.drain(..).partition(|(_, seen)| now - seen > retention);
        self.enrolled = kept;
        idle.into_iter().map(|(e, _)| json!({"released": {"identity": e, "cause": "idle"}})).collect()
    }

    /// The enrolled identities with the time of each one's last verified `hello`, in enrolment order: what a host
    /// saves to keep enrolments across a restart.
    pub fn entries(&self) -> &[(String, i64)] {
        &self.enrolled
    }

    /// Take back what [`Enrolment::entries`] gave, after a restart; the configuration stays the host's current one.
    pub fn restore_entries(&mut self, entries: Vec<(String, i64)>) {
        self.enrolled = entries;
    }

    /// The machine's clock, seconds.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Apply one trace event (`owner_op`, `release`, `hello`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|o| o.iter().next()) else { return vec![] };
        let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "owner_op" => self.owner_op(&s("identity"), &s("device"), &s("id")),
            "release" => self.release(&s("identity"), &s("device"), &s("id")),
            "hello" => self.hello(&s("identity")),
            "advance" => self.advance(e.as_i64().unwrap_or(0)),
            _ => vec![],
        }
    }

    /// `{enrolled, free}`: the enrolled identities in enrolment order, and the places left in the bound.
    pub fn snapshot(&self) -> Value {
        json!({"enrolled": self.enrolled(), "free": self.serve_any.saturating_sub(self.enrolled.len())})
    }
}

fn error(to: &str, id: &str, reason: &str) -> Vec<Value> {
    vec![json!({"error": {"to": to, "in_reply_to": id, "reason": reason}})]
}
