//! The device's and the subscriber's sides of the Presence Profile: a device's own record kept fresh at its authority
//! ([`Publisher`]), and several devices' records combined into one identity's presence ([`combine`], [`Watch`]).
//!
//! Spec: P§4 (the combining rule: valid records and the authority's assertion as candidates, ranked `dnd` > `busy` >
//! `available` > `away` > `offline`, ties broken deterministically: a record before the assertion, a registered state
//! before an unknown one, code-point order), P§5 (an unknown state ranks and shows as
//! `available`, its token kept).

use serde_json::{json, Value};

use dsip_core::registry::{effective_presence_state, PRESENCE_STATES};

/// The profile identifier a presence record names in `dsip.profiles`.
///
/// Spec: P§ (title), §11.2 (a receiver supporting none of the named profiles refuses the payload).
/// Impl (spec-gap 142): a record names `presence/0.1`, and implementations of P§ list it as supported.
pub const PROFILE: &str = "presence/0.1";

/// The identity's presence as P§4 combines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combined {
    /// The effective state: a `dsip-presence-state` registered value.
    pub state: String,
    /// The token that won, shown raw when unknown (P§5).
    pub token: String,
    /// `record`, `assertion` or `none`: where the winner came from. A client renders an assertion as the authority's
    /// claim (§9.3).
    pub source: &'static str,
}

/// P§4 rank of an effective state, highest first.
fn rank(state: &str) -> u8 {
    match state {
        "dnd" => 4,
        "busy" => 3,
        "available" => 2,
        "away" => 1,
        _ => 0,
    }
}

/// Combine the records a subscriber holds (each `{state, expires_at, device?}`) with the body's assertion at `now`.
///
/// Spec: P§4, P§5.
pub fn combine(records: &[Value], asserted: Option<&str>, now: i64) -> Combined {
    let mut candidates: Vec<(String, &'static str)> = records
        .iter()
        .filter(|r| r["expires_at"].as_i64().is_some_and(|e| e > now))
        .filter_map(|r| r["state"].as_str().map(|s| (s.to_string(), "record")))
        .collect();
    if asserted == Some("available") {
        candidates.push(("available".into(), "assertion"));
    }
    // highest rank, then a record before the assertion, a registered token before an unknown one, code-point order
    let best = candidates.into_iter().min_by(|(a, sa), (b, sb)| {
        let key = |t: &str, s: &str| {
            (std::cmp::Reverse(rank(effective_presence_state(t))), s != "record", !PRESENCE_STATES.contains(&t), t.to_string())
        };
        key(a, sa).cmp(&key(b, sb))
    });
    match best {
        None => Combined { state: "offline".into(), token: "offline".into(), source: "none" },
        Some((token, source)) => Combined { state: effective_presence_state(&token).into(), token, source },
    }
}

/// Run a `presence` vector (`input.check` `aggregate`).
///
/// Spec: P§4.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    match i["check"].as_str() {
        Some("aggregate") => {
            let records = i["records"].as_array().cloned().unwrap_or_default();
            let c = combine(&records, i["asserted"].as_str(), v["context"]["now"].as_i64().unwrap_or(0));
            json!({"state": c.state, "token": c.token, "source": c.source})
        }
        other => json!({"error": format!("unknown presence check {other:?}")}),
    }
}

/// A device's own presence record, kept fresh at its authority.
///
/// Clockless: the host calls [`Publisher::set`] when the user picks a state and [`Publisher::tick`] on its timer, signs
/// each payload returned with the record's lifetime as its validity (`expires_at − issued_at`), and sends it to the
/// authority. It reports an authority's `error` with [`Publisher::refused`].
///
/// Spec: P§3 (the record: `to` the authority, `subject` the identity, `device` the signer; `seq` per `(subject, device)`
/// must grow), P§8 (lifetime 60–3,600 s, at least 5 s between two accepted records; devices publish again before
/// expiry).
/// Impl: `seq` is the larger of the last one plus one and the current time, as for reachability hints, so it keeps
/// growing across restarts; the record is published again at ⅔ of its lifetime, as hints are re-signed (DHT Hints
/// Profile §2). Client behaviour only: the authority's checks are what the vectors pin.
#[derive(Debug, Clone)]
pub struct Publisher {
    identity: String,
    device: String,
    authority: String,
    lifetime: i64,
    state: Option<String>,
    seq: i64,
    last_sent: Option<i64>,
    due: Option<i64>,
}

impl Publisher {
    /// A publisher for `device`, acting for `identity`, whose records go to `authority` (its relay's DID) with
    /// `lifetime` seconds of validity, clamped to P§8's bounds.
    pub fn new(identity: &str, device: &str, authority: &str, lifetime: i64) -> Publisher {
        Publisher {
            identity: identity.into(),
            device: device.into(),
            authority: authority.into(),
            lifetime: lifetime.clamp(crate::authority::RECORD_MIN_LIFETIME_S, dsip_core::PRESENCE_MAX_VALIDITY_S),
            state: None,
            seq: 0,
            last_sent: None,
            due: None,
        }
    }

    /// The record lifetime the host signs with.
    pub fn lifetime(&self) -> i64 {
        self.lifetime
    }

    /// The state being published, if any.
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// A new authority (the device bound to another relay): the next record goes there at once.
    pub fn rebind(&mut self, authority: &str, now: i64) -> Option<Value> {
        self.authority = authority.into();
        self.last_sent = None;
        self.due = self.state.as_ref().map(|_| now);
        self.tick(now)
    }

    /// The user picked `state` (`None` stops publishing; the record then lapses at its `expires_at`). Returns the
    /// payload to sign now, or `None` when P§8's publish interval holds it back: [`Publisher::tick`] sends it then.
    pub fn set(&mut self, state: Option<&str>, now: i64) -> Option<Value> {
        self.state = state.map(String::from);
        self.due = self.state.as_ref().map(|_| now);
        self.tick(now)
    }

    /// The payload to sign at `now`, if one is due.
    pub fn tick(&mut self, now: i64) -> Option<Value> {
        let state = self.state.clone()?;
        let mut due = self.due?;
        if let Some(last) = self.last_sent {
            // P§8: at least the publish interval between two records of this device
            due = due.max(last + crate::authority::PUBLISH_INTERVAL_S);
        }
        if now < due {
            self.due = Some(due);
            return None;
        }
        self.seq = (self.seq + 1).max(now);
        self.last_sent = Some(now);
        self.due = Some(now + self.lifetime * 2 / 3);
        Some(json!({
            "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [PROFILE], "extensions": [], "critical": []},
            "type": "presence", "to": self.authority, "subject": self.identity, "device": self.device,
            "state": state, "seq": self.seq,
        }))
    }

    /// When [`Publisher::tick`] next has something to send.
    pub fn next_deadline(&self) -> Option<i64> {
        self.state.as_ref()?;
        let due = self.due?;
        Some(self.last_sent.map_or(due, |l| due.max(l + crate::authority::PUBLISH_INTERVAL_S)))
    }

    /// The authority refused the last record with `reason` (P§9). `policy.rate-limited` is tried again after its
    /// `retry_after`; `presence.stale` again at once with a larger `seq`; anything else is not sent again until the
    /// user picks a state (P§9: the device publishes a corrected record).
    pub fn refused(&mut self, reason: &str, retry_after: Option<i64>, now: i64) {
        match reason {
            "policy.rate-limited" => self.due = Some(now + retry_after.unwrap_or(crate::authority::PUBLISH_INTERVAL_S)),
            "presence.stale" => {
                self.seq += 1;
                self.last_sent = None;
                self.due = Some(now);
            }
            _ => self.due = None,
        }
    }
}

/// What a subscriber holds of one identity's presence, from its authority's `notify` bodies.
///
/// Spec: §9.3 (notifies apply in `seq` order; `terminated` ends the subscription), P§3 (the body: the assertion and
/// each held record as the signed envelope, which the subscriber verifies itself), P§4 (records combined by the
/// subscriber), §9.3 (an assertion is rendered as the authority's claim).
#[derive(Debug, Clone, Default)]
pub struct Watch {
    target: String,
    seq: Option<i64>,
    asserted: Option<String>,
    records: Vec<Value>,
    terminated: bool,
}

impl Watch {
    /// A watch on `target`'s presence.
    pub fn new(target: &str) -> Watch {
        Watch { target: target.into(), ..Default::default() }
    }

    /// The identity watched.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether the subscription has ended.
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    /// Apply a verified `notify` payload. Each carried record's signed `frame` goes through `verify`, which returns the
    /// record's verified payload and the identity its signer acts for (§7.4), or `None`. A record is kept only when it
    /// verifies, is a `presence` record, names this target as `subject`, is signed by the identity it names, and names
    /// its signer as `device` (P§3). Returns whether the notify was applied (a stale `seq` is ignored, §9.3).
    pub fn notify(&mut self, payload: &Value, mut verify: impl FnMut(&str) -> Option<(Value, String)>) -> bool {
        let seq = payload["seq"].as_i64();
        if let (Some(have), Some(got)) = (self.seq, seq) {
            if got <= have {
                return false;
            }
        }
        self.seq = seq.or(self.seq);
        if payload["state"] == "terminated" {
            self.terminated = true;
        }
        let body = &payload["body"];
        if body["event"] != "presence" {
            return true;
        }
        self.asserted = body["state"].as_str().map(String::from);
        self.records = body["records"]
            .as_array()
            .map(|rs| {
                rs.iter()
                    .filter_map(|r| r["frame"].as_str())
                    .filter_map(&mut verify)
                    .filter(|(p, identity)| {
                        p["type"] == "presence" && p["subject"] == self.target.as_str() && identity == &self.target && p["device"] == p["from"]
                    })
                    .map(|(p, _)| json!({"device": p["device"], "state": p["state"], "seq": p["seq"], "expires_at": p["expires_at"]}))
                    .collect()
            })
            .unwrap_or_default();
        true
    }

    /// The identity's presence at `now` (P§4).
    pub fn combined(&self, now: i64) -> Combined {
        combine(&self.records, self.asserted.as_deref(), now)
    }

    /// The verified records held, each `{device, state, seq, expires_at}`.
    pub fn records(&self) -> &[Value] {
        &self.records
    }
}
