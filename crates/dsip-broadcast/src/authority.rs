//! The target authority: publication registry, subscriptions, notifies, provenance attachment.
//!
//! Spec: §9.3 (authorization is the authority's policy; anti-enumeration:
//! identical `reject policy.blocked` for unauthorized and nonexistent targets;
//! per-event caps; renewal replaces; `expires_in: 0` terminates; the first
//! notify carries current state; terminal notifies carry a reason), §22.1
//! (the publisher's record, keyed by stream), §22.3 (statements attached, never
//! overwriting), §8.3 (newer replaces older; expired records are invalid).
//!
//! Impl (spec-gap 18): `publisher` MUST equal the verified identity; `stream_id`
//! is namespaced under it. Impl (spec-gap 19): presence derives from device
//! bindings at this authority. Impl (spec-gap 21): provenance rides to
//! subscribers in `notify.body`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dsip_core::registry::SUBSCRIPTION_EVENTS;
use dsip_session::event::{Emission, SendMsg};
use dsip_session::Message;

/// A held publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publication {
    /// Record id (ULID; newer replaces older).
    pub publication: String,
    /// Publisher DID.
    pub publisher: String,
    /// `live` | `scheduled` | `ended` | `withdrawn` | `expired`.
    pub state: String,
    /// Record expiry.
    pub expires_at: i64,
    /// Variants as advertised.
    pub variants: Vec<Value>,
    /// Policy block.
    pub policy: Value,
    /// Processors that attached statements, in order.
    pub provenance: Vec<String>,
    /// The original frame (for third-party-verifiable notify bodies).
    pub frame: Option<String>,
}

/// A live subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Subscriber identity.
    pub subscriber: String,
    /// Subscriber device (where notifies go).
    pub device: String,
    /// Target (stream id or subject DID).
    pub target: String,
    /// Event classes.
    pub events: Vec<String>,
    /// Soft-state expiry.
    pub expires_at: i64,
    /// Last seq sent.
    pub seq: u64,
}

/// Authorization policy for one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// `public` | `allow`.
    pub mode: String,
    /// Allowed subscriber identities (mode `allow`).
    pub allow: Vec<String>,
}

/// Events into the authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorityEvent {
    /// Clock.
    Advance {
        /// Seconds.
        advance: i64,
    },
    /// A verified message (publish / unpublish / subscribe / provenance).
    Recv {
        /// The message.
        recv: Value,
    },
    /// Local policy.
    Local(LocalPolicy),
    /// Device binding (presence).
    Relay(Binding),
}

/// Local policy actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "local", rename_all = "snake_case")]
pub enum LocalPolicy {
    /// Set a target's policy.
    Policy {
        /// Target.
        target: String,
        /// `public` | `allow`.
        mode: String,
        /// Allowlist.
        #[serde(default)]
        allow: Vec<String>,
    },
    /// Issue a capability token for a target (e.g. a follow token).
    IssueCapability {
        /// Token.
        token: String,
        /// Target.
        target: String,
    },
}

/// Device bindings seen by the authority (presence source).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "relay", rename_all = "snake_case")]
pub enum Binding {
    /// Bound.
    Bind {
        /// Device.
        device: String,
        /// Identity.
        identity: String,
    },
    /// Unbound.
    Unbind {
        /// Device.
        device: String,
        /// Identity.
        identity: String,
    },
}

/// The authority.
pub struct Authority {
    /// Clock.
    pub now: i64,
    identities: HashMap<String, String>,
    /// stream → record.
    pub publications: BTreeMap<String, Publication>,
    /// subscription id → subscription.
    pub subscriptions: BTreeMap<String, Subscription>,
    policy: HashMap<String, Policy>,
    capabilities: HashMap<String, String>,
    bound: BTreeSet<String>,
    out: Vec<Emission>,
    /// Extra (non-Send) emissions in README shape, interleaved in order with sends via [`Authority::step`].
    events: Vec<Value>,
}

impl Authority {
    /// Create an authority at clock `start` with a device→identity map.
    pub fn new(start: i64, identities: HashMap<String, String>) -> Authority {
        Authority {
            now: start,
            identities,
            publications: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            policy: HashMap::new(),
            capabilities: HashMap::new(),
            bound: BTreeSet::new(),
            out: vec![],
            events: vec![],
        }
    }

    /// From a state vector's context.
    pub fn from_vector(ctx: &Value) -> Authority {
        let ids = ctx
            .get("identities")
            .and_then(Value::as_object)
            .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
            .unwrap_or_default();
        Authority::new(ctx["start"].as_i64().unwrap_or(0), ids)
    }

    /// Record that `device` acts for `identity`.
    pub fn learn_identity(&mut self, device: &str, identity: &str) {
        self.identities.insert(device.into(), identity.into());
    }

    /// Set a target's policy.
    pub fn set_policy(&mut self, target: &str, mode: &str, allow: Vec<String>) {
        self.policy.insert(target.into(), Policy { mode: mode.into(), allow });
    }

    /// Issue a capability token.
    pub fn issue_capability(&mut self, token: &str, target: &str) {
        self.capabilities.insert(token.into(), target.into());
    }

    fn identity_of(&self, did: &str) -> String {
        self.identities.get(did).cloned().unwrap_or_else(|| did.to_string())
    }

    fn event(&mut self, v: Value) {
        self.events.push(v);
    }

    /// Drive one event. Returns README-shaped emissions in order (sends as `{"send": …}`).
    pub fn step(&mut self, ev: &AuthorityEvent) -> Vec<Value> {
        self.out.clear();
        self.events.clear();
        match ev {
            AuthorityEvent::Advance { advance } => {
                self.now += advance;
                self.expire();
            }
            AuthorityEvent::Recv { recv } => self.recv(recv),
            AuthorityEvent::Local(LocalPolicy::Policy { target, mode, allow }) => self.set_policy(target, mode, allow.clone()),
            AuthorityEvent::Local(LocalPolicy::IssueCapability { token, target }) => self.issue_capability(token, target),
            AuthorityEvent::Relay(Binding::Bind { device, identity }) => {
                self.learn_identity(device, identity);
                self.bound.insert(identity.clone());
                self.notify_all("presence", identity);
            }
            AuthorityEvent::Relay(Binding::Unbind { identity, .. }) => {
                self.bound.remove(identity);
                self.notify_all("presence", identity);
            }
        }
        std::mem::take(&mut self.events)
    }

    /// Drive a verified message directly (hosts); returns README-shaped emissions.
    pub fn recv_value(&mut self, m: &Value) -> Vec<Value> {
        self.step(&AuthorityEvent::Recv { recv: m.clone() })
    }

    /// Advance the clock (hosts).
    pub fn advance_to(&mut self, now: i64) -> Vec<Value> {
        let d = now - self.now;
        if d > 0 { self.step(&AuthorityEvent::Advance { advance: d }) } else { vec![] }
    }

    fn recv(&mut self, m: &Value) {
        let t = m["type"].as_str().unwrap_or("");
        let from = m["from"].as_str().unwrap_or("").to_string();
        let identity = self.identity_of(&from);
        match t {
            "publish" => {
                let publisher = m["publisher"].as_str().unwrap_or("").to_string();
                let stream = m["stream_id"].as_str().unwrap_or("").to_string();
                if publisher != identity {
                    return self.event(json!({"drop": "publisher-mismatch"}));
                }
                if !crate::receiver::stream_in_namespace(&stream, &publisher) {
                    return self.event(json!({"drop": "stream-id-namespace"}));
                }
                let id = m["id"].as_str().unwrap_or("").to_string();
                if let Some(cur) = self.publications.get(&stream) {
                    if id <= cur.publication {
                        return self.event(json!({"drop": "stale-publication"}));
                    }
                }
                let state = m["state"].as_str().unwrap_or("live").to_string();
                self.publications.insert(
                    stream.clone(),
                    Publication {
                        publication: id,
                        publisher,
                        state: state.clone(),
                        expires_at: m["expires_at"].as_i64().unwrap_or(0),
                        variants: m["variants"].as_array().cloned().unwrap_or_default(),
                        policy: m.get("policy").cloned().unwrap_or(json!({})),
                        provenance: vec![],
                        frame: m.get("_frame").and_then(Value::as_str).map(String::from),
                    },
                );
                self.event(json!({"publication": {"stream": stream, "state": state}}));
                self.notify_all("publication", &stream);
            }
            "unpublish" => {
                let stream = m["stream_id"].as_str().unwrap_or("").to_string();
                let pid = m["publication"].as_str().unwrap_or("");
                let Some(cur) = self.publications.get_mut(&stream).filter(|c| c.publication == pid) else {
                    return self.event(json!({"drop": "unknown-publication"}));
                };
                if cur.publisher != identity {
                    return self.event(json!({"drop": "publisher-mismatch"}));
                }
                cur.state = "withdrawn".into();
                self.event(json!({"publication": {"stream": stream, "state": "withdrawn"}}));
                self.notify_all("publication", &stream);
            }
            "provenance" | "broadcast.provenance" => {
                let stream = m["original_stream"].as_str().unwrap_or("").to_string();
                let pid = m["original_publication"].as_str().unwrap_or("");
                let processor = m["processor"].as_str().unwrap_or("").to_string();
                let Some(cur) = self.publications.get_mut(&stream).filter(|c| c.publication == pid) else {
                    return self.event(json!({"drop": "provenance-unknown-publication"}));
                };
                if processor != identity {
                    return self.event(json!({"drop": "provenance-processor-mismatch"}));
                }
                let inv = m["input_variant"].as_str().unwrap_or("");
                if !cur.variants.iter().any(|v| v["id"].as_str() == Some(inv)) {
                    return self.event(json!({"drop": "provenance-variant-unknown"}));
                }
                cur.provenance.push(processor.clone());
                self.event(json!({"provenance": {"stream": stream, "processor": processor}}));
                self.notify_all("publication", &stream);
            }
            "subscribe" => self.recv_subscribe(m, &identity),
            _ => self.event(json!({"drop": "not-broadcast"})),
        }
    }

    fn authorized(&self, target: &str, identity: &str, token: Option<&str>) -> bool {
        if token.is_some_and(|t| self.capabilities.get(t).map(String::as_str) == Some(target)) {
            return true;
        }
        match self.policy.get(target) {
            None => true,
            Some(p) => p.mode == "public" || p.allow.iter().any(|a| a == identity),
        }
    }

    fn target_exists(&self, target: &str, events: &[String]) -> bool {
        if events.iter().any(|e| e == "publication") {
            return self.publications.contains_key(target);
        }
        self.identities.values().any(|i| i == target) || self.bound.contains(target) || self.policy.contains_key(target)
    }

    fn recv_subscribe(&mut self, m: &Value, identity: &str) {
        let target = m["target"].as_str().unwrap_or("").to_string();
        let events: Vec<String> = m["events"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
        let expires_in = m["expires_in"].as_i64().unwrap_or(0);
        let id = m["id"].as_str().unwrap_or("").to_string();
        let from = m["from"].as_str().unwrap_or("").to_string();
        let existing = self
            .subscriptions
            .iter()
            .find(|(_, s)| s.subscriber == identity && s.target == target && s.events == events)
            .map(|(k, _)| k.clone());
        if expires_in == 0 {
            // §9.3: expires_in 0 terminates a matching subscription
            match existing {
                Some(sid) => {
                    self.subscriptions.remove(&sid);
                    self.event(json!({"subscription": {"id": sid, "state": "terminated"}}));
                }
                None => self.event(json!({"drop": "no-matching-subscription"})),
            }
            return;
        }
        // §9.3 anti-enumeration: unauthorized and nonexistent targets get the identical reject
        if !self.target_exists(&target, &events) || !self.authorized(&target, identity, m["capability"].as_str()) {
            self.send(SendMsg { msg_type: "reject".into(), to: from, session: Some(id), reason: Some("policy.blocked".into()), ..Default::default() });
            return;
        }
        let cap = events.iter().map(|e| SUBSCRIPTION_EVENTS.iter().find(|(n, _)| n == e).map(|(_, c)| *c).unwrap_or(86_400)).min().unwrap_or(86_400);
        let lifetime = expires_in.min(cap);
        if let Some(sid) = existing {
            self.subscriptions.remove(&sid);
            self.event(json!({"subscription": {"id": sid, "state": "replaced"}}));
        }
        self.subscriptions.insert(
            id.clone(),
            Subscription { subscriber: identity.into(), device: from, target, events, expires_at: self.now + lifetime, seq: 0 },
        );
        self.notify(&id, "active", None);
    }

    fn body_for(&self, sub: &Subscription) -> Value {
        if sub.events.iter().any(|e| e == "publication") {
            match self.publications.get(&sub.target) {
                Some(p) => {
                    let mut b = json!({"event": "publication", "state": p.state, "publication": p.publication});
                    if !p.provenance.is_empty() {
                        b["provenance"] = json!(p.provenance);
                    }
                    b
                }
                None => json!({"event": "publication", "state": "unknown"}),
            }
        } else {
            json!({"event": "presence", "state": if self.bound.contains(&sub.target) { "available" } else { "offline" }})
        }
    }

    fn send(&mut self, m: SendMsg) {
        self.events.push(Emission::Send(m).to_json());
    }

    fn notify(&mut self, sid: &str, state: &str, reason: Option<&str>) {
        let Some(sub) = self.subscriptions.get_mut(sid) else { return };
        sub.seq += 1;
        let (to, seq) = (sub.device.clone(), sub.seq);
        let body = self.body_for(self.subscriptions.get(sid).expect("exists"));
        let mut extra = vec![("subscription", json!(sid)), ("seq", json!(seq)), ("state", json!(state))];
        if let Some(r) = reason {
            extra.push(("reason", json!(r)));
        }
        extra.push(("body", body));
        self.send(SendMsg { msg_type: "notify".into(), to, extra, ..Default::default() });
        if state == "terminated" {
            self.subscriptions.remove(sid);
        }
    }

    fn notify_all(&mut self, event: &str, target: &str) {
        let ids: Vec<String> = self
            .subscriptions
            .iter()
            .filter(|(_, s)| s.target == target && s.events.iter().any(|e| e == event))
            .map(|(k, _)| k.clone())
            .collect();
        for sid in ids {
            self.notify(&sid, "active", None);
        }
    }

    fn expire(&mut self) {
        let lapsed: Vec<String> = self.subscriptions.iter().filter(|(_, s)| s.expires_at <= self.now).map(|(k, _)| k.clone()).collect();
        for sid in lapsed {
            // §9.3: soft state — lapsed subscriptions end with a terminal notify carrying session.expired
            self.notify(&sid, "terminated", Some("session.expired"));
        }
        let expired: Vec<String> = self
            .publications
            .iter()
            .filter(|(_, p)| (p.state == "live" || p.state == "scheduled") && p.expires_at <= self.now)
            .map(|(k, _)| k.clone())
            .collect();
        for stream in expired {
            self.publications.get_mut(&stream).expect("exists").state = "expired".into();
            self.event(json!({"publication": {"stream": stream, "state": "expired"}}));
            self.notify_all("publication", &stream);
        }
    }

    /// README `publications` snapshot.
    pub fn snapshot_publications(&self) -> Value {
        let m: serde_json::Map<String, Value> = self
            .publications
            .iter()
            .map(|(s, p)| (s.clone(), json!({"publication": p.publication, "publisher": p.publisher, "state": p.state})))
            .collect();
        Value::Object(m)
    }

    /// README `subscriptions` snapshot.
    pub fn snapshot_subscriptions(&self) -> Value {
        let m: serde_json::Map<String, Value> = self
            .subscriptions
            .iter()
            .map(|(k, s)| (k.clone(), json!({"subscriber": s.subscriber, "target": s.target, "events": s.events, "seq": s.seq, "expires_at": s.expires_at})))
            .collect();
        Value::Object(m)
    }
}

/// Abbreviate a verified full payload into the authority's message view (it reads the payload directly).
pub fn message_of(m: &Message) -> Value {
    serde_json::to_value(m).unwrap_or(Value::Null)
}
