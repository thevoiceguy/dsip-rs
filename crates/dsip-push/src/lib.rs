//! `dsip-push` — a push gateway (Wake Profile, draft `wake/0.1`): the service an app's publisher runs so that relays
//! and mailboxes run by anyone can wake that app's devices. It holds the APNs key and the FCM service account; a
//! device enrols its platform token here and gets an opaque handle; a waker's signed `wake` is checked and forwarded.
//!
//! Spec: sections owned by this crate — W§2.1 (one signed envelope per HTTPS `POST`, one signed envelope back), W§3
//! (enrolment: the handle), W§5.3 (the gateway's checks, the push it forwards, `wake.registration-ended` once the
//! provider reports the token unknown, rate limits answered `transport.rate-limited` with `retry_after`), W§9.
//! The rules themselves are `dsip-wake`'s ([`dsip_wake::check_enrol`], [`dsip_wake::check_wake`]); this crate is the
//! service around them: [`Gateway`] (the requests), [`providers`] (APNs, FCM, and a recording provider for tests),
//! [`server`] (HTTPS, and the gateway's own `did:web` document).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod providers;
pub mod server;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};

use dsip_core::did::{DidDocument, Service, StaticResolver};
use dsip_core::envelope::{self, sign, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_transport::resolver::{Over, WebDocuments};
use dsip_transport::verify::SeenIds;
use dsip_wake::Handle;

pub use providers::{Outcome, Provider};

/// The largest request a gateway reads: the `ws/1.0` envelope cap (§13.2). Spec: W§2.1
pub const MAX_REQUEST_BYTES: usize = dsip_core::WS_MAX_ENVELOPE_BYTES;
/// The longest handle. Spec: W§3
pub const MAX_HANDLE_CHARS: usize = 512;
const HANDLE_AAD: &[u8] = b"dsip-push handle v1";

/// Wakes per handle, and per waker, within [`Limits::window_s`].
///
/// Spec: W§5.3 ("it bounds wakes per handle and per waker"); the values are this gateway's own.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Wakes for one handle in a window.
    pub per_handle: usize,
    /// Wakes from one waker in a window.
    pub per_waker: usize,
    /// The window, seconds.
    pub window_s: i64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { per_handle: 30, per_waker: 3000, window_s: 60 }
    }
}

/// How a gateway is set up.
pub struct GatewayConfig {
    /// The gateway's signing key.
    pub key: KeyPair,
    /// The gateway's DID (a `did:web`, whose document names its `DSIPWake` endpoint).
    pub did: String,
    /// The key its handles are sealed under (AES-256-GCM).
    pub handle_key: [u8; 32],
    /// The `(provider, app)` pairs it pushes for (W§3).
    pub apps: Vec<(String, String)>,
    /// A provider per provider name (`apns`, `fcm`).
    pub providers: HashMap<String, Arc<dyn Provider>>,
    /// Documents of `did:web` wakers it holds; [`GatewayConfig::web`] fetches the others.
    pub resolver: StaticResolver,
    /// Fetches the `did:web` documents of wakers (§8.1); `None`: only `did:key` wakers and the held documents verify.
    pub web: Option<Arc<WebDocuments>>,
    /// Rate limits.
    pub limits: Limits,
}

struct State {
    seen: SeenIds,
    /// Handles whose platform token the provider reported unknown (W§5.3: every later wake is answered so).
    ended: HashSet<String>,
    per_handle: HashMap<String, VecDeque<i64>>,
    per_waker: HashMap<String, VecDeque<i64>>,
}

/// A push gateway: the requests of W§3 and W§5.3, answered with signed envelopes.
pub struct Gateway {
    cfg: GatewayConfig,
    state: Mutex<State>,
}

/// What the HTTP layer sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `200` with this signed envelope (W§2.1).
    Answer(String),
    /// A status with no envelope: a request that cannot be addressed (it does not verify), or a provider failure, which
    /// the waker treats as a transport failure and MAY retry once (W§2.1, W§5.2).
    Status(u16, &'static str),
}

impl Gateway {
    /// A gateway.
    pub fn new(cfg: GatewayConfig) -> Gateway {
        Gateway { cfg, state: Mutex::new(State { seen: SeenIds::default(), ended: HashSet::new(), per_handle: HashMap::new(), per_waker: HashMap::new() }) }
    }

    /// The gateway's DID.
    pub fn did(&self) -> &str {
        &self.cfg.did
    }

    /// The gateway's DID document: its key and its `DSIPWake` endpoint `endpoint` (W§2).
    pub fn document(&self, endpoint: &str) -> DidDocument {
        let mut doc = DidDocument::minimal_web(&self.cfg.did, &self.cfg.key.public(), None);
        doc.service.push(Service { id: format!("{}#dsip-wake", self.cfg.did), service_type: "DSIPWake".into(), service_endpoint: json!(endpoint) });
        doc
    }

    fn kid(&self) -> String {
        format!("{}#key-1", self.cfg.did)
    }

    fn signed(&self, p: &Value) -> Reply {
        Reply::Answer(sign(p, &self.cfg.key, &self.kid()).frame())
    }

    fn error(&self, to: &str, in_reply_to: &str, reason: &str, retry_after: Option<i64>, now: i64) -> Reply {
        let mut p = json!({"dsip": dsip_wake::version(), "type": "error", "id": dsip_core::ulid::Ulid::generate().as_str(),
                           "from": self.cfg.did, "to": to, "in_reply_to": in_reply_to, "reason": reason,
                           "issued_at": now, "expires_at": now + 30});
        if let Some(r) = retry_after {
            p["retry_after"] = json!(r);
        }
        self.signed(&p)
    }

    /// Seal `h` into a handle only this gateway can read. `None` when it would be longer than 512 characters.
    ///
    /// Spec: W§3. Impl: AES-256-GCM under the gateway's handle key with a random nonce, so the gateway keeps no table;
    /// a platform token too long for that is refused.
    pub fn seal_handle(&self, h: &Handle) -> Option<String> {
        let mut pt = json!({"p": h.provider, "a": h.app, "t": h.token, "k": h.key});
        if let Some(e) = &h.environment {
            pt["e"] = json!(e);
        }
        let nonce: [u8; 12] = rand::random();
        let cipher = Aes256Gcm::new_from_slice(&self.cfg.handle_key).ok()?;
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: pt.to_string().as_bytes(), aad: HANDLE_AAD }).ok()?;
        let handle = dsip_core::b64::encode(&[nonce.as_slice(), &ct].concat());
        (handle.len() <= MAX_HANDLE_CHARS).then_some(handle)
    }

    /// Read a handle this gateway sealed. Spec: W§3
    pub fn open_handle(&self, handle: &str) -> Option<Handle> {
        let raw = dsip_core::b64::decode(handle)?;
        if raw.len() < 12 + 16 {
            return None;
        }
        let cipher = Aes256Gcm::new_from_slice(&self.cfg.handle_key).ok()?;
        let pt = cipher.decrypt(Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: HANDLE_AAD }).ok()?;
        let v: Value = serde_json::from_slice(&pt).ok()?;
        Some(Handle {
            key: v["k"].as_str()?.to_string(),
            provider: v["p"].as_str()?.to_string(),
            app: v["a"].as_str()?.to_string(),
            token: v["t"].as_str()?.to_string(),
            environment: v["e"].as_str().map(String::from),
        })
    }

    /// Fetch the `did:web` documents the request names that the gateway does not hold (before verifying it).
    async fn fetch_documents(&self, body: &str) {
        let Some(web) = &self.cfg.web else { return };
        let mut dids = web.missing(body, &self.cfg.resolver);
        dids.truncate(WebDocuments::PER_FRAME);
        if !dids.is_empty() {
            web.fetch(&dids).await;
        }
    }

    /// Answer one request body.
    ///
    /// Spec: W§2.1, W§3, W§5.3.
    pub async fn handle(&self, body: &str, now: i64) -> Reply {
        if body.len() > MAX_REQUEST_BYTES {
            return Reply::Status(413, "request over the envelope cap");
        }
        self.fetch_documents(body).await;
        let verified = {
            let Ok(env) = Envelope::from_frame(body.trim()) else { return Reply::Status(400, "not an envelope") };
            let resolver = Over(&self.cfg.resolver, self.cfg.web.as_deref());
            let mut st = self.state.lock().expect("state");
            st.seen.sweep(now);
            let mut ctx = Context::new(now, &resolver);
            ctx.seen_ids = st.seen.set();
            match envelope::verify(&env, &ctx, None) {
                Ok(v) => {
                    st.seen.insert(v.payload["id"].as_str().unwrap_or(""), now, now);
                    v
                }
                Err(_) => return Reply::Status(400, "the request does not verify"),
            }
        };
        let p = &verified.payload;
        let from = verified.identity.clone();
        let id = p["id"].as_str().unwrap_or("").to_string();
        if p["to"] != self.cfg.did.as_str() {
            return self.error(&from, &id, "transport.routing-refused", None, now);
        }
        match verified.msg_type() {
            "wake-enrol" => self.enrol(p, &from, &id, now),
            "wake" => self.wake(p, &from, &id, now).await,
            _ => self.error(&from, &id, "transport.routing-refused", None, now),
        }
    }

    fn enrol(&self, p: &Value, from: &str, id: &str, now: i64) -> Reply {
        let e = match dsip_wake::check_enrol(p, &self.cfg.apps) {
            Ok(e) => e,
            Err(r) => return self.error(from, id, r.reason.unwrap_or("transport.routing-refused"), None, now),
        };
        let h = Handle {
            key: e["key"].as_str().unwrap_or("").to_string(),
            provider: e["provider"].as_str().unwrap_or("").to_string(),
            app: e["app"].as_str().unwrap_or("").to_string(),
            token: e["token"].as_str().unwrap_or("").to_string(),
            environment: e["environment"].as_str().map(String::from),
        };
        match self.seal_handle(&h) {
            Some(handle) => {
                tracing::info!("enrolled a {} token for {}", h.provider, h.app);
                self.signed(&dsip_wake::accepted_message(&self.cfg.did, from, id, Some(&handle), now))
            }
            None => self.error(from, id, "transport.routing-refused", None, now),
        }
    }

    /// Spec: W§5.3 — the checks, then the dead-token answer, then the rate limits, then the provider.
    async fn wake(&self, p: &Value, waker: &str, id: &str, now: i64) -> Reply {
        let fwd = match dsip_wake::check_wake(p, waker, &self.cfg.did, now, |h| self.open_handle(h)) {
            Ok(f) => f,
            Err(r) => return self.error(waker, id, r.reason.unwrap_or("transport.routing-refused"), None, now),
        };
        // check_wake opened the handle; read it again for the provider
        let handle = dsip_wake::verify_registration(&p["registration"], now).and_then(|r| r["handle"].as_str().map(String::from)).unwrap_or_default();
        let Some(h) = self.open_handle(&handle) else { return self.error(waker, id, "wake.not-authorized", None, now) };
        {
            let mut st = self.state.lock().expect("state");
            if st.ended.contains(&handle) {
                return self.error(waker, id, "wake.registration-ended", None, now);
            }
            let l = self.cfg.limits;
            let wait = window(&mut st.per_handle, &handle, now, l.per_handle, l.window_s).max(window(&mut st.per_waker, waker, now, l.per_waker, l.window_s));
            if wait > 0 {
                return self.error(waker, id, "transport.rate-limited", Some(wait), now);
            }
        }
        let Some(provider) = self.cfg.providers.get(&h.provider).cloned() else {
            return self.error(waker, id, "wake.unsupported-app", None, now);
        };
        match provider.push(&h, &fwd).await {
            Outcome::Sent => {
                tracing::info!("wake {} from {waker} handed to {}", fwd["data"]["dsip-wake"]["kind"], h.provider);
                self.signed(&dsip_wake::accepted_message(&self.cfg.did, waker, id, None, now))
            }
            Outcome::Unregistered => {
                tracing::info!("{} reports a token unknown: its handle is ended", h.provider);
                self.state.lock().expect("state").ended.insert(handle);
                self.error(waker, id, "wake.registration-ended", None, now)
            }
            Outcome::Failed(why) => {
                tracing::warn!("{}: {why}", h.provider);
                Reply::Status(503, "the push provider failed")
            }
        }
    }
}

/// A sliding-window limit: `0` and the time recorded when `key` is under `max` in the last `window_s`, else the
/// seconds until a slot frees.
fn window(log: &mut HashMap<String, VecDeque<i64>>, key: &str, now: i64, max: usize, window_s: i64) -> i64 {
    log.retain(|_, q| q.back().is_some_and(|t| *t + window_s > now));
    let q = log.entry(key.to_string()).or_default();
    while q.front().is_some_and(|t| *t + window_s <= now) {
        q.pop_front();
    }
    if q.len() >= max {
        return q.front().map_or(1, |t| (t + window_s - now).max(1));
    }
    q.push_back(now);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> Gateway {
        Gateway::new(GatewayConfig {
            key: KeyPair::from_seed([3; 32]),
            did: "did:web:push.test".into(),
            handle_key: [9; 32],
            apps: vec![("fcm".into(), "proj".into())],
            providers: HashMap::new(),
            resolver: StaticResolver::default(),
            web: None,
            limits: Limits::default(),
        })
    }

    #[test]
    fn a_handle_opens_and_a_tampered_one_does_not() {
        let g = gateway();
        let h = Handle { key: "did:key:z6Mk".into(), provider: "apns".into(), app: "a.voip".into(), token: "ab".repeat(32), environment: Some("sandbox".into()) };
        let s = g.seal_handle(&h).unwrap();
        assert_eq!(g.open_handle(&s), Some(h));
        let mut t = s.into_bytes();
        t[20] = if t[20] == b'A' { b'B' } else { b'A' };
        assert_eq!(g.open_handle(&String::from_utf8(t).unwrap()), None);
    }

    #[test]
    fn a_token_too_long_for_a_handle_is_refused() {
        let h = Handle { key: "did:key:z6Mk".into(), provider: "fcm".into(), app: "p".into(), token: "x".repeat(400), environment: None };
        assert!(gateway().seal_handle(&h).is_none());
    }

    #[test]
    fn the_window_counts_and_frees() {
        let mut log = HashMap::new();
        assert_eq!(window(&mut log, "h", 100, 2, 60), 0);
        assert_eq!(window(&mut log, "h", 110, 2, 60), 0);
        assert_eq!(window(&mut log, "h", 120, 2, 60), 40);
        assert_eq!(window(&mut log, "h", 160, 2, 60), 0);
    }
}
