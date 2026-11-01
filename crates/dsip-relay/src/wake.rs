//! The relay as a waker (Wake Profile, draft `wake/0.1`): it keeps the registrations its devices send in
//! `wake-register`, and when it holds an invite for a registered device that is not bound it asks the device's push
//! gateway to wake it, and to end the call on the screen when the invite stops being held before the device binds.
//!
//! Spec: W§4.2 (the checks on `wake-register`, one registration per device), W§4.3 (when a registration ends), W§4.4
//! (the `wake` capability in the relay's `hello`), W§5.1 (`call`, `call-ended`), W§5.2 (the `wake`, one retry for a
//! transport failure, never for an answered one), W§6 (the caller sealed to the device's `seal_key`).
//! Impl: registrations are kept in a JSON file beside the queue store, so a restarted relay still wakes devices that
//! are asleep (they register again only when they next bind).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_transport::wake::{Answer, WakeClient};
use dsip_wake::{Emit, Waker};

/// The kinds a relay sends. Spec: W§4.4, W§5.1
pub const KINDS: [&str; 2] = ["call", "call-ended"];

/// How a relay wakes devices.
#[derive(Clone)]
pub struct WakeConfig {
    /// Sends wakes to gateways (W§2.1).
    pub client: WakeClient,
    /// The gateways this relay will use; `None` admits any (W§4.2 step 4).
    pub gateways: Option<Vec<String>>,
    /// Where registrations are kept across a restart; `None`: in memory only.
    pub store: Option<PathBuf>,
}

impl std::fmt::Debug for WakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeConfig").field("gateways", &self.gateways).field("store", &self.store).finish_non_exhaustive()
    }
}

/// A device's registration as kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    identity: String,
    gateway: String,
    registration: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_key: Option<String>,
    expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kinds: Option<Vec<String>>,
}

/// A wake to send: the device it is for (to act on the answer), the gateway, the signed `wake`, its `deliver_by`.
pub(crate) struct Outgoing {
    pub device: String,
    pub gateway: String,
    pub wake: Envelope,
    pub deliver_by: i64,
}

/// The relay's wake state.
pub(crate) struct Wakes {
    waker: Waker,
    records: HashMap<String, Record>,
    /// Per held invite: its caller's device and identity, for the sealed hint (W§6), and when it can be forgotten.
    callers: HashMap<String, (String, Option<String>, i64)>,
    gateways: Option<Vec<String>>,
    store: Option<PathBuf>,
    pub(crate) client: WakeClient,
    tx: mpsc::UnboundedSender<Outgoing>,
}

impl Wakes {
    /// The wake state, with what `cfg.store` holds; wakes go out on the returned channel.
    pub(crate) fn new(cfg: WakeConfig, now: i64) -> (Wakes, mpsc::UnboundedReceiver<Outgoing>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut w = Wakes { waker: Waker::new(), records: HashMap::new(), callers: HashMap::new(), gateways: cfg.gateways, store: cfg.store, client: cfg.client, tx };
        if let Some(path) = &w.store {
            match std::fs::read(path).map(|b| serde_json::from_slice::<HashMap<String, Record>>(&b)) {
                Ok(Ok(held)) => {
                    for (device, r) in held.into_iter().filter(|(_, r)| r.expires_at > now) {
                        w.waker.register(&device, &r.identity, r.expires_at, r.kinds.clone());
                        w.records.insert(device, r);
                    }
                    tracing::info!("wake: {} registrations restored", w.records.len());
                }
                Ok(Err(e)) => tracing::warn!("wake: {}: {e}; starting with no registrations", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("wake: {}: {e}; starting with no registrations", path.display()),
            }
        }
        (w, rx)
    }

    fn persist(&self) {
        let Some(path) = &self.store else { return };
        let tmp = path.with_extension("tmp");
        let write = serde_json::to_vec(&self.records).map_err(std::io::Error::other).and_then(|b| std::fs::write(&tmp, b)).and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = write {
            tracing::warn!("wake: writing {}: {e}", path.display());
        }
    }

    /// A verified `wake-register` from bound `device` of `identity`: the W§4.2 checks, then the registration is kept
    /// or ended. `Err` is the refusal's reason token (`transport.routing-refused` for a schema failure, which has none).
    pub(crate) fn register(&mut self, payload: &Value, device: &str, identity: &str, relay: &str, now: i64) -> Result<(), &'static str> {
        match dsip_wake::check_register(payload, device, relay, now, self.gateways.as_deref()) {
            Ok(dsip_wake::Registered::Removed) => {
                self.waker.end_registration(device, "removed");
                if self.records.remove(device).is_some() {
                    tracing::info!("wake: {device} removed its registration");
                    self.persist();
                }
                Ok(())
            }
            Ok(dsip_wake::Registered::Registration(r)) => {
                let kinds: Option<Vec<String>> = r["kinds"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect());
                let expires_at = r["expires_at"].as_i64().unwrap_or(now);
                self.waker.register(device, identity, expires_at, kinds.clone());
                let record = Record {
                    identity: identity.to_string(),
                    gateway: r["gateway"].as_str().unwrap_or("").to_string(),
                    registration: payload["registration"].clone(),
                    seal_key: r["seal_key"].as_str().map(String::from),
                    expires_at,
                    kinds,
                };
                tracing::info!("wake: {device} registered through {} until {expires_at}", record.gateway);
                self.records.insert(device.to_string(), record);
                self.persist();
                Ok(())
            }
            Err(refusal) => Err(refusal.reason.unwrap_or("transport.routing-refused")),
        }
    }

    /// The devices an invite to `to` is held for, when they are registered: `to` itself, or every registered device of
    /// the identity `to` (§12.7: a device of it that binds while the attempt is live becomes a leg).
    pub(crate) fn devices_for(&self, to: &str) -> Vec<String> {
        if self.records.contains_key(to) {
            return vec![to.to_string()];
        }
        let mut d: Vec<String> = self.records.iter().filter(|(_, r)| r.identity == to).map(|(d, _)| d.clone()).collect();
        d.sort();
        d
    }

    /// An invite `session` from `caller`, `(device, the identity it acts for)`, held until `expires_at` for
    /// `devices`. Spec: W§5.1
    pub(crate) fn hold(&mut self, now: i64, session: &str, devices: &[String], expires_at: i64, caller: (&str, &str), key: &KeyPair) {
        let (caller, identity) = caller;
        if devices.is_empty() {
            return;
        }
        let obo = (identity != caller).then(|| identity.to_string());
        self.callers.insert(session.to_string(), (caller.to_string(), obo, expires_at + dsip_wake::W_CALL_ENDED_S));
        let emits = self.waker.hold(now, session, devices, expires_at);
        self.act(emits, key, now);
    }

    /// The initiator's `cancel` for `session` reached the relay. Spec: W§5.1
    pub(crate) fn drop_invite(&mut self, now: i64, session: &str, key: &KeyPair) {
        let emits = self.waker.drop_invite(now, session);
        self.act(emits, key, now);
    }

    /// Settle expiries at `now`. Spec: W§4.3, W§5.1
    pub(crate) fn settle(&mut self, now: i64, key: &KeyPair) {
        let emits = self.waker.settle(now);
        self.callers.retain(|_, (_, _, until)| *until > now);
        self.act(emits, key, now);
    }

    /// `device` bound or unbound (§13.3: a binding flushes what is held for it).
    pub(crate) fn bound(&mut self, device: &str, bound: bool) {
        if bound {
            self.waker.bind(device);
        } else {
            self.waker.unbind(device);
        }
    }

    /// `device`'s delegation was revoked (§7.4). Spec: W§4.3
    pub(crate) fn revoked(&mut self, device: &str, key: &KeyPair, now: i64) {
        let emits = self.waker.end_registration(device, "revoked");
        self.act(emits, key, now);
    }

    /// The gateway answered a wake for `device` with `reason`. Spec: W§4.3, W§8.1
    pub(crate) fn answered(&mut self, device: &str, reason: &str, key: &KeyPair, now: i64) {
        let emits = self.waker.answered(device, reason);
        self.act(emits, key, now);
    }

    fn act(&mut self, emits: Vec<Emit>, key: &KeyPair, now: i64) {
        let mut changed = false;
        for e in emits {
            match &e {
                Emit::Wake { device, kind, session, deliver_by } => {
                    let Some(r) = self.records.get(device) else { continue };
                    let sealed = match (*kind, session, &r.seal_key) {
                        ("call", Some(s), Some(k)) => self.seal(s, k),
                        _ => None,
                    };
                    let Some(p) = dsip_wake::wake_message(&key.did(), &r.gateway, &r.registration, &e, sealed, now) else { continue };
                    tracing::info!("wake: {kind} → {device} through {}", r.gateway);
                    let out = Outgoing { device: device.clone(), gateway: r.gateway.clone(), wake: sign(&p, key, &key.kid()), deliver_by: *deliver_by };
                    let _ = self.tx.send(out);
                }
                Emit::Ended { device, cause } => {
                    tracing::info!("wake: registration of {device} ended ({cause})");
                    changed |= self.records.remove(device).is_some();
                }
            }
        }
        if changed {
            self.persist();
        }
    }

    /// The caller of `session`, sealed to `seal_key` (W§6). `None` when the key does not decode or the hint is too long.
    fn seal(&self, session: &str, seal_key: &str) -> Option<Value> {
        let (from, obo, _) = self.callers.get(session)?;
        let pk: [u8; 32] = dsip_core::b64::decode(seal_key)?.try_into().ok()?;
        let ephemeral: [u8; 32] = rand::random();
        dsip_wake::seal_hint(&pk, session, from, obo.as_deref(), &ephemeral)
    }
}

/// Send `out` to its gateway, retrying once a transport failure while the wake is still useful (W§5.2), and give back
/// the reason of a refusal to act on.
pub(crate) async fn send(client: &WakeClient, out: &Outgoing) -> Option<String> {
    for attempt in 0..2 {
        match client.send(&out.gateway, &out.wake).await {
            Ok(Answer::Accepted { .. }) => return None,
            Ok(Answer::Refused { reason, .. }) => {
                tracing::info!("wake: {} refused for {}: {reason}", out.gateway, out.device);
                return Some(reason);
            }
            Err(e) => {
                tracing::warn!("wake: {e}");
                if attempt == 0 && dsip_transport::now_s() < out.deliver_by {
                    continue;
                }
                return None;
            }
        }
    }
    None
}
