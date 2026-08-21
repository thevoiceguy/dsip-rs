//! `dsip-wasm` — the same verifier and engine, compiled for the browser.
//!
//! Spec: none (infrastructure) — every normative behavior comes from
//! `dsip-core`, `dsip-schema`, `dsip-session`, and `dsip-endpoint`; this crate
//! only marshals JSON strings across the wasm-bindgen boundary. The browser
//! supplies the clock (`Date.now()/1000`), the WebSocket, WebRTC, and storage.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_endpoint::hello::{client_hello, verify_relay_hello};
use dsip_endpoint::verify::SeenIds;
use dsip_endpoint::{ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys};
use dsip_session::LocalEvent;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32], JsValue> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(JsValue::from_str("seed must be 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c).map_err(js)?, 16).map_err(js)?;
    }
    Ok(out)
}

fn js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn core_event_json(e: &CoreEvent) -> Value {
    match e {
        CoreEvent::Send { frame, msg_type, session, to } => json!({"send": {"frame": frame, "type": msg_type, "session": session, "to": to}}),
        CoreEvent::Emission(em) => json!({"emission": em.to_json()}),
        CoreEvent::Received { message, identity, display_name, payload } => {
            json!({"received": {"message": message, "identity": identity, "display_name": display_name, "payload": payload}})
        }
        CoreEvent::Rejected { code, detail } => json!({"rejected": {"code": code, "detail": detail}}),
    }
}

/// Install the panic hook (better errors in the browser console).
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Create an identity: `{"controller_seed_hex","device_seed_hex"}` are generated when absent.
/// Returns JSON with seeds (keep private), DIDs, kid, and the signed delegation frame (§7.4).
#[wasm_bindgen]
pub fn create_identity(controller_seed_hex: Option<String>, device_seed_hex: Option<String>, display_name: &str, now: f64) -> Result<String, JsValue> {
    let controller = match controller_seed_hex {
        Some(h) => KeyPair::from_seed(unhex(&h)?),
        None => KeyPair::generate(),
    };
    let device = match device_seed_hex {
        Some(h) => KeyPair::from_seed(unhex(&h)?),
        None => KeyPair::generate(),
    };
    let now = now as i64;
    let payload = dsip_core::delegation::delegation_payload(
        &controller.did(),
        &device.did(),
        now - 60,
        now + 365 * 86_400,
        &["dsip.signaling", "dsip.media.interactive"],
    );
    let delegation = sign(&payload, &controller, &controller.kid());
    Ok(json!({
        "controller_seed_hex": hex(&controller.seed()), "device_seed_hex": hex(&device.seed()),
        "identity": controller.did(), "device": device.did(), "kid": device.kid(),
        "display_name": display_name, "delegation": delegation.frame(),
    })
    .to_string())
}

/// Verify a frame standalone (stages 1–14) with a vector-style context JSON. Returns the `expect` projection.
#[wasm_bindgen]
pub fn verify_frame(frame: &str, context_json: &str) -> String {
    let ctx: Value = serde_json::from_str(context_json).unwrap_or(json!({}));
    let resolver = Context::resolver_from_vector(&ctx);
    let c = Context::from_vector(&ctx, &resolver);
    let env = match Envelope::from_frame(frame) {
        Ok(e) => e,
        Err(v) => return v.to_expect().to_string(),
    };
    match dsip_core::envelope::verify(&env, &c, Some(frame)) {
        Ok(ver) => {
            let sem = dsip_schema::check_payload(&ver.payload, &dsip_schema::SemanticContext::from_vector(&ctx));
            if !sem.ok() {
                return sem.to_expect().to_string();
            }
            let mut out = dsip_core::envelope::accept_verdict(&ver).to_expect();
            for (k, v) in sem.extra {
                out[k] = v;
            }
            out["payload"] = ver.payload;
            out.to_string()
        }
        Err(v) => v.to_expect().to_string(),
    }
}

/// A browser endpoint: the engine + verifier + builder behind a JSON API.
#[wasm_bindgen]
pub struct Endpoint {
    core: Core,
    supported: dsip_core::version::Supported,
    resolver: StaticResolver,
    seen: SeenIds,
    hello_id: Option<String>,
}

#[wasm_bindgen]
impl Endpoint {
    /// `identity_json` as returned by [`create_identity`]; `config_json` = `{"video":bool,"first_contact_required":bool,"t_establish":…}`.
    #[wasm_bindgen(constructor)]
    pub fn new(identity_json: &str, config_json: &str, now: f64) -> Result<Endpoint, JsValue> {
        let id: Value = serde_json::from_str(identity_json).map_err(js)?;
        let cfgv: Value = serde_json::from_str(config_json).unwrap_or(json!({}));
        let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
        let delegation = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
        let keys = IdentityKeys {
            identity: id["identity"].as_str().unwrap_or("").to_string(),
            device,
            delegation,
            display_name: id["display_name"].as_str().unwrap_or("").to_string(),
        };
        let cfg = CoreConfig {
            video: cfgv["video"].as_bool().unwrap_or(false),
            t_establish: cfgv["t_establish"].as_i64(),
            t_ring: cfgv["t_ring"].as_i64(),
            t_ring_local: cfgv["t_ring_local"].as_i64(),
            first_contact_required: cfgv["first_contact_required"].as_bool().unwrap_or(false),
        };
        let resolver = StaticResolver::default();
        Ok(Endpoint {
            core: Core::new(keys, cfg, resolver.clone(), now as i64),
            supported: dsip_core::version::Supported::default(),
            resolver,
            seen: SeenIds::default(),
            hello_id: None,
        })
    }

    /// The client `hello` frame to send first on a connection (§13.2).
    pub fn hello_frame(&mut self, now: f64) -> String {
        let id = self.core.new_id(now as i64);
        self.hello_id = Some(id.clone());
        client_hello(self.core.keys(), &self.supported, &id, now as i64).frame()
    }

    /// Verify the relay's `hello` (must echo our id, §20.5). Returns `{"ok":true,"did":…,"capabilities":…}` or `{"ok":false,"code":…}`.
    pub fn relay_hello(&mut self, frame: &str, now: f64) -> String {
        let sent = self.hello_id.clone().unwrap_or_default();
        match verify_relay_hello(frame, &sent, now as i64, &self.resolver, &mut self.seen, &self.supported) {
            Ok(r) => json!({"ok": true, "did": r.did, "capabilities": r.capabilities}).to_string(),
            Err(v) => json!({"ok": false, "code": v.to_expect()["code"], "detail": v.detail}).to_string(),
        }
    }

    /// Our DIDs and display name.
    pub fn whoami(&self) -> String {
        let k = self.core.keys();
        json!({"identity": k.identity, "device": k.device.did(), "display_name": k.display_name}).to_string()
    }

    /// A fresh ULID.
    pub fn new_id(&mut self, now: f64) -> String {
        self.core.new_id(now as i64)
    }

    /// SDP for the next invite/answer/update transport descriptor.
    pub fn set_sdp(&mut self, sdp: Option<String>) {
        self.core.set_sdp(sdp);
    }

    /// `data` for the next `info` (ICE candidates).
    pub fn set_info_data(&mut self, data_json: &str) {
        if let Ok(v) = serde_json::from_str(data_json) {
            self.core.set_info_data(v);
        }
    }

    /// A local event (README vocabulary JSON). Returns a JSON array of events.
    pub fn local(&mut self, event_json: &str, now: f64) -> Result<String, JsValue> {
        let ev: LocalEvent = serde_json::from_str(event_json).map_err(js)?;
        let out = self.core.local(ev, now as i64).map_err(js)?;
        Ok(Value::Array(out.iter().map(core_event_json).collect()).to_string())
    }

    /// An inbound frame. Returns a JSON array of events.
    pub fn inbound(&mut self, frame: &str, now: f64) -> Result<String, JsValue> {
        let out = self.core.inbound(frame, now as i64).map_err(js)?;
        Ok(Value::Array(out.iter().map(core_event_json).collect()).to_string())
    }

    /// Advance the clock; due timers fire. Returns a JSON array of events.
    pub fn tick(&mut self, now: f64) -> Result<String, JsValue> {
        let out = self.core.tick(now as i64).map_err(js)?;
        Ok(Value::Array(out.iter().map(core_event_json).collect()).to_string())
    }

    /// Seconds until the next timer, or -1.
    pub fn next_deadline(&self) -> f64 {
        self.core.endpoint().next_deadline().map(|d| d as f64).unwrap_or(-1.0)
    }

    /// Session snapshot (README shape) for one session id.
    pub fn session(&self, id: &str) -> String {
        self.core.endpoint().snapshot([id.to_string()]).to_string()
    }

    /// Contacts snapshot (README shape).
    pub fn contacts_snapshot(&self) -> String {
        self.core.endpoint().contacts.snapshot().to_string()
    }

    /// Pending introductions `[[id, identity], …]`.
    pub fn requests(&self) -> String {
        json!(self.core.requests()).to_string()
    }

    /// Export persisted first-contact state (store it; reload with [`Endpoint::load_contacts`]).
    pub fn contacts_json(&self) -> String {
        serde_json::to_string(&self.core.contacts()).unwrap_or_else(|_| "{}".into())
    }

    /// Import persisted first-contact state.
    pub fn load_contacts(&mut self, json_text: &str) {
        if let Ok(f) = serde_json::from_str::<ContactFile>(json_text) {
            self.core.load_contacts(&f);
        }
    }
}
