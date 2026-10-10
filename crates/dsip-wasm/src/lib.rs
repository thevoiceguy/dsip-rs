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

/// Sign a `delegation-revocation` for `device` with the identity key in `identity_json` (§7.4, v0.8; spec-gap 57):
/// `id` a fresh ULID, `reason` a `dsip-revocation-reason` token. Returns the frame: hand it to the relay (which ends
/// the device's binding and refuses its next `hello`) and hold it ([`Endpoint::hold_revocation`]).
#[wasm_bindgen]
pub fn revocation_frame(identity_json: &str, id: &str, device: &str, reason: &str, now: f64) -> Result<String, JsValue> {
    let idj: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(idj["controller_seed_hex"].as_str().unwrap_or(""))?);
    let now = now as i64;
    let dsip = dsip_core::version::version_block(&dsip_core::version::Supported::all_known(), &[]);
    let p = dsip_core::delegation::revocation_payload(dsip, id, &controller.did(), device, now, reason, now);
    Ok(sign(&p, &controller, &controller.kid()).frame())
}

/// Rehome an identity to `did:web` (§7.2, §8.4): the same keys, the identity named by the DID, the device delegation
/// re-signed under `<did>#key-1`. Returns the identity JSON; [`did_document`] gives the document to host at the
/// DID's URL (`https://<host>/.well-known/did.json`, or `/<path>/did.json`).
#[wasm_bindgen]
pub fn rehome(identity_json: &str, did_web: &str, now: f64) -> Result<String, JsValue> {
    if !did_web.starts_with("did:web:") {
        return Err(JsValue::from_str("not a did:web DID"));
    }
    let mut id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().unwrap_or(""))?);
    let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
    let now = now as i64;
    let payload = dsip_core::delegation::delegation_payload(
        did_web,
        &device.did(),
        now - 60,
        now + 365 * 86_400,
        &["dsip.signaling", "dsip.media.interactive"],
    );
    id["identity"] = json!(did_web);
    id["delegation"] = json!(sign(&payload, &controller, &format!("{did_web}#key-1")).frame());
    Ok(id.to_string())
}

/// The DID document of a `did:web` identity (§7.2; the shape `dsip identity init --did-web` writes): one Multikey
/// verification method for the identity key, and `alsoKnownAs` (a JSON array of strings; `tel:+…` claims the
/// number of a binding, N§3.3).
#[wasm_bindgen]
pub fn did_document(identity_json: &str, also_known_as_json: &str) -> Result<String, JsValue> {
    let id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let did = id["identity"].as_str().unwrap_or("").to_string();
    if !did.starts_with("did:web:") {
        return Err(JsValue::from_str("not a did:web identity"));
    }
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().unwrap_or(""))?);
    let kid = format!("{did}#key-1");
    let multibase = controller.did().trim_start_matches("did:key:").to_string();
    let aka: Vec<String> = serde_json::from_str(also_known_as_json).unwrap_or_default();
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did,
        "verificationMethod": [{"id": kid, "type": "Multikey", "controller": did, "publicKeyMultibase": multibase}],
        "authentication": [kid],
        "assertionMethod": [kid],
    });
    if !aka.is_empty() {
        doc["alsoKnownAs"] = json!(aka);
    }
    serde_json::to_string_pretty(&doc).map_err(js)
}

fn policy_of(policy_json: &str) -> dsip_number::Policy {
    dsip_number::Policy::from_json(&serde_json::from_str(policy_json).unwrap_or(json!({})))
}

/// N§4: check a `tel` claim from an invite's `identity.claims` against the envelope's verified signing identity and
/// that identity's DID document (JSON, or `null` when none is held), under a `tn-binding` policy (the vectors'
/// context shape: `trust_anchors`, `certificates`, …; `{}` for none). Returns
/// `{"outcome": "ignored" | "attested" | "dropped", "line", "reason", "issued", "attested_by"}`: the lines the
/// `tn-binding/claim-*` vectors pin.
#[wasm_bindgen]
pub fn check_claim(claim_json: &str, identity: &str, did_document_json: &str, now: f64, policy_json: &str) -> String {
    let claim: Value = serde_json::from_str(claim_json).unwrap_or(Value::Null);
    let doc: Value = serde_json::from_str(did_document_json).unwrap_or(Value::Null);
    match dsip_number::check_claim(&claim, identity, &doc, now as i64, &policy_of(policy_json)) {
        dsip_number::ClaimOutcome::Ignored => json!({"outcome": "ignored"}),
        dsip_number::ClaimOutcome::Attested { line, issued, expires, attested_by } => {
            json!({"outcome": "attested", "line": line, "issued": issued, "expires": expires, "attested_by": attested_by})
        }
        dsip_number::ClaimOutcome::Dropped { reason, line } => json!({"outcome": "dropped", "reason": reason, "line": line}),
    }
    .to_string()
}

/// N§5: the warning when a verified number now belongs to another identity than a stored contact listing it;
/// `contacts_json` is `[{"name", "did", "numbers": ["+…"]}]`. Returns the warning, or `""` when none is due.
#[wasm_bindgen]
pub fn identity_change(contacts_json: &str, tn: &str, did: &str, attested_by: Option<String>, issued: f64) -> String {
    let v: Vec<Value> = serde_json::from_str(contacts_json).unwrap_or_default();
    let contacts: Vec<dsip_number::Contact> = v
        .iter()
        .map(|c| dsip_number::Contact {
            name: c["name"].as_str().unwrap_or_default().into(),
            did: c["did"].as_str().unwrap_or_default().into(),
            numbers: c["numbers"].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(String::from)).collect(),
        })
        .collect();
    dsip_number::identity_change(&contacts, tn, did, attested_by.as_deref(), issued as i64).unwrap_or_default()
}

/// N§6, N§7: the DID a number resolves to, from the bindings a lookup returned (a JSON array of compact JWS
/// strings), each verified in full against its own DID's document (`documents_json`: `{did: document}`), the newest
/// winning. Returns `{"did", "attested_by", "issued", "others"}`, or `null` when no binding verifies.
#[wasm_bindgen]
pub fn tn_select(tn: &str, bindings_json: &str, documents_json: &str, now: f64, policy_json: &str) -> String {
    let bindings: Vec<Value> = serde_json::from_str(bindings_json).unwrap_or_default();
    let docs: serde_json::Map<String, Value> = serde_json::from_str(documents_json).unwrap_or_default();
    match dsip_number::select(tn, &bindings, &docs, now as i64, &policy_of(policy_json)) {
        Some(s) => json!({"did": s.did, "attested_by": s.attested_by, "issued": s.issued, "others": s.others}).to_string(),
        None => "null".into(),
    }
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

/// §18.1 verification basis for an identity + its `identity.claims` (JSON array). The browser
/// renders exactly what the CLI does, through the one canonical `dsip_core::trust` function.
#[wasm_bindgen]
pub fn verification_basis(identity_did: &str, claims_json: &str) -> String {
    let claims: Vec<Value> = serde_json::from_str(claims_json).unwrap_or_default();
    dsip_core::trust::verification_basis(identity_did, &claims)
}

/// The `tel` caller headline for a call surface, or `""` if the claim is not a `tel` claim.
#[wasm_bindgen]
pub fn tel_caller_line(claim_json: &str) -> String {
    let claim: Value = serde_json::from_str(claim_json).unwrap_or(json!({}));
    dsip_core::trust::tel_caller_line(&claim).unwrap_or_default()
}

/// A human summary of a `gateway.downgraded` error's losses (JSON array of strings).
#[wasm_bindgen]
pub fn downgrade_summary(losses_json: &str) -> String {
    let losses: Vec<String> = serde_json::from_str(losses_json).unwrap_or_default();
    dsip_core::trust::downgrade_summary(&losses.iter().map(String::as_str).collect::<Vec<_>>())
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
            ..Default::default()
        };
        let resolver = StaticResolver::default();
        Ok(Endpoint {
            core: Core::new(keys, cfg, resolver.clone(), now as i64),
            supported: dsip_core::version::Supported::all_known(),
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

    /// Whether the next `invite`/`update` offers video (its descriptors must match the SDP set with `set_sdp`, B§2.1).
    pub fn set_video(&mut self, video: bool) {
        self.core.set_video(video);
    }

    /// Video codec registry ids (JSON array) the next offer lists; they must appear as `rtpmap`s in the SDP (B§3.4).
    pub fn set_video_codecs(&mut self, ids_json: &str) {
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(ids_json) {
            self.core.set_video_codecs(ids);
        }
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

    /// Hold a DID document (JSON) for resolution (§8.1: the document is the authority for its DID; the host obtained
    /// it, as the CLI's `--did-document`): `did:web` signers verify against it. Returns false for text that is not
    /// a document.
    pub fn add_document(&mut self, doc_json: &str) -> bool {
        match serde_json::from_str::<dsip_core::did::DidDocument>(doc_json) {
            Ok(d) => {
                self.resolver.insert(d.clone());
                self.core.add_document(d);
                true
            }
            Err(_) => false,
        }
    }

    /// `identity.claims` for the next invite (a JSON array): a `tel` claim with the caller's own `binding` (N§4).
    pub fn set_claims(&mut self, claims_json: &str) {
        self.core.set_claims(serde_json::from_str(claims_json).unwrap_or_default());
    }

    /// A patch for the next invite only (JSON object): `{"destination": "tel:+…"}` names the PSTN number a gateway
    /// should reach (N§4.1); `null` clears it.
    pub fn set_invite_patch(&mut self, patch_json: &str) {
        self.core.set_invite_patch(serde_json::from_str::<Value>(patch_json).ok().filter(Value::is_object));
    }

    /// Hold a `delegation-revocation` frame (one we signed, or one handed to us): every later verification applies
    /// it (§7.4, v0.8: "any store they hold"). Returns false for text that is not a frame.
    pub fn hold_revocation(&mut self, frame: &str) -> bool {
        match Envelope::from_frame(frame) {
            Ok(e) => {
                self.core.hold_revocation(e);
                true
            }
            Err(_) => false,
        }
    }
}
