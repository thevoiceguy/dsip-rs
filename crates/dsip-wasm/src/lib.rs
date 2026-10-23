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

pub mod messaging;

/// What this client's device delegation carries (§7.4): signaling and interactive media for calls, and
/// `dsip.messaging` for the mailbox (M§4.3).
const DEVICE_CAPABILITIES: &[&str] = &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"];

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_endpoint::hello::{client_hello, verify_relay_hello};
use dsip_endpoint::verify::SeenIds;
use dsip_endpoint::calls::AcceptPolicy;
use dsip_endpoint::{AnswerPolicy, CallCommand, CallEvent, CallOut, Calls, CallsConfig, Command, ContactFile, Core, CoreConfig, CoreEvent,
                    IdentityKeys, Invite, InvitePatch, MediaRequest, MediaResult};
use dsip_session::LocalEvent;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Result<[u8; 32], JsValue> {
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

pub(crate) fn js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// A `local` call's JSON as a [`Command`]: the engine event plus the host fields beside it.
fn command_from_json(v: &Value) -> Result<Command, serde_json::Error> {
    let ev: LocalEvent = serde_json::from_value(v.clone())?;
    let sdp = v.get("sdp").and_then(Value::as_str).map(String::from);
    Ok(match ev {
        LocalEvent::PlaceCall { session, to } => {
            let claims = v.get("claims").and_then(Value::as_array).cloned().unwrap_or_default();
            let patch = match v.get("patch") {
                Some(p) if p.is_object() => serde_json::from_value(p.clone())?,
                _ => InvitePatch::default(),
            };
            Command::PlaceCall { session, to, invite: Invite { sdp, claims, patch } }
        }
        LocalEvent::Accept { session, answered_by } => Command::Accept { session, answered_by, sdp },
        LocalEvent::Update { session, id, answered_by } => Command::Update { session, id, answered_by, sdp },
        LocalEvent::AnswerUpdate { session, in_reply_to, answered_by } => Command::AnswerUpdate { session, in_reply_to, answered_by, sdp },
        LocalEvent::Info { session } => match v.get("data") {
            Some(data) => Command::Info { session, data: data.clone() },
            None => Command::Engine(LocalEvent::Info { session }),
        },
        other => Command::Engine(other),
    })
}


fn core_event_json(e: &CoreEvent) -> Value {
    match e {
        CoreEvent::Send { frame, msg_type, session, to } => json!({"send": {"frame": frame, "type": msg_type, "session": session, "to": to}}),
        CoreEvent::Emission(em) => json!({"emission": em.to_json()}),
        CoreEvent::Received { message, identity, display_name, payload } => {
            json!({"received": {"message": message, "identity": identity, "display_name": display_name, "payload": payload}})
        }
        CoreEvent::Rejected { code, detail } => json!({"rejected": {"code": code, "detail": detail}}),
        CoreEvent::Resolve { did } => json!({"resolve": {"did": did}}),
    }
}

fn media_request_json(m: &MediaRequest) -> Value {
    match m {
        MediaRequest::Offer { session, add_source } => json!({"kind": "offer", "session": session, "add_source": add_source}),
        MediaRequest::Answer { session, offer, screening } => json!({"kind": "answer", "session": session, "offer": offer, "screening": screening}),
        MediaRequest::ApplyAnswer { session, sdp } => json!({"kind": "apply_answer", "session": session, "sdp": sdp}),
        MediaRequest::RemoteCandidates { session, candidates } => json!({"kind": "remote_candidates", "session": session, "candidates": candidates}),
        MediaRequest::StartSending { session } => json!({"kind": "start_sending", "session": session}),
        MediaRequest::HoldSending { session } => json!({"kind": "hold_sending", "session": session}),
        MediaRequest::Close { session } => json!({"kind": "close", "session": session}),
        other => json!({"kind": "unknown", "debug": format!("{other:?}")}),
    }
}

fn call_event_json(e: &CallEvent) -> Value {
    match e {
        CallEvent::Ringing { session } => json!({"event": "ringing", "session": session}),
        CallEvent::Silent { session } => json!({"event": "silent", "session": session}),
        CallEvent::NoOffer { session } => json!({"event": "no_offer", "session": session}),
        CallEvent::UpdateOffered { session, id } => json!({"event": "update_offered", "session": session, "id": id}),
        CallEvent::Recording { session, emission } => json!({"event": "recording", "session": session, "emission": emission}),
        CallEvent::RecordingHeld { session } => json!({"event": "recording_held", "session": session}),
        CallEvent::SendingResumed { session } => json!({"event": "sending_resumed", "session": session}),
        CallEvent::NothingToAccept { session } => json!({"event": "nothing_to_accept", "session": session}),
        CallEvent::ResentInClear { old, new, by } => json!({"event": "resent_in_clear", "old": old, "new": new, "by": by}),
        other => json!({"event": "unknown", "debug": format!("{other:?}")}),
    }
}

fn outs_json(out: &[CallOut]) -> String {
    Value::Array(
        out.iter()
            .map(|o| match o {
                CallOut::Core(e) => core_event_json(e),
                CallOut::Media(m) => json!({"media_request": media_request_json(m)}),
                CallOut::Call(e) => json!({"call": call_event_json(e)}),
            })
            .collect(),
    )
    .to_string()
}

/// A `call` command's JSON (`{"command": "accept"|"screen"|…, "session"}`) as a [`CallCommand`].
fn call_command(v: &Value) -> Result<CallCommand, JsValue> {
    let session = v["session"].as_str().ok_or_else(|| JsValue::from_str("no session"))?.to_string();
    Ok(match v["command"].as_str().unwrap_or("") {
        "accept" => CallCommand::Accept { session },
        "screen" => CallCommand::Screen { session },
        "decline" => CallCommand::Decline { session },
        "cancel" => CallCommand::Cancel { session },
        "hangup" => CallCommand::Hangup { session },
        "update" => CallCommand::Update { session },
        "escalate" => CallCommand::Escalate { session },
        "answer_update" => CallCommand::AnswerUpdate { session },
        "reject_update" => CallCommand::RejectUpdate { session },
        "info" => CallCommand::Info { session },
        "accept_recording" => CallCommand::AcceptRecording { session },
        "decline_recording" => CallCommand::DeclineRecording { session },
        other => return Err(JsValue::from_str(&format!("unknown call command {other:?}"))),
    })
}

/// A `media` result's JSON (`{"kind": "offer"|"answer", "session", "sdp"}` or `{"kind": "candidate", "session",
/// "candidate": {…}|null}`) as a [`MediaResult`].
fn media_result(v: &Value) -> Result<MediaResult, JsValue> {
    let session = v["session"].as_str().ok_or_else(|| JsValue::from_str("no session"))?.to_string();
    let sdp = || v["sdp"].as_str().map(String::from).ok_or_else(|| JsValue::from_str("no sdp"));
    Ok(match v["kind"].as_str().unwrap_or("") {
        "offer" => MediaResult::Offer { session, sdp: sdp()? },
        "answer" => MediaResult::Answer { session, sdp: sdp()? },
        "candidate" => MediaResult::Candidate { session, candidate: Some(v["candidate"].clone()).filter(|c| !c.is_null()) },
        other => return Err(JsValue::from_str(&format!("unknown media result {other:?}"))),
    })
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
        DEVICE_CAPABILITIES,
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
        DEVICE_CAPABILITIES,
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

/// The X25519 secrets sealed bodies addressed to this identity and this device open with (§10.4): the identity's
/// when its key is on this device, and the device's.
fn unseal_keys(id: &Value, keys: &IdentityKeys) -> Result<Vec<(String, [u8; 32])>, JsValue> {
    let mut out = vec![];
    if let Some(seed) = id["controller_seed_hex"].as_str().filter(|s| !s.is_empty()) {
        out.push((keys.identity.clone(), dsip_core::hpke::x25519_from_ed25519_seed(&unhex(seed)?)));
    }
    out.push((keys.device.did(), dsip_core::hpke::x25519_from_ed25519_seed(&keys.device.seed())));
    Ok(out)
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

/// A signed reachability hint for this identity (DHT Hints Profile §2; §8.3: `seq` is the publisher's, newer wins):
/// the frame to `POST /dsip/v1/hints` on a node (§10). `endpoints_json` is `[{uri, bindings?, service?, …}]`: the
/// signaling relay (`service` absent) and, with `"service": "DSIPMailbox"`, the mailbox entry a `did:key` identity
/// advertises this way (Messaging Profile M§4.2). Signed by the device under its delegation, as the CLI's
/// `--publish-hint` signs; `ttl_s` is clamped to the profile's maximum (§12.9, spec-gap 96).
#[wasm_bindgen]
pub fn hint_frame(identity_json: &str, id: &str, endpoints_json: &str, ttl_s: f64, seq: f64, now: f64) -> Result<String, JsValue> {
    let id_v: Value = serde_json::from_str(identity_json).map_err(js)?;
    let device = KeyPair::from_seed(unhex(id_v["device_seed_hex"].as_str().unwrap_or(""))?);
    let delegation = Envelope::from_frame(id_v["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
    let subject = id_v["identity"].as_str().unwrap_or("");
    let ttl = (ttl_s as i64).clamp(3, dsip_core::HINT_MAX_VALIDITY_S);
    let endpoints: Vec<dsip_dht::record::Endpoint> = serde_json::from_str::<Vec<Value>>(endpoints_json)
        .map_err(js)?
        .into_iter()
        .map(|mut e| {
            if e.get("bindings").is_none() {
                e["bindings"] = json!(["ws/1.0"]);
            }
            serde_json::from_value(e).map_err(js)
        })
        .collect::<Result<_, _>>()?;
    let payload = dsip_dht::record::hint_payload_with_id(subject, subject, &endpoints, seq as i64, now as i64, ttl, id);
    Ok(dsip_dht::record::sign_hint(&payload, &device, vec![delegation]).frame())
}

/// Fold the hint frames a node (or several) returned for `did` down to the winner (§8.3: verified against the
/// subject DID or its delegation, unexpired, highest `seq`), with every candidate's verdict. `documents_json` is
/// `{did: document}` for `did:web` subjects. Returns `{"hint": {uri, bindings, seq, issued_at, expires_at, signer} |
/// null, "report": [[verdict], …]}`. What it returns is a hint: never authority (§8.1 rule 6).
#[wasm_bindgen]
pub fn hint_select(did: &str, frames_json: &str, documents_json: &str, now: f64) -> String {
    let frames: Vec<String> = serde_json::from_str(frames_json).unwrap_or_default();
    let mut resolver = StaticResolver::default();
    if let Ok(docs) = serde_json::from_str::<Value>(documents_json) {
        for d in docs.as_object().map(|o| o.values().cloned().collect::<Vec<_>>()).unwrap_or_default() {
            if let Ok(doc) = serde_json::from_value::<dsip_core::did::DidDocument>(d) {
                resolver.insert(doc);
            }
        }
    }
    let ctx = Context::new(now as i64, &resolver);
    let (winner, report) = dsip_dht::record::select(&frames, &ctx);
    let hint = winner.filter(|h| h.subject == did).map(|h| {
        // `uri` is the signaling endpoint's (profile §2: `service` absent); every endpoint is in `endpoints`
        let signaling = h.endpoints.iter().find(|e| e.service() == "DSIPSignaling").or(h.endpoints.first());
        json!({"uri": signaling.map(|e| e.uri.clone()), "bindings": signaling.map(|e| e.bindings.clone()), "endpoints": h.endpoints,
               "seq": h.seq, "issued_at": h.issued_at, "expires_at": h.expires_at, "signer": h.signer})
    });
    json!({"hint": hint, "report": report.into_iter().map(|(_, v)| v).collect::<Vec<_>>()}).to_string()
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

/// A watched identity's presence, as the page shows it. Spec: P§4.
fn presence_json(w: &dsip_broadcast::presence::Watch, now: i64) -> String {
    let c = w.combined(now);
    json!({"target": w.target(), "state": c.state, "token": c.token, "source": c.source, "records": w.records().len(),
           "terminated": w.terminated()})
    .to_string()
}

/// A browser endpoint: the engine + verifier + builder behind a JSON API, with the call glue
/// ([`dsip_endpoint::calls`]): the page is the media host, doing the media work the glue asks for.
#[wasm_bindgen]
pub struct Endpoint {
    core: Core,
    calls: Calls,
    supported: dsip_core::version::Supported,
    resolver: StaticResolver,
    seen: SeenIds,
    hello_id: Option<String>,
    presence: Option<dsip_broadcast::presence::Publisher>,
    presence_state: Option<String>,
    watches: std::collections::BTreeMap<String, dsip_broadcast::presence::Watch>,
}

#[wasm_bindgen]
impl Endpoint {
    /// `identity_json` as returned by [`create_identity`]; `config_json` = `{"video":bool,"first_contact_required":bool,
    /// "t_establish":…, "seal":bool, "answer": "ring"|"accept"|"screen"|"decline"|"silent", "recording":
    /// "ask"|"always"|"never", "one_call":bool}`. Sealed bodies addressed to this identity or device open with their
    /// keys (§10.4); `did:web` signers whose documents are not held are asked for (`resolve` events, answered with
    /// [`Endpoint::resolved`]).
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
            seal: cfgv["seal"].as_bool().unwrap_or(false),
            resolve_on_demand: true,
            unseal_keys: unseal_keys(&id, &keys)?,
        };
        let calls = CallsConfig {
            media: true,
            answer: match cfgv["answer"].as_str().unwrap_or("ring") {
                "accept" => AnswerPolicy::Accept,
                "screen" => AnswerPolicy::Screen,
                "decline" => AnswerPolicy::Decline,
                "silent" => AnswerPolicy::Silent,
                _ => AnswerPolicy::Ring,
            },
            recording: match cfgv["recording"].as_str().unwrap_or("ask") {
                "always" => AcceptPolicy::Always,
                "never" => AcceptPolicy::Never,
                _ => AcceptPolicy::Ask,
            },
            one_call: cfgv["one_call"].as_bool().unwrap_or(false),
        };
        let resolver = StaticResolver::default();
        Ok(Endpoint {
            core: Core::new(keys, cfg, resolver.clone(), now as i64),
            calls: Calls::new(calls),
            supported: dsip_core::version::Supported::all_known(),
            resolver,
            seen: SeenIds::default(),
            hello_id: None,
            presence: None,
            presence_state: None,
            watches: Default::default(),
        })
    }

    /// Bound to the relay `authority` (its DID, from its `hello`): our presence record goes there. Returns the signed
    /// record to send now, or `null`. Spec: P§3.
    pub fn presence_bound(&mut self, authority: &str, now: f64) -> Result<Option<String>, JsValue> {
        let now = now as i64;
        let out = match self.presence.as_mut() {
            Some(p) => p.rebind(authority, now),
            None => {
                let k = self.core.keys();
                let mut p = dsip_broadcast::presence::Publisher::new(&k.identity, &k.device.did(), authority, 300);
                let out = p.set(self.presence_state.as_deref(), now);
                self.presence = Some(p);
                out
            }
        };
        self.sign_presence(out, now)
    }

    /// The user picked a presence state (`null` stops publishing). Returns the signed record to send now, or `null`
    /// (not bound yet, or P§8's publish interval holds it back: [`Endpoint::presence_tick`] returns it then).
    /// Spec: P§3, P§5, P§8.
    pub fn presence_set(&mut self, state: Option<String>, now: f64) -> Result<Option<String>, JsValue> {
        self.presence_state = state;
        let out = self.presence.as_mut().and_then(|p| p.set(self.presence_state.as_deref(), now as i64));
        self.sign_presence(out, now as i64)
    }

    /// Our presence record due at `now` (a refresh, or one held back), signed, or `null`. Spec: P§8.
    pub fn presence_tick(&mut self, now: f64) -> Result<Option<String>, JsValue> {
        let out = self.presence.as_mut().and_then(|p| p.tick(now as i64));
        self.sign_presence(out, now as i64)
    }

    /// The authority refused our record with `reason` (an `error` whose `in_reply_to` is the record). Spec: P§9.
    pub fn presence_refused(&mut self, reason: &str, retry_after: Option<f64>, now: f64) {
        if let Some(p) = self.presence.as_mut() {
            p.refused(reason, retry_after.map(|r| r as i64), now as i64);
        }
    }

    fn sign_presence(&mut self, out: Option<Value>, now: i64) -> Result<Option<String>, JsValue> {
        let Some(p) = out else { return Ok(None) };
        let lifetime = self.presence.as_ref().map_or(300, |p| p.lifetime());
        self.core.sign_payload(p, now, lifetime).map(Some).map_err(js)
    }

    /// A signed `subscribe` to `target`'s presence at its authority `authority` (the relay that answers for it,
    /// §9.3), for `expires_in` seconds (at most 3,600 for presence; a renewal replaces). Returns
    /// `{"frame", "subscription"}`; the host sends the frame on its connection to that relay.
    /// Spec: §9.3, P§3.
    pub fn presence_subscribe(&mut self, target: &str, authority: &str, expires_in: f64, now: f64) -> Result<String, JsValue> {
        let mut p = json!({"dsip": dsip_core::version::version_block(&self.supported, &[dsip_broadcast::PROFILE]),
                           "type": "subscribe", "to": authority, "target": target, "events": ["presence"], "expires_in": expires_in as i64});
        // P§6: presence is private by default; the grants we hold from the target admit us
        let claims = self.core.presence_claims(target, now as i64);
        let presented = claims.len();
        if presented > 0 {
            p["claims"] = Value::Array(claims);
        }
        let frame = self.core.sign_payload(p, now as i64, 30).map_err(js)?;
        let sub = Envelope::from_frame(&frame)
            .ok()
            .and_then(|e| dsip_core::b64::decode(&e.payload))
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["id"].as_str().map(String::from))
            .unwrap_or_default();
        // §9.3: a renewal replaces the subscription; the watch follows the new one
        self.watches.retain(|_, w| w.target() != target);
        self.watches.insert(sub.clone(), dsip_broadcast::presence::Watch::new(target));
        Ok(json!({"frame": frame, "subscription": sub, "grants": presented}).to_string())
    }

    /// Signed `grant-revocation`s, addressed to our authority, for every grant we issued to `identity` (P§7, §19.4):
    /// sent before the grants are revoked locally, so the authority ends what they admitted. Returns a JSON array of
    /// `{"grant", "frame"}`.
    pub fn grant_revocations(&mut self, identity: &str, authority: &str, now: f64) -> Result<String, JsValue> {
        let ids: Vec<String> = self.core.contacts().grants_issued.iter().filter(|(_, g)| g.identity == identity).map(|(id, _)| id.clone()).collect();
        let mut out = vec![];
        for id in ids {
            if let Some(frame) = self.core.grant_revocation(&id, authority, now as i64).map_err(js)? {
                out.push(json!({"grant": id, "frame": frame}));
            }
        }
        Ok(Value::Array(out).to_string())
    }

    /// A verified presence `notify` payload (from a `received` event). Each carried record is verified here, independently
    /// of the authority. Returns `{"target", "state", "token", "source", "records", "terminated"}` (P§4: `source` is
    /// `record`, `assertion` — the authority's claim — or `none`), or `null` when it is for no presence watch of ours
    /// or out of order. Spec: §9.3, P§3, P§4.
    pub fn presence_notify(&mut self, payload_json: &str, now: f64) -> Option<String> {
        let payload: Value = serde_json::from_str(payload_json).ok()?;
        let sub = payload["subscription"].as_str()?.to_string();
        let core = &self.core;
        let w = self.watches.get_mut(&sub)?;
        if !w.notify(&payload, |f| core.verify_record(f, now as i64)) {
            return None;
        }
        let out = presence_json(w, now as i64);
        if w.terminated() {
            self.watches.remove(&sub);
        }
        Some(out)
    }

    /// Every watched identity's presence at `now`, as [`Endpoint::presence_notify`] gives it (records expire, P§4).
    pub fn presence_all(&self, now: f64) -> String {
        Value::Array(self.watches.values().map(|w| serde_json::from_str(&presence_json(w, now as i64)).unwrap_or(Value::Null)).collect()).to_string()
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

    /// Whether the next `invite`/`update` offers video (its descriptors must match the SDP that rides with it, B§2.1).
    pub fn set_video(&mut self, video: bool) {
        self.core.set_video(video);
    }

    /// Video codec registry ids (JSON array) the next offer lists; they must appear as `rtpmap`s in the SDP (B§3.4).
    pub fn set_video_codecs(&mut self, ids_json: &str) {
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(ids_json) {
            self.core.set_video_codecs(ids);
        }
    }

    /// A local event (README vocabulary JSON), with what the host supplies for its message beside it: `sdp` on
    /// `place_call`, `accept`, `update` and `answer_update`; `claims` (§18.1) and `patch` (`{direction?,
    /// recording_session?, destination?}`, C§6, N§4.1) on `place_call`; `data` on `info` (B§4). Returns a JSON
    /// array of events.
    pub fn local(&mut self, event_json: &str, now: f64) -> Result<String, JsValue> {
        let v: Value = serde_json::from_str(event_json).map_err(js)?;
        let out = self.core.command(command_from_json(&v).map_err(js)?, now as i64).map_err(js)?;
        self.observe(out, now)
    }

    /// An inbound frame. Returns a JSON array of events.
    pub fn inbound(&mut self, frame: &str, now: f64) -> Result<String, JsValue> {
        let out = self.core.inbound(frame, now as i64).map_err(js)?;
        self.observe(out, now)
    }

    /// Advance the clock; due timers fire. Returns a JSON array of events.
    pub fn tick(&mut self, now: f64) -> Result<String, JsValue> {
        let out = self.core.tick(now as i64).map_err(js)?;
        self.observe(out, now)
    }

    fn observe(&mut self, events: Vec<CoreEvent>, now: f64) -> Result<String, JsValue> {
        let out = self.calls.observe(&mut self.core, events, now as i64).map_err(js)?;
        Ok(outs_json(&out))
    }

    /// Place a call to `to`: `invite_json` is `{claims?, patch?}` (as `place_call` takes them). Returns
    /// `{"session", "events"}`; the events ask for the SDP offer (`media_request` `offer`), and the invite goes out
    /// once [`Endpoint::media`] hands it back (§16.3).
    pub fn place(&mut self, to: &str, invite_json: &str, now: f64) -> Result<String, JsValue> {
        let v: Value = serde_json::from_str(invite_json).unwrap_or(json!({}));
        let claims = v.get("claims").and_then(Value::as_array).cloned().unwrap_or_default();
        let patch = match v.get("patch") {
            Some(p) if p.is_object() => serde_json::from_value(p.clone()).map_err(js)?,
            _ => InvitePatch::default(),
        };
        let (session, out) = self.calls.place(&mut self.core, to, Invite { sdp: None, claims, patch }, now as i64).map_err(js)?;
        Ok(json!({"session": session, "events": serde_json::from_str::<Value>(&outs_json(&out)).map_err(js)?}).to_string())
    }

    /// What the user asks of a call: `{"command": "accept"|"screen"|"decline"|"cancel"|"hangup"|"update"|"escalate"|
    /// "answer_update"|"reject_update"|"info"|"accept_recording"|"decline_recording", "session"}`. Returns a JSON
    /// array of events.
    pub fn call(&mut self, command_json: &str, now: f64) -> Result<String, JsValue> {
        let v: Value = serde_json::from_str(command_json).map_err(js)?;
        let out = self.calls.command(&mut self.core, call_command(&v)?, now as i64).map_err(js)?;
        Ok(outs_json(&out))
    }

    /// The page's answer to a `media_request` (`{"kind": "offer"|"answer", "session", "sdp"}`), or a local ICE
    /// candidate (`{"kind": "candidate", "session", "candidate": {candidate, sdp_mid, sdp_m_line_index}|null}`, null at
    /// the end). Returns a JSON array of events.
    pub fn media(&mut self, result_json: &str, now: f64) -> Result<String, JsValue> {
        let v: Value = serde_json::from_str(result_json).map_err(js)?;
        let out = self.calls.media(&mut self.core, media_result(&v)?, now as i64).map_err(js)?;
        Ok(outs_json(&out))
    }

    /// The outcome of a `resolve` event: the DID document fetched for `did` (JSON), or `""` when the fetch failed
    /// (`error` says why). A document is held from now on, for calls and for relay `hello`s alike (§8.1, §8.4); the
    /// frames that waited for it are verified. Returns a JSON array of events.
    pub fn resolved(&mut self, did: &str, doc_json: &str, error: &str, now: f64) -> Result<String, JsValue> {
        let result = match serde_json::from_str::<dsip_core::did::DidDocument>(doc_json) {
            Ok(d) if d.id == did => {
                self.resolver.insert(d.clone());
                Ok(d)
            }
            Ok(d) => Err(dsip_core::did::ResolveError::Fetch { did: did.into(), detail: format!("the document is for {}", d.id) }),
            Err(e) => Err(dsip_core::did::ResolveError::Fetch { did: did.into(), detail: if error.is_empty() { e.to_string() } else { error.into() } }),
        };
        let out = self.core.resolved(did, result, now as i64).map_err(js)?;
        self.observe(out, now)
    }

    /// Whether outbound session bodies are sealed (§10.4); a sealed call refused as an unknown critical extension is
    /// placed once more in clear, and sealing stays off afterwards.
    pub fn seal(&self) -> bool {
        self.core.seal()
    }

    /// Seal outbound session bodies to the addressee's key agreement key when it resolves (§10.4).
    pub fn set_seal(&mut self, on: bool) {
        self.core.set_seal(on);
    }

    /// The other side's recording in `session` (C§4): `{disclosure, pending, hold_media, …}`, or `null`.
    pub fn recording(&self, session: &str) -> String {
        self.calls.consent(session).unwrap_or(Value::Null).to_string()
    }

    /// Whether the other side's recording holds our media in `session` (C§4).
    pub fn holds_media(&self, session: &str) -> bool {
        self.calls.holds_media(session)
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

/// Choose a peer's mailbox (M§4.2, §8.1): its DID document's `DSIPMailbox` entries when it has a document held here,
/// else the `DSIPMailbox` endpoints of its reachability hint (`hint_select`'s `endpoints`), through the vector-pinned
/// `select_mailbox`. Returns `{"source": "did-document"|"hint"|null, "selected": did|null, "uri": …, "order": […]}`.
#[wasm_bindgen]
pub fn mailbox_select(document_json: &str, hint_endpoints_json: &str) -> String {
    let doc: Value = serde_json::from_str(document_json).unwrap_or(Value::Null);
    let document_entries: Vec<Value> = doc["service"].as_array().into_iter().flatten()
        .filter(|s| s["type"] == "DSIPMailbox").map(|s| s["serviceEndpoint"].clone()).collect();
    let hint_entries: Vec<Value> = serde_json::from_str::<Vec<Value>>(hint_endpoints_json).unwrap_or_default().into_iter()
        .filter(|e| e["service"] == "DSIPMailbox")
        .map(|mut e| { if let Some(m) = e.as_object_mut() { m.remove("service"); } e }).collect();
    let all: Vec<Value> = document_entries.iter().chain(hint_entries.iter()).cloned().collect();
    let mut out = dsip_messaging::client::select_mailbox(&json!({"document_entries": document_entries, "hint_entries": hint_entries}));
    let entry = all.iter().find(|e| e["mailbox"] == out["selected"]).cloned().unwrap_or(Value::Null);
    out["uri"] = entry["uri"].clone();
    out["entry"] = entry; // M§4.2: `accepts` and `voicemail` are read from the selected entry
    out.to_string()
}

/// Whether the caller may offer to record a voicemail after an attempt ended (M§13.2, the pinned rule):
/// `entry_json` the callee's selected `DSIPMailbox` entry, `can_send` from [`messaging::Messenger::can_send`],
/// `outcome_type` `reject` or `cancel` (our own), `reason` its token. `{"offer": bool, "max_duration_s"?}`.
#[wasm_bindgen]
pub fn voicemail_offer(entry_json: &str, can_send: bool, outcome_type: &str, reason: &str) -> String {
    let entry: Value = serde_json::from_str(entry_json).unwrap_or(Value::Null);
    dsip_messaging::client::voicemail_offer(&json!({"voicemail": entry["voicemail"], "can_send": can_send,
        "outcome": {"type": outcome_type, "reason": reason}})).to_string()
}

/// Re-issue this identity's delegation with `dsip.messaging` (M§4.3), and `extra` when given (`dsip.record` for a
/// record-keeper, C§9), when the identity key is on this device: the identity JSON with the new delegation (see
/// [`messaging::redelegate`]).
#[wasm_bindgen]
pub fn redelegate(identity_json: &str, now: f64, extra: Option<String>) -> Result<String, JsValue> {
    messaging::redelegate(identity_json, now as i64, extra.as_deref())
}
