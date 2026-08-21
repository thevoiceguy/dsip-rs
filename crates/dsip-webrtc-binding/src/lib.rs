//! `dsip-webrtc-binding` — the WebRTC Media Binding 1.0 (v0.7 companion document
//! `v0.7/dsip-webrtc-media-binding-v0.7.md`), as pure, stack-independent rules.
//!
//! Spec: sections owned by this crate — B§2 (the `transport:webrtc` descriptor and
//! where SDP rides), B§2.1 (descriptors are authoritative for *what* was negotiated,
//! SDP for transport parameters, and the two MUST agree), B§2.2 (SDP profile: BUNDLE,
//! rtcp-mux, sha-256 fingerprint, `a=setup`), B§3.1/B§3.3 (role mapping; offer
//! `actpass`, answer `active`/`passive`), B§3.4 (codec identifier ↔ `a=rtpmap`),
//! B§4.2–B§4.4 (candidate carriage in `info`, ACTIVE-only buffering, attribution),
//! B§5 (re-offer on the same transport; rollback; ICE restart refused), B§6.1 (exactly
//! one answer applied per offer), B§7 (encryption floor), B§8 (reason tokens).
//!
//! Impl: the media backends (`dsip-media`) produce and consume real SDP; this crate is
//! what the endpoint runs *between* the signalling layer and the backend so that the
//! binding's MUSTs are enforced identically whichever stack is underneath, and what the
//! `media-binding/` vectors pin. It compiles to WASM (no I/O, no media dependencies).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod candidates;
pub mod renegotiation;
pub mod sdp;

use serde_json::{json, Value};

use dsip_core::{RejectCode, Verdict};
pub use sdp::{parse_sdp, Sdp, Section};

/// B§3.4 — DSIP codec identifiers → SDP encoding names (compared case-insensitively).
pub const CODEC_ENCODING: &[(&str, &str)] = &[
    ("codec:audio/opus", "opus"),
    ("codec:audio/pcmu", "PCMU"),
    ("codec:audio/pcma", "PCMA"),
    ("codec:audio/g722", "G722"),
    ("codec:video/h264", "H264"),
    ("codec:video/vp8", "VP8"),
    ("codec:video/vp9", "VP9"),
    ("codec:video/av1", "AV1"),
];

/// B§7 — transport profiles that satisfy the encryption floor (DTLS-SRTP or SRTP).
pub const SECURE_PROTOCOLS: &[&str] = &["UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVP", "TCP/TLS/RTP/SAVPF", "RTP/SAVPF", "RTP/SAVP"];

fn transport0(payload: &Value) -> &Value {
    payload.get("transports").and_then(Value::as_array).and_then(|a| a.first()).unwrap_or(&Value::Null)
}

fn reject(code: RejectCode, reason: &'static str, detail: String) -> Verdict {
    Verdict::reject_with(code, reason).detail(detail)
}

/// B§2.1/B§2.2/B§3.3: the descriptor and its SDP must agree and the SDP must carry the
/// profile. Offers fail with `media.unsupported` (`media.offer-required` without SDP,
/// `media.encryption-required` for plain RTP); answers fail with `media.failed` (the
/// accepted leg is ended with `bye`).
pub fn check_description(payload: &Value, is_answer: bool, offer_sdp: Option<&Sdp>) -> Verdict {
    let bad: &'static str = if is_answer { "media.failed" } else { "media.unsupported" };
    let t = transport0(payload);
    if t.get("id").and_then(Value::as_str) != Some("transport:webrtc") {
        return Verdict::accept().with("binding", "not-webrtc");
    }
    let ice = t.get("ice").and_then(Value::as_str);
    if (!is_answer && ice != Some("trickle")) || (is_answer && t.get("ice").is_some() && ice != Some("trickle")) {
        return reject(RejectCode::BindingIceMode, bad, format!("ice={ice:?}"));
    }
    let Some(sdp_text) = t.get("sdp").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return reject(RejectCode::BindingSdpMissing, if is_answer { "media.failed" } else { "media.offer-required" }, "transports[0].sdp".into());
    };
    let Some(sdp) = parse_sdp(sdp_text) else {
        return reject(RejectCode::BindingSdpInvalid, bad, "unparseable SDP".into());
    };
    let empty = vec![];
    let media = payload.get("media").and_then(Value::as_array).unwrap_or(&empty);
    let live: Vec<&Section> = sdp.sections.iter().filter(|s| s.port != 0).collect();
    if is_answer {
        if let Some(o) = offer_sdp {
            if sdp.sections.len() != o.sections.len() {
                return reject(RejectCode::BindingSectionCount, bad, format!("{} sections for an offer of {}", sdp.sections.len(), o.sections.len()));
            }
        }
    }
    if live.iter().any(|s| s.kind == "application") {
        return reject(RejectCode::BindingExtraSection, bad, "m=application is outside Core v1.0".into());
    }
    if live.len() != media.len() {
        return reject(RejectCode::BindingSectionCount, bad, format!("{} live m= sections for {} media descriptors", live.len(), media.len()));
    }
    for (i, (desc, sec)) in media.iter().zip(live.iter()).enumerate() {
        let ty = desc.get("type").and_then(Value::as_str).unwrap_or("");
        if sec.kind != ty {
            return reject(RejectCode::BindingKindMismatch, bad, format!("section {i}: m={} for type {ty}", sec.kind));
        }
        if !SECURE_PROTOCOLS.contains(&sec.protocol.as_str()) {
            let reason = if is_answer { bad } else { "media.encryption-required" };
            return reject(RejectCode::BindingEncryption, reason, format!("section {i}: {}", sec.protocol));
        }
        let direction = sec.direction().or_else(|| sdp.session_direction()).unwrap_or("sendrecv");
        let want = desc.get("direction").and_then(Value::as_str).unwrap_or("");
        if direction != want {
            return reject(RejectCode::BindingDirectionMismatch, bad, format!("section {i}: a={direction} for direction {want}"));
        }
        let enc = sec.encodings();
        for c in desc.get("codecs").and_then(Value::as_array).into_iter().flatten() {
            let id = c.get("id").and_then(Value::as_str).unwrap_or("");
            if let Some((_, name)) = CODEC_ENCODING.iter().find(|(cid, _)| *cid == id) {
                if !enc.iter().any(|e| e.eq_ignore_ascii_case(name)) {
                    return reject(RejectCode::BindingCodecMissing, bad, format!("section {i}: no rtpmap for {id}"));
                }
            }
        }
        if !sec.has("rtcp-mux") {
            return reject(RejectCode::BindingRtcpMuxMissing, bad, format!("section {i}"));
        }
        match sdp.attr(sec, "fingerprint") {
            Some(fp) if fp.to_ascii_lowercase().starts_with("sha-256 ") => {}
            _ => return reject(RejectCode::BindingFingerprintMissing, bad, format!("section {i}: a=fingerprint:sha-256 required")),
        }
        if sdp.attr(sec, "ice-ufrag").is_none() || sdp.attr(sec, "ice-pwd").is_none() {
            return reject(RejectCode::BindingIceCredentialsMissing, bad, format!("section {i}"));
        }
        let setup = sdp.attr(sec, "setup");
        if is_answer {
            if !matches!(setup, Some("active" | "passive")) {
                return reject(RejectCode::BindingSetupInvalid, bad, format!("section {i}: answer a=setup:{} (must be active or passive)", setup.unwrap_or("none")));
            }
        } else if setup != Some("actpass") {
            return reject(RejectCode::BindingSetupInvalid, bad, format!("section {i}: offer a=setup:{} (must be actpass)", setup.unwrap_or("none")));
        }
    }
    Verdict::accept()
}

/// B§2: an `invite`/`update` offer.
pub fn check_offer(payload: &Value) -> Verdict {
    check_description(payload, false, None)
}

/// B§2/B§3.1: an `answer` against the offer it selects from.
pub fn check_answer(offer: &Value, answer: &Value) -> Verdict {
    let osdp = transport0(offer).get("sdp").and_then(Value::as_str).and_then(parse_sdp);
    check_description(answer, true, osdp.as_ref())
}

/// B§3.3: who is the DTLS client. Offer MUST be `actpass`; answer MUST be `active` or `passive`.
pub fn dtls_roles(offer_setup: &str, answer_setup: &str) -> Value {
    if offer_setup != "actpass" {
        return reject(RejectCode::BindingSetupInvalid, "media.unsupported", format!("offer a=setup:{offer_setup}")).to_expect();
    }
    match answer_setup {
        "active" => json!({"verdict": "accept", "offerer": "server", "answerer": "client"}),
        "passive" => json!({"verdict": "accept", "offerer": "client", "answerer": "server"}),
        other => reject(RejectCode::BindingSetupInvalid, "media.failed", format!("answer a=setup:{other}")).to_expect(),
    }
}

/// The ICE credentials `(ufrag, pwd)` of a payload's webrtc descriptor, if any (B§5.4).
pub fn ice_credentials(payload: &Value) -> Option<(String, String)> {
    let sdp = transport0(payload).get("sdp").and_then(Value::as_str).and_then(parse_sdp)?;
    let sec = sdp.sections.first();
    let get = |name: &str| match sec {
        Some(s) => sdp.attr(s, name).map(String::from),
        None => sdp.session_value(name).map(String::from),
    };
    Some((get("ice-ufrag")?, get("ice-pwd")?))
}

/// B§6.1 / Core §12.7 rule 4: exactly one answer is applied — the first valid one; earlier
/// invalid ones end their leg with `bye media.failed`, later ones with `bye session.already-answered`.
pub fn one_answer(offer: &Value, answers: &[Value]) -> Value {
    let mut applied: Option<String> = None;
    let mut legs = vec![];
    for a in answers {
        let from = a.get("from").cloned().unwrap_or(Value::Null);
        if applied.is_some() {
            legs.push(json!({"from": from, "bye": "session.already-answered"}));
            continue;
        }
        let v = check_answer(offer, a);
        if v.ok() {
            applied = from.as_str().map(String::from);
            legs.push(json!({"from": from, "applied": true}));
        } else {
            legs.push(json!({"from": from, "bye": "media.failed", "code": v.code}));
        }
    }
    json!({"applied": applied, "legs": legs})
}

/// Vector runner entry (`kind: media-binding`): dispatch on `input.check`.
pub fn run_vector(v: &Value) -> Value {
    let inp = &v["input"];
    let ctx = &v["context"];
    match inp["check"].as_str().unwrap_or("") {
        "offer" => check_offer(&inp["payload"]).to_expect(),
        "answer" => check_answer(&inp["offer"], &inp["payload"]).to_expect(),
        "role" => dtls_roles(inp["offer_setup"].as_str().unwrap_or(""), inp["answer_setup"].as_str().unwrap_or("")),
        "one-answer" => one_answer(&inp["offer"], inp["answers"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "candidates" => {
            let mut m = candidates::CandidateExchange::new(ctx.get("peer").and_then(Value::as_str));
            trace(inp, |e| m.step(e))
        }
        "renegotiation" => {
            let mut m = renegotiation::Renegotiation::new(ctx.get("ufrag").and_then(Value::as_str));
            trace(inp, |e| m.step(e))
        }
        other => json!({"error": format!("unknown media-binding check {other}")}),
    }
}

fn trace(inp: &Value, mut step: impl FnMut(&Value) -> Vec<Value>) -> Value {
    let steps: Vec<Value> = inp["steps"].as_array().into_iter().flatten().map(|st| json!({"emit": step(&st["event"])})).collect();
    json!({"steps": steps})
}
