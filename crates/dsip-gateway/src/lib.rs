//! `dsip-gateway` — the protocol rules of the DSIP↔SIP/PSTN gateway (Phase 4, workstream G0/G1;
//! `impl/docs/dsip_gateway_plan.md`). Pure: no SIP stack, no media; the daemon hosts this the
//! way `dsip-cli` hosts `dsip-endpoint`.
//!
//! Spec: sections owned by this crate — §15.5 (foreign codes MUST be mapped to DSIP reasons,
//! never tunnelled; [`map_inbound`]/[`map_outbound`] are the normative tables the Gateway
//! Profile will carry), §6.3 (crossing the PSTN is a trust downgrade unless identity semantics
//! are preserved — [`downgrade`]), §14.1 (a gateway answers with `answered_by: gateway`),
//! §18.1 (a PSTN caller is a claim with a verification basis, never a badge — [`tel_claim`]),
//! §19.4 (first contact applies to the gateway identity), §12.5 (the cancel/answer race on the
//! SIP leg), §16.2/§14.2 (SDP ⇄ descriptors), Appendix C (early media: classify or answer and
//! pass through).
//!
//! Impl: every table here is pinned by `impl/vectors/gateway/`; the Python reference is
//! `impl/tools/dsipvec/gateway.py`. Choices the spec leaves open (Q.850 precedence over the SIP
//! status, the `Reason: DSIP;text=<token>` header on every crossing, attempt-phase tokens
//! becoming `gateway.mapped` once ACTIVE, single-contact 3xx handling) are plan §11 spec gaps.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod controller;
#[cfg(feature = "host")]
pub mod host;

use serde_json::{json, Map, Value};

use dsip_webrtc_binding::{parse_sdp, CODEC_ENCODING};

/// The gateway's own identity (the verifier named in claims).
pub const GATEWAY_DID: &str = "did:web:gw.example";

/// Q.850 cause → DSIP reason (RFC 3326 Reason header; wins over the SIP status when mapped).
pub const Q850_TO_DSIP: &[(u32, &str)] = &[
    (1, "identity.unknown"), (16, "user.hangup"), (17, "endpoint.busy"), (18, "endpoint.unavailable"),
    (19, "endpoint.unavailable"), (20, "endpoint.unavailable"), (21, "user.declined"), (22, "identity.not-in-service"),
    (28, "identity.unknown"), (31, "user.hangup"), (34, "gateway.unreachable"), (38, "gateway.unreachable"),
    (41, "gateway.unreachable"), (42, "gateway.unreachable"), (43, "gateway.unreachable"), (44, "gateway.unreachable"),
    (47, "media.failed"), (63, "media.unsupported"), (65, "media.unsupported"), (79, "media.unsupported"), (102, "session.timeout"),
];

/// SIP final status → DSIP reason (§15.5, extended).
pub const SIP_TO_DSIP: &[(u32, &str)] = &[
    (403, "policy.blocked"), (404, "identity.unknown"), (408, "endpoint.unavailable"), (410, "identity.not-in-service"),
    (415, "media.unsupported"), (480, "endpoint.unavailable"), (484, "identity.unknown"), (486, "endpoint.busy"),
    (487, "session.cancelled"), (488, "media.unsupported"), (502, "gateway.unreachable"), (503, "gateway.unreachable"),
    (504, "gateway.unreachable"), (600, "endpoint.busy"), (603, "user.declined"), (604, "identity.unknown"), (606, "media.unsupported"),
];

/// DSIP reason → (SIP status, Q.850 cause) for a pre-answer refusal.
pub const DSIP_TO_SIP: &[(&str, u32, Option<u32>)] = &[
    ("user.declined", 603, Some(21)), ("user.no-answer", 480, Some(19)), ("user.blocked", 603, Some(21)), ("user.cancelled", 487, None),
    ("endpoint.busy", 486, Some(17)), ("endpoint.unavailable", 480, Some(18)), ("endpoint.capability", 488, Some(79)),
    ("identity.not-in-service", 410, Some(22)), ("identity.moved", 410, Some(22)), ("identity.suspended", 403, Some(21)), ("identity.unknown", 404, Some(1)),
    ("session.expired", 480, Some(102)), ("session.timeout", 480, Some(102)), ("session.failed", 500, Some(41)),
    ("media.unsupported", 488, Some(65)), ("media.offer-required", 488, Some(65)), ("media.encryption-required", 488, Some(65)),
    ("policy.blocked", 403, Some(21)), ("policy.trust-insufficient", 403, Some(21)), ("policy.first-contact-required", 403, Some(21)),
    ("policy.rate-limited", 503, Some(42)), ("policy.terminated", 480, Some(31)),
    ("transport.envelope-too-large", 503, Some(41)), ("transport.hello-required", 503, Some(41)), ("transport.hello-rejected", 503, Some(41)),
    ("transport.routing-refused", 503, Some(41)), ("transport.unknown-recipient", 404, Some(1)), ("transport.rate-limited", 503, Some(42)),
    ("gateway.unreachable", 503, Some(38)), ("gateway.mapped", 500, Some(41)),
];

/// DSIP reason → Q.850 cause on a BYE.
pub const BYE_CAUSES: &[(&str, u32)] = &[("user.hangup", 16), ("session.already-answered", 16), ("session.cancelled", 16), ("media.failed", 47), ("policy.terminated", 31)];

const ATTEMPT_TOKENS: &[&str] = &[
    "endpoint.busy", "endpoint.unavailable", "identity.unknown", "identity.not-in-service", "identity.moved", "session.cancelled",
    "user.declined", "policy.blocked",
];

fn lookup<'a>(table: &'a [(u32, &'a str)], k: u32) -> Option<&'a str> {
    table.iter().find(|(c, _)| *c == k).map(|(_, t)| *t)
}

/// §15.5: a SIP final response (or BYE Reason) → `{reason, carry, detail?}`. `phase` is the DSIP
/// leg's state: `pre-answer` → `reject`, `active` → `bye`, `transport` → `error`.
pub fn map_inbound(sip_status: Option<u32>, q850: Option<u32>, phase: &str, moved_to: Option<&str>) -> Value {
    let carry = match phase { "active" => "bye", "transport" => "error", _ => "reject" };
    let (mut token, mut detail): (String, Option<String>) = match (q850.and_then(|c| lookup(Q850_TO_DSIP, c)), sip_status.and_then(|s| lookup(SIP_TO_DSIP, s))) {
        (Some(t), _) => (t.into(), Some(format!("Q.850 {}", q850.unwrap()))),
        (None, Some(t)) => (t.into(), Some(format!("SIP {}", sip_status.unwrap()))),
        (None, None) if sip_status.is_none() && q850.is_none() => ("user.hangup".into(), None),
        (None, None) => ("gateway.mapped".into(), Some(match sip_status { Some(s) => format!("SIP {s}"), None => format!("Q.850 {}", q850.unwrap()) })),
    };
    if token == "identity.not-in-service" {
        if let Some(m) = moved_to {
            token = "identity.moved".into();
            detail = Some(m.to_string());
        }
    }
    if phase == "active" && ATTEMPT_TOKENS.contains(&token.as_str()) {
        detail = Some(detail.unwrap_or_else(|| token.clone()));
        token = "gateway.mapped".into();
    }
    let mut out = json!({"reason": token, "carry": carry});
    if let Some(d) = detail {
        out["detail"] = d.into();
    }
    out
}

/// §15.5 reverse: a DSIP reason → the SIP leg's final response (pre-answer) or BYE (active), always
/// with `Reason: DSIP;text=<token>` and a Q.850 cause where one fits.
pub fn map_outbound(token: &str, phase: &str) -> Value {
    let hdr = json!({"protocol": "DSIP", "text": token});
    let entry = DSIP_TO_SIP.iter().find(|(t, _, _)| *t == token);
    if phase == "active" {
        let cause = BYE_CAUSES.iter().find(|(t, _)| *t == token).map(|(_, c)| *c)
            .or_else(|| entry.and_then(|(_, _, c)| *c)).unwrap_or(16);
        return json!({"method": "BYE", "q850": cause, "reason_header": hdr});
    }
    let (status, cause) = match entry {
        Some((_, s, c)) => (*s, *c),
        None => match token.split('.').next().unwrap_or("") {
            "user" => (603, Some(21)), "endpoint" => (480, Some(18)), "identity" => (404, Some(1)), "session" => (500, Some(41)),
            "media" => (488, Some(65)), "policy" => (403, Some(21)), "transport" => (503, Some(41)), "gateway" => (503, Some(38)),
            _ => (500, Some(41)),
        },
    };
    let mut out = json!({"status": status, "reason_header": hdr});
    if let Some(c) = cause {
        out["q850"] = c.into();
    }
    if matches!(token, "policy.rate-limited" | "transport.rate-limited") {
        out["retry_after"] = true.into();
    }
    out
}

/// A trunk's SDP → DSIP media descriptors (§16.2); unknown encodings dropped, empty sections omitted.
pub fn sip_sdp_to_descriptors(sdp_text: &str) -> Value {
    let Some(sdp) = parse_sdp(sdp_text) else { return json!({"error": "unparseable"}) };
    let mut media = vec![];
    for sec in &sdp.sections {
        if sec.port == 0 || !matches!(sec.kind.as_str(), "audio" | "video") {
            continue;
        }
        let mut codecs: Vec<&str> = vec![];
        for v in sec.values("rtpmap") {
            if let Some((_, rest)) = v.split_once(' ') {
                let enc = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
                if let Some((cid, _)) = CODEC_ENCODING.iter().find(|(_, e)| e.eq_ignore_ascii_case(&enc)) {
                    if !codecs.contains(cid) {
                        codecs.push(cid);
                    }
                }
            }
        }
        if codecs.is_empty() {
            continue;
        }
        let direction = sec.direction().or_else(|| sdp.session_direction()).unwrap_or("sendrecv");
        media.push(json!({"type": sec.kind, "direction": direction, "codecs": codecs.iter().map(|c| json!({"id": c})).collect::<Vec<_>>()}));
    }
    let srtp = if sdp.sections.iter().any(|s| s.has("crypto")) { "sdes" } else if sdp.sections.iter().any(|s| s.protocol.contains("TLS")) { "dtls" } else { "none" };
    json!({"media": media, "srtp": srtp})
}

/// DSIP descriptors → the SIP leg's m= lines (§14.2 selection carried across).
pub fn descriptors_to_sip_sdp(media: &[Value]) -> Value {
    let mut lines = vec![];
    for d in media {
        let encs: Vec<&str> = d["codecs"].as_array().into_iter().flatten()
            .filter_map(|c| c["id"].as_str()).filter_map(|id| CODEC_ENCODING.iter().find(|(cid, _)| *cid == id).map(|(_, e)| *e)).collect();
        if encs.is_empty() {
            continue;
        }
        lines.push(json!({"kind": d["type"], "encodings": encs, "direction": d.get("direction").and_then(Value::as_str).unwrap_or("sendrecv")}));
    }
    json!({"m_lines": lines})
}

/// §18.1/§6.3: the `identity.claims[]` entry for a PSTN caller plus the basis string a client renders.
pub fn tel_claim(from_tn: &str, identity: Option<&Value>, cnam: Option<&str>, gateway: &str) -> Value {
    let (mut attestation, mut verified) = ("none".to_string(), false);
    if let Some(id) = identity.filter(|v| v.is_object()) {
        attestation = id.get("attest").and_then(Value::as_str).unwrap_or("none").to_string();
        verified = id.get("verified").and_then(Value::as_bool).unwrap_or(false) && attestation != "none";
        if let Some(orig) = id.get("orig_tn").and_then(Value::as_str) {
            if orig != from_tn {
                attestation = "none".into();
                verified = false;
            }
        }
    }
    let mut claim = Map::new();
    claim.insert("type".into(), "tel".into());
    claim.insert("number".into(), from_tn.into());
    claim.insert("attestation".into(), attestation.clone().into());
    claim.insert("verified".into(), verified.into());
    claim.insert("verifier".into(), gateway.into());
    if let Some(c) = cnam {
        claim.insert("cnam".into(), c.into());
    }
    let host = gateway.strip_prefix("did:web:").unwrap_or(gateway);
    let basis = if verified {
        format!("Gateway attested by {host} · STIR attestation {attestation} (verified)")
    } else if attestation != "none" {
        format!("Gateway attested by {host} · STIR attestation {attestation} (unverified)")
    } else {
        format!("Gateway attested by {host} · no attestation")
    };
    json!({"claim": Value::Object(claim), "trust_basis": basis})
}

/// §6.3: which crossings emit `gateway.downgraded`; each lost guarantee is named.
pub fn downgrade(facts: &Value) -> Value {
    let b = |k: &str| facts.get(k).and_then(Value::as_bool).unwrap_or(false);
    let direction = facts.get("direction").and_then(Value::as_str).unwrap_or("");
    let mut lost = vec![];
    if !b("trunk_srtp") {
        lost.push("no-srtp-on-trunk");
    }
    if direction == "outbound" && !b("identity_assertable") {
        lost.push("identity-not-assertable");
    }
    if direction == "inbound" && facts.get("attestation").and_then(Value::as_str).unwrap_or("none") == "none" {
        lost.push("no-attestation");
    }
    if b("policy_present") {
        lost.push("policy-unenforceable");
    }
    json!({"downgraded": !lost.is_empty(), "lost": lost})
}

/// Vector runner entry (`kind: gateway`): dispatch on `input.check`.
pub fn run_vector(v: &Value) -> Value {
    let inp = &v["input"];
    let s = |k: &str| inp.get(k).and_then(Value::as_str);
    let u = |k: &str| inp.get(k).and_then(Value::as_u64).map(|n| n as u32);
    match s("check").unwrap_or("") {
        "reason-inbound" => map_inbound(u("sip_status"), u("q850"), s("phase").unwrap_or("pre-answer"), s("moved_to")),
        "reason-outbound" => map_outbound(s("reason").unwrap_or(""), s("phase").unwrap_or("pre-answer")),
        "sdp-to-descriptors" => sip_sdp_to_descriptors(s("sdp").unwrap_or("")),
        "descriptors-to-sdp" => descriptors_to_sip_sdp(inp["media"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "claims" => tel_claim(s("from_tn").unwrap_or(""), inp.get("identity"), s("cnam"), GATEWAY_DID),
        "downgrade" => downgrade(&inp["facts"]),
        "trace" => {
            let mut call = controller::GatewayCall::new(&v["context"]);
            let steps: Vec<Value> = inp["steps"].as_array().into_iter().flatten()
                .map(|st| { let emit = call.step(&st["event"]); json!({"emit": emit, "state": call.snapshot()}) }).collect();
            json!({"steps": steps})
        }
        other => json!({"error": format!("unknown gateway check {other}")}),
    }
}
