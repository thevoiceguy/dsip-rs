//! Stateless semantic checks (stages 12–14).
//!
//! Spec: §11 (version), §13.2/§20.5 (relay `hello` anti-splicing), §14.2
//! (selection ⊆ offer), §9.3 (subscription lifetime caps), §19.4
//! (introduction size, grant references an introduction), §15.1/§14.3/§12.10/§22.2
//! (registry membership with fallback), §7.5 (`key-rotation`: `from` = `subject`,
//! `next` ≠ `previous`, signer = `previous` unless `recovery`). Schema README checks 5, 7, 9, 11, 12.

use serde_json::{Map, Value};

use dsip_core::registry::{
    effective_answered_by, effective_integrity, effective_progress_status, resolve_reason, INTEGRITY_MODES,
    REASON_BEARING_TYPES, SUBSCRIPTION_EVENTS,
};
use dsip_core::version::{check_version, Supported};
use dsip_core::{RejectCode, Verdict, INTRODUCTION_MAX_BYTES};

use crate::validate::validate;

/// Receiver context for the stateless checks.
#[derive(Debug, Default, Clone)]
pub struct SemanticContext {
    /// Supported versions.
    pub supported: Supported,
    /// The id of the client `hello` this connection sent (relay `hello` anti-splicing).
    pub sent_hello_id: Option<String>,
    /// The offer (`media`, `transports`) an `answer` must select from.
    pub offer: Option<Value>,
    /// Pending introduction ids a `grant` may reference; `None` skips the check.
    pub known_introductions: Option<Vec<String>>,
    /// Encoded envelope size in bytes, when known (introduction cap).
    pub encoded_size: Option<usize>,
    /// The `kid` that signed the envelope, when known (`key-rotation` signer rule, §7.5).
    pub signer_kid: Option<String>,
}

impl SemanticContext {
    /// From a vector's `context` object.
    pub fn from_vector(ctx: &Value) -> SemanticContext {
        SemanticContext {
            supported: Supported::from_json(ctx.get("supported")),
            sent_hello_id: ctx.get("sent_hello_id").and_then(Value::as_str).map(String::from),
            offer: ctx.get("offer").filter(|o| o.is_object()).cloned(),
            known_introductions: ctx.get("known_introductions").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).map(String::from).collect()
            }),
            encoded_size: ctx.get("encoded_size").and_then(Value::as_u64).map(|n| n as usize),
            signer_kid: ctx.get("signer_kid").and_then(Value::as_str).map(String::from),
        }
    }
}

/// Impl (spec-gap 9): SDP-style offer→answer direction compatibility.
fn direction_answers(offered: &str, selected: &str) -> bool {
    matches!(
        (offered, selected),
        ("sendrecv", _) | ("sendonly", "recvonly" | "inactive") | ("recvonly", "sendonly" | "inactive") | ("inactive", "inactive")
    ) && ["sendrecv", "sendonly", "recvonly", "inactive"].contains(&selected)
}

/// Check 9: is `selection` (an `answer`) a subset of `offer`?
///
/// Spec: §14.2 — an answer is a selection, not a second offer. Impl (spec-gap 9)
/// for the per-field rule: match descriptors on `type`+`purpose`; codec ids ⊆
/// offered; direction answers the offered direction; transport id ∈ offered.
pub fn selection_is_subset(selection: &Value, offer: &Value) -> bool {
    let arr = |v: &Value, k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    let offered_media = arr(offer, "media");
    for sel in arr(selection, "media") {
        let Some(m) = offered_media.iter().find(|o| s(o, "type") == s(&sel, "type") && s(o, "purpose") == s(&sel, "purpose"))
        else {
            return false;
        };
        let offered_codecs: Vec<_> = arr(m, "codecs").iter().filter_map(|c| s(c, "id")).collect();
        if arr(&sel, "codecs").iter().any(|c| !s(c, "id").is_some_and(|id| offered_codecs.contains(&id))) {
            return false;
        }
        if !direction_answers(&s(m, "direction").unwrap_or_default(), &s(&sel, "direction").unwrap_or_default()) {
            return false;
        }
    }
    let offered_transports: Vec<_> = arr(offer, "transports").iter().filter_map(|t| s(t, "id")).collect();
    arr(selection, "transports").iter().all(|t| s(t, "id").is_some_and(|id| offered_transports.contains(&id)))
}

/// Stage 14: the stateless semantic checks, then registry effects on accept.
pub fn check_semantic(payload: &Value, ctx: &SemanticContext) -> Verdict {
    let t = payload.get("type").and_then(Value::as_str).unwrap_or("");
    let s = |k: &str| payload.get(k).and_then(Value::as_str);
    if t == "hello" {
        if let (Some(irt), Some(sent)) = (s("in_reply_to"), ctx.sent_hello_id.as_deref()) {
            if irt != sent {
                // §13.2 / §20.5: the relay hello is bound to the client hello it answers
                return Verdict::reject(RejectCode::HelloInReplyToMismatch);
            }
        }
    }
    if t == "answer" {
        if let Some(offer) = &ctx.offer {
            if !selection_is_subset(payload, offer) {
                return Verdict::reject(RejectCode::SelectionNotSubset);
            }
        }
    }
    if t == "subscribe" {
        let expires_in = payload.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
        for ev in payload.get("events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if let Some((_, cap)) = SUBSCRIPTION_EVENTS.iter().find(|(e, _)| *e == ev) {
                if expires_in > *cap {
                    // §9.3 hard caps → `error policy.subscription-lifetime` (v0.7, spec-gap 19)
                    return Verdict::reject_with(RejectCode::SubscriptionLifetimeExceeded, "policy.subscription-lifetime");
                }
            }
        }
    }
    if t == "introduction" {
        if let Some(size) = ctx.encoded_size {
            if size > INTRODUCTION_MAX_BYTES {
                return Verdict::reject(RejectCode::IntroductionTooLarge); // §19.4
            }
        }
    }
    if t == "grant" {
        if let Some(known) = &ctx.known_introductions {
            if !s("session").is_some_and(|sid| known.iter().any(|k| k == sid)) {
                return Verdict::reject(RejectCode::GrantUnknownIntroduction); // §19.4
            }
        }
    }
    if t == "key-rotation" {
        // §7.5 (v0.7, spec-gap 22): only the identity rotates its own keys, by its retiring key
        // unless a recovery key signs with `recovery: true`.
        if s("subject") != s("from") {
            return Verdict::reject(RejectCode::RotationSubjectMismatch);
        }
        if s("next") == s("previous") {
            return Verdict::reject(RejectCode::RotationNextSameAsPrevious);
        }
        let recovery = payload.get("recovery").and_then(Value::as_bool).unwrap_or(false);
        if let Some(signer) = ctx.signer_kid.as_deref() {
            if !recovery && Some(signer) != s("previous") {
                return Verdict::reject(RejectCode::RotationSignerNotPrevious);
            }
        }
    }
    let mut v = Verdict::accept();
    for (k, val) in registry_effects(payload) {
        v = v.with(&k, val);
    }
    v
}

/// Check 5 — registry membership with fallback. Never rejects; yields `effective` and `warnings`.
///
/// Spec: §15.1, §14.3, §12.10.
pub fn registry_effects(payload: &Value) -> Map<String, Value> {
    let t = payload.get("type").and_then(Value::as_str).unwrap_or("");
    let mut eff = Map::new();
    let mut warnings: Vec<Value> = vec![];
    if let Some(reason) = payload.get("reason").and_then(Value::as_str) {
        if REASON_BEARING_TYPES.contains(&t) || t == "notify" {
            let r = resolve_reason(reason, t);
            eff.insert("reason".into(), r.effective.into());
            eff.insert("fallback".into(), r.fallback.into());
            if !r.valid_on_type {
                warnings.push("reason-not-valid-on-type".into()); // Impl (spec-gap 10)
            }
        }
    }
    if (t == "answer" || t == "update") && payload.get("answered_by").is_some() {
        if let Some(a) = payload.get("answered_by").and_then(Value::as_str) {
            eff.insert("answered_by".into(), effective_answered_by(a).into());
        }
    }
    if t == "progress" {
        if let Some(st) = payload.get("status").and_then(Value::as_str) {
            eff.insert("status".into(), effective_progress_status(st).into());
        }
    }
    if t == "publish" {
        if let Some(m) = payload.get("integrity").and_then(Value::as_str) {
            eff.insert("integrity".into(), effective_integrity(Some(m)).into());
            if !INTEGRITY_MODES.contains(&m) {
                warnings.push("integrity-mode-unknown".into()); // §22.2 registry fallback
            }
        }
    }
    let mut out = Map::new();
    if !eff.is_empty() {
        out.insert("effective".into(), Value::Object(eff));
    }
    if !warnings.is_empty() {
        out.insert("warnings".into(), Value::Array(warnings));
    }
    out
}

/// Stages 12–14 in order: version, schema, semantic.
pub fn check_payload(payload: &Value, ctx: &SemanticContext) -> Verdict {
    let v = check_version(payload, &ctx.supported);
    if !v.ok() {
        return v;
    }
    let v = validate(payload);
    if !v.ok() {
        return v;
    }
    check_semantic(payload, ctx)
}
