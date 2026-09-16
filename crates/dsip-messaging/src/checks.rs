//! Stateless checks on profile messages (M§5) and decrypted content objects (M§8, M§10–M§13).
//!
//! Spec: M§5.1 (delivery-envelope lifetimes, `MAX_MLS_BYTES`), M§5.2 (the deposit class table),
//! M§5.5, M§4.4/M§16 (mailbox modes), M§8.1–M§8.4 (content objects, kind/purpose fallback,
//! reactions, blobs), M§10.2–M§10.3 (receipt shapes), M§11.1 (activity fallback), M§12.1 and
//! M§13.3 (personal-group-only objects), M§6.3 (conversation kind fallback).

use std::collections::BTreeSet;

use serde_json::{json, Value};

use dsip_core::ulid::Ulid;

use crate::schemas::schema_ok;

/// Maximum decoded size of an `mls`, `welcome`, `group_info`, `sealed` or `archive` value.
///
/// Spec: M§5.1.
pub const MAX_MLS_BYTES: usize = 24_576;
/// Maximum `expires_at − issued_at` of every profile message.
///
/// Spec: M§5.1 — delivery envelopes, not records.
pub const MAX_LIFETIME_S: i64 = 60;
/// Maximum lifetime of an `ephemeral` deposit.
///
/// Spec: M§11.2.
pub const EPHEMERAL_LIFETIME_S: i64 = 10;
/// Tolerance between a content id's ULID timestamp and `sent_at`.
///
/// Spec: M§8.1 (the §20.6 consistency check applied to content).
pub const ULID_TOLERANCE_S: i64 = 300;
/// Maximum UTF-8 length of a reaction's text.
///
/// Spec: M§8.2.
pub const REACTION_MAX_BYTES: usize = 32;

/// Profile message types with schemas.
pub const MESSAGE_SCHEMAS: &[&str] =
    &["deposit", "accepted", "sync", "items", "key-packages", "key-package-fetch", "blob-put", "mailbox-config"];
/// Content object types with schemas.
pub const OBJECT_SCHEMAS: &[&str] = &["content", "receipt", "activity", "archive-key", "call-event", "archive-record"];

/// Registry `dsip-deposit-class` (M§17).
pub const DEPOSIT_CLASSES: &[&str] = &["handshake", "application", "welcome", "group-info", "ephemeral", "archive", "introduction", "grant"];
/// Deposit classes carrying a signed core envelope for first contact, with a recipient and no group.
///
/// Spec: M§14.1. Impl (spec-gap 54).
pub const FIRST_CONTACT_CLASSES: &[&str] = &["introduction", "grant"];
/// Registry `dsip-content-kind` (M§17).
pub const CONTENT_KINDS: &[&str] = &["text", "audio", "video", "image", "file", "contact", "location"];
/// Registry `dsip-content-purpose` (M§17).
pub const CONTENT_PURPOSES: &[&str] =
    &["message", "voice-message", "video-message", "voicemail", "attachment", "reaction", "callback-request"];
/// Registry `dsip-receipt-kind` (M§17).
pub const RECEIPT_KINDS: &[&str] = &["delivered", "read", "played"];
/// Registry `dsip-activity` (M§17).
pub const ACTIVITIES: &[&str] = &["typing", "recording-audio", "recording-video", "uploading"];
/// Registry `dsip-mailbox-mode` (M§17).
pub const MAILBOX_MODES: &[&str] = &["sync", "queue"];
/// Registry `dsip-conversation-kind` (M§17).
pub const CONVERSATION_KINDS: &[&str] = &["personal", "direct", "group"];

const DEPOSIT_BASE: &[&str] = &["dsip", "type", "id", "from", "to", "issued_at", "expires_at", "group", "class", "recipient"];
const SIZED_FIELDS: &[&str] = &["mls", "welcome", "group_info", "sealed", "archive"];

/// Class-specific (required, permitted) fields of a deposit.
///
/// Spec: M§5.2 class table.
fn deposit_fields(class: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match class {
        "handshake" => (&["mls"], &["mls", "seq", "welcome", "group_info", "ratchet_tree_blob", "grants"]),
        "application" => (&["mls"], &["mls", "seq", "blobs"]),
        "welcome" => (&["mls", "hub"], &["mls", "hub", "grants", "origin", "successor_of", "ratchet_tree_blob"]),
        "group-info" => (&["mls"], &["mls", "ratchet_tree_blob"]),
        "ephemeral" => (&["sealed"], &["sealed"]),
        "introduction" | "grant" => (&["envelope"], &["envelope"]),
        _ => (&["archive", "akid", "ref_group", "ref_seq"], &["archive", "akid", "ref_group", "ref_seq"]),
    }
}

/// `{"verdict": "accept"}`.
pub fn accept() -> Value {
    json!({"verdict": "accept"})
}

/// An accept carrying an `effective` interpretation.
pub fn accept_effective(effective: Value) -> Value {
    json!({"verdict": "accept", "effective": effective})
}

/// A rejection with an implementation-neutral code and, when the profile assigns one, a reason token.
pub fn reject(code: &str, reason: Option<&str>) -> Value {
    match reason {
        Some(r) => json!({"verdict": "reject", "code": code, "reason": r}),
        None => json!({"verdict": "reject", "code": code}),
    }
}

/// Whether any number in `v` is a float (§10.3).
pub fn has_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => n.is_f64(),
        Value::Object(m) => m.values().any(has_float),
        Value::Array(a) => a.iter().any(has_float),
        _ => false,
    }
}

/// Decoded length of unpadded base64url from its length alone (the alphabet is a schema check).
///
/// Impl: computed arithmetically so that decoders differing on non-canonical trailing bits
/// cannot disagree about the limit.
pub fn decoded_len(b64: &str) -> usize {
    b64.len() * 3 / 4
}

fn int(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or(0)
}

/// Schema plus stateless rules for a profile message payload.
///
/// Spec: M§5.1, M§5.2, M§5.5, M§4.4.
pub fn check_message(p: &Value) -> Value {
    let t = p["type"].as_str().unwrap_or("");
    if !MESSAGE_SCHEMAS.contains(&t) {
        return reject("unknown-type", None);
    }
    if !schema_ok(t, p) {
        return reject("schema-invalid", None);
    }
    if int(p, "expires_at") - int(p, "issued_at") > MAX_LIFETIME_S {
        return reject("lifetime-exceeded", None); // M§5.1
    }
    match t {
        "deposit" => check_deposit(p),
        "mailbox-config" if p.get("mode").is_some_and(|m| !MAILBOX_MODES.contains(&m.as_str().unwrap_or(""))) => {
            reject("mailbox-mode-unsupported", Some("mailbox.unsupported-mode"))
        }
        "key-packages"
            if p["key_packages"].as_array().is_none_or(Vec::is_empty) && p.get("last_resort").is_none() =>
        {
            reject("key-packages-empty", None) // M§5.5
        }
        _ => accept(),
    }
}

fn check_deposit(p: &Value) -> Value {
    let class = p["class"].as_str().unwrap_or("");
    if !DEPOSIT_CLASSES.contains(&class) {
        // M§5.2: class is structural; an unknown class is refused, never ignored
        return reject("deposit-class-unsupported", Some("mailbox.unsupported-class"));
    }
    if class == "ephemeral" && int(p, "expires_at") - int(p, "issued_at") > EPHEMERAL_LIFETIME_S {
        return reject("lifetime-exceeded", None); // M§11.2
    }
    let keys: BTreeSet<&str> = p.as_object().map(|m| m.keys().map(String::as_str).collect()).unwrap_or_default();
    let (required, allowed) = deposit_fields(class);
    let missing = required.iter().any(|f| !keys.contains(f));
    let extra = keys.iter().any(|k| !DEPOSIT_BASE.contains(k) && !allowed.contains(k));
    if missing || extra {
        return reject("deposit-fields", None);
    }
    let first_contact = FIRST_CONTACT_CLASSES.contains(&class);
    if first_contact == keys.contains("group") || (first_contact && !keys.contains("recipient")) {
        return reject("deposit-fields", None); // spec-gap 54: first-contact deposits name a recipient and no group
    }
    if class == "introduction" && p["envelope"].as_str().is_some_and(|e| e.len() > dsip_core::INTRODUCTION_MAX_BYTES) {
        return reject("introduction-too-large", Some("transport.envelope-too-large")); // §19.4
    }
    if SIZED_FIELDS.iter().any(|f| p[*f].as_str().is_some_and(|s| decoded_len(s) > MAX_MLS_BYTES)) {
        return reject("object-too-large", Some("mailbox.object-too-large")); // M§5.1
    }
    accept()
}

/// Schema plus stateless rules for a decrypted content object in its group context.
///
/// Spec: M§8.1 (sender is the MLS leaf identity, conversation matches, ULID consistency,
/// unknown objects ignored), M§10, M§11.1, M§12.1, M§13.3.
pub fn check_object(o: &Value, ctx: &Value) -> Value {
    if has_float(o) {
        return reject("payload-float", None); // §10.3 applies inside MLS plaintext too
    }
    let name = o["object"].as_str().unwrap_or("");
    if !OBJECT_SCHEMAS.contains(&name) {
        return accept_effective(json!({"render": "ignore"}));
    }
    if !schema_ok(name, o) {
        return reject("schema-invalid", None);
    }
    if matches!(name, "content" | "receipt" | "activity") {
        if o["sender"] != ctx["leaf_identity"] {
            return reject("sender-mismatch", None);
        }
        // spec-gap 52: an undisclosed read watermark travels in the personal group (M§10.5) and names the
        // conversation it describes, not the personal group's own
        let private_read = name == "receipt" && o["kind"] == "read" && ctx["conversation_kind"] == "personal";
        if o["conversation"] != ctx["conversation"] && !private_read {
            return reject("conversation-mismatch", None);
        }
    }
    if matches!(name, "content" | "receipt") {
        let ts = Ulid::parse(o["id"].as_str().unwrap_or("")).map(|u| u.timestamp_s()).unwrap_or(i64::MIN / 2);
        if (ts - int(o, "sent_at")).abs() > ULID_TOLERANCE_S {
            return reject("ulid-sent-at-mismatch", None);
        }
    }
    if matches!(name, "archive-key" | "call-event") && ctx["conversation_kind"].as_str() != Some("personal") {
        return reject("personal-group-only", None); // M§12.1, M§13.3
    }
    match name {
        "content" => check_content(o),
        "receipt" => {
            let kind = o["kind"].as_str().unwrap_or("");
            if !RECEIPT_KINDS.contains(&kind) {
                return accept_effective(json!({"render": "ignore"}));
            }
            let ok = if kind == "read" {
                o.get("through").is_some() && o.get("targets").is_none()
            } else {
                o.get("targets").is_some() && o.get("through").is_none()
            };
            if ok {
                accept_effective(json!({"receipt": kind}))
            } else {
                reject("receipt-shape", None)
            }
        }
        "activity" => {
            let a = o["activity"].as_str().unwrap_or("");
            accept_effective(json!({"activity": if ACTIVITIES.contains(&a) { a } else { "active" }}))
        }
        _ => accept(),
    }
}

fn kind_body(kind: &str) -> &'static [&'static str] {
    match kind {
        "text" => &["text"],
        "audio" | "video" => &["blob", "duration_ms"],
        "image" => &["blob"],
        "file" => &["blob", "name"],
        "contact" => &["did"],
        _ => &["lat_e7", "lon_e7"],
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Bool(b)) => *b,
        Some(_) => true,
    }
}

fn check_content(o: &Value) -> Value {
    let kind = o["kind"].as_str().unwrap_or("");
    let purpose = o["purpose"].as_str().unwrap_or("");
    let eff_kind = if CONTENT_KINDS.contains(&kind) {
        if kind_body(kind).iter().any(|f| o.get(f).is_none()) {
            return reject("content-body", None);
        }
        kind
    } else if o.get("blob").is_some() {
        "file" // M§8.2: unknown kind with a blob is offered as a file
    } else {
        "unsupported"
    };
    if purpose == "reaction" {
        let text_len = o["text"].as_str().map(str::len).unwrap_or(0);
        if kind != "text" || !truthy(o.get("reply_to")) || text_len > REACTION_MAX_BYTES {
            return reject("reaction-invalid", None);
        }
    }
    if purpose == "voicemail" && (!matches!(kind, "audio" | "video") || o.get("session").is_none()) {
        return reject("content-body", None); // M§13.2
    }
    let eff_purpose = if CONTENT_PURPOSES.contains(&purpose) { purpose } else { "message" };
    accept_effective(json!({"kind": eff_kind, "purpose": eff_purpose}))
}

/// Schema plus kind fallback for the `dsip_conversation` GroupContext extension.
///
/// Spec: M§6.3 — an unknown conversation kind is handled as `group`.
pub fn check_conversation_ext(ext: &Value) -> Value {
    if !schema_ok("dsip-conversation", ext) {
        return reject("schema-invalid", None);
    }
    let k = ext["kind"].as_str().unwrap_or("");
    accept_effective(json!({"kind": if CONVERSATION_KINDS.contains(&k) { k } else { "group" }}))
}
