//! Wire-format payload rules enforced at parse.
//!
//! Spec: §10.3 — UTF-8, no floating point, integer timestamps. These are
//! enforced *before* any schema runs, on the decoded payload bytes, so a
//! payload that merely looks schema-valid after lossy parsing never gets that far.

use serde_json::Value;

use crate::did::is_did;
use crate::ulid::Ulid;
use crate::verdict::{RejectCode, Verdict};

/// Parse payload bytes into a JSON object under the §10.3 rules.
///
/// `core_shape` additionally requires the DSIP core fields (`dsip`, `type`, `id`,
/// `from`, `issued_at`, `expires_at`) with correct primitive types; it is off
/// for delegation credentials, whose payload is not a message.
pub fn parse_payload(raw: &[u8], core_shape: bool) -> Result<Value, Verdict> {
    let text = std::str::from_utf8(raw).map_err(|_| Verdict::reject(RejectCode::PayloadNotUtf8))?;
    let value: Value = serde_json::from_str(text).map_err(|_| Verdict::reject(RejectCode::PayloadNotJson))?;
    if !value.is_object() {
        return Err(Verdict::reject(RejectCode::PayloadNotJson));
    }
    if contains_float(&value) {
        return Err(Verdict::reject(RejectCode::PayloadFloat));
    }
    if core_shape {
        check_core_shape(&value)?;
    }
    Ok(value)
}

/// True if any number anywhere in the value is not an integer.
///
/// Spec: §10.3 "avoid floating point values". serde_json keeps `1.0` as a float,
/// so integral-looking floats are caught too — matching the Python harness.
pub fn contains_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => !(n.is_i64() || n.is_u64()),
        Value::Array(a) => a.iter().any(contains_float),
        Value::Object(o) => o.values().any(contains_float),
        _ => false,
    }
}

/// Core fields every DSIP payload must carry, typed, before schema validation.
pub fn check_core_shape(p: &Value) -> Result<(), Verdict> {
    let shape = |what: &str| Err(Verdict::reject(RejectCode::PayloadShape).detail(what.to_string()));
    if !p.get("dsip").is_some_and(Value::is_object) {
        return shape("dsip");
    }
    if !p.get("type").is_some_and(Value::is_string) {
        return shape("type");
    }
    if !p.get("id").and_then(Value::as_str).is_some_and(|s| Ulid::parse(s).is_some()) {
        return shape("id");
    }
    if !p.get("from").and_then(Value::as_str).is_some_and(is_did) {
        return shape("from");
    }
    let ts = |k: &str| p.get(k).and_then(Value::as_i64).filter(|t| *t >= 0);
    if ts("issued_at").is_none() || ts("expires_at").is_none() {
        return shape("timestamps");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_rejected_integers_kept() {
        assert!(contains_float(&serde_json::json!({"a": [1, {"b": 2.0}]})));
        assert!(!contains_float(&serde_json::json!({"a": [1, {"b": 2}]})));
        assert_eq!(parse_payload(b"[1]", true).unwrap_err().code, Some(RejectCode::PayloadNotJson));
        assert_eq!(parse_payload(b"\xff", true).unwrap_err().code, Some(RejectCode::PayloadNotUtf8));
    }
}
