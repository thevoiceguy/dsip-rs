//! JSON Schema (draft 2020-12) validation with native `type` dispatch.
//!
//! Spec: §10.3; §15.2 (the reason wire structure — `reason` required, `detail` ≤ 1024,
//! `retry_after` — is enforced here by the payload schemas). Impl: `message.schema.json`'s
//! `oneOf` dispatcher is not used;
//! dispatch is a match on `type`, which avoids cross-file `$ref` resolution
//! and yields the same result because every payload schema pins `type` with
//! `const`. Format assertions are off, matching the Python harness
//! (`jsonschema` validates `format` only with an explicit checker).

use std::collections::HashMap;
use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

use dsip_core::registry::MESSAGE_TYPES;
use dsip_core::{RejectCode, Verdict};

use crate::embedded::{BROADCAST_PROVENANCE, REACHABILITY_HINT, SCHEMAS};

/// Names of the embedded spec schemas.
pub const SCHEMA_NAMES: &[&str] = &[
    "invite", "progress", "answer", "reject", "cancel", "update", "info", "bye", "error", "hello", "introduction",
    "grant", "publish", "subscribe", "notify", "unpublish", "envelope", "message",
];

fn compiled() -> &'static HashMap<&'static str, Validator> {
    static CELL: OnceLock<HashMap<&'static str, Validator>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut m = HashMap::new();
        let extra = [("reachability-hint", REACHABILITY_HINT), ("broadcast-provenance", BROADCAST_PROVENANCE)];
        for (name, text) in SCHEMAS.iter().chain(extra.iter()) {
            if *name == "message" {
                continue; // relative $refs; dispatched natively instead
            }
            let schema: Value = serde_json::from_str(text).expect("embedded schema is JSON");
            let v = jsonschema::options()
                .should_validate_formats(false)
                .build(&schema)
                .unwrap_or_else(|e| panic!("schema {name} does not compile: {e}"));
            m.insert(*name, v);
        }
        m
    })
}

/// The compiled validator for a schema name, if embedded.
pub fn schema_for(name: &str) -> Option<&'static Validator> {
    compiled().get(name)
}

/// Validate `instance` against the named schema. Returns the first error message on failure.
pub fn validate_against(name: &str, instance: &Value) -> Result<(), String> {
    let v = schema_for(name).ok_or_else(|| format!("no schema named {name}"))?;
    match v.iter_errors(instance).next() {
        None => Ok(()),
        Some(e) => Err(format!("{} at {}", e, e.instance_path())),
    }
}

/// Implementation-local payload types (not in the §12.1 message set) and their schemas.
pub const LOCAL_TYPES: &[(&str, &str)] = &[("reachability-hint", "reachability-hint"), ("broadcast.provenance", "broadcast-provenance")];

/// Stage 13: dispatch on `type` and validate. `unknown-type` for types outside the message set
/// (and the implementation-local extension types listed in [`LOCAL_TYPES`]).
pub fn validate(payload: &Value) -> Verdict {
    let Some(t) = payload.get("type").and_then(Value::as_str) else { return Verdict::reject(RejectCode::UnknownType) };
    let schema = if MESSAGE_TYPES.contains(&t) {
        t
    } else if let Some((_, s)) = LOCAL_TYPES.iter().find(|(lt, _)| *lt == t) {
        s
    } else {
        return Verdict::reject(RejectCode::UnknownType);
    };
    match validate_against(schema, payload) {
        Ok(()) => Verdict::accept(),
        Err(e) => Verdict::reject(RejectCode::SchemaInvalid).detail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_schemas_compile_and_dispatch() {
        for n in SCHEMA_NAMES.iter().filter(|n| **n != "message") {
            assert!(schema_for(n).is_some(), "{n}");
        }
        assert!(schema_for("reachability-hint").is_some());
        assert_eq!(validate(&serde_json::json!({"type": "transfer"})).code, Some(RejectCode::UnknownType));
        assert_eq!(validate(&serde_json::json!({"type": "bye"})).code, Some(RejectCode::SchemaInvalid));
    }
}
