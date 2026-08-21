//! Receiver-side verification: the publication record, provenance statements, variant selection.
//!
//! Spec: §22.1 (record shape; variant order is the publisher's preference), §22.2
//! (integrity mode: the record declares it, a selected variant may override, unknown
//! tokens fall back to `metadata-only`, a verified transcode statement makes the delivered
//! stream `derivative-bound`), §22.3 (a statement references the original publication and
//! is signed by its processor), §8.1 (the publisher is whoever the signature
//! verifies as), §16.4 (policy violations are surfaced, not silently enforced).

use serde_json::{json, Map, Value};

use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::version::check_version;
use dsip_core::{RejectCode, Verdict};
use dsip_schema::{check_payload, validate_against, SemanticContext};

/// Impl (spec-gap 18): a stream_id is the publisher DID or a colon-suffixed extension of it.
pub fn stream_in_namespace(stream_id: &str, publisher: &str) -> bool {
    stream_id == publisher || stream_id.starts_with(&format!("{publisher}:"))
}

/// Pick the first advertised variant whose codec and transport the receiver supports.
pub fn select_variant(variants: &[Value], codecs: &[String], transports: &[String]) -> Option<String> {
    variants
        .iter()
        .find(|v| {
            v["codec"].as_str().is_some_and(|c| codecs.iter().any(|x| x == c))
                && v["transport"].as_str().is_some_and(|t| transports.iter().any(|x| x == t))
        })
        .and_then(|v| v["id"].as_str().map(String::from))
}

/// §22.3 checks for one statement (already envelope-verified as `stmt_identity`) against the publication it references.
pub fn evaluate_provenance(stmt: &Value, stmt_identity: &str, publication: &Value) -> Value {
    let s = |k: &str| stmt.get(k).and_then(Value::as_str);
    if s("original_publication") != publication["id"].as_str() {
        return json!({"verdict": "reject", "code": "provenance-unknown-publication"});
    }
    if s("original_stream") != publication["stream_id"].as_str() {
        return json!({"verdict": "reject", "code": "provenance-stream-mismatch"});
    }
    if s("processor") != Some(stmt_identity) {
        return json!({"verdict": "reject", "code": "provenance-processor-mismatch"});
    }
    let known_variant = publication["variants"].as_array().is_some_and(|vs| vs.iter().any(|v| v["id"].as_str() == s("input_variant")));
    if !known_variant {
        return json!({"verdict": "reject", "code": "provenance-variant-unknown"});
    }
    let mut out = json!({"verdict": "accept", "processor": s("processor"), "operation": s("operation"), "integrity_mode": "derivative-bound"});
    let pol = &publication["policy"];
    if s("operation") == Some("transcode") && matches!(pol["transcoding"].as_str(), Some("forbidden" | "denied")) {
        out["policy_violation"] = "transcoding".into();
    }
    if pol["redistribution"].as_str() == Some("forbidden") {
        out["policy_violation"] = "redistribution".into();
    }
    out
}

/// A verified publication plus what the receiver derived from it.
#[derive(Debug, Clone)]
pub struct Receiver {
    /// The decoded record.
    pub publication: Value,
    /// Publisher DID (the verified identity).
    pub publisher: String,
    /// Chosen variant id, if any.
    pub selected_variant: Option<String>,
    /// Per-statement results (accept with processor/operation, or reject with code).
    pub provenance: Vec<Value>,
    /// Processors with non-transcode operations.
    pub delivered_by: Vec<String>,
    /// Processors that transcoded.
    pub transcoded_by: Vec<String>,
    /// Integrity mode the record (or the selected variant) declares, after registry fallback (§22.2).
    pub declared_integrity: &'static str,
}

impl Receiver {
    /// Integrity mode to display: `derivative-bound` when any accepted transcode statement
    /// exists, else what the record declares (§22.2, v0.7).
    pub fn integrity_mode(&self) -> &'static str {
        if self.transcoded_by.is_empty() { self.declared_integrity } else { "derivative-bound" }
    }

    /// The vector `expect` projection.
    pub fn to_expect(&self, signer: &str) -> Value {
        json!({
            "verdict": "accept", "type": "publish", "signer": signer, "identity": self.publisher,
            "selected_variant": self.selected_variant,
            "provenance": self.provenance,
            "display": {"original_publisher": self.publisher, "delivered_by": self.delivered_by,
                        "transcoded_by": self.transcoded_by, "integrity_mode": self.integrity_mode()},
        })
    }
}

/// Verify a publication envelope and its provenance statements; select a variant.
///
/// Returns the signer DID with the receiver view, or the rejecting verdict.
pub fn evaluate_publication(
    publication: &Envelope,
    provenance: &[Envelope],
    codecs: &[String],
    transports: &[String],
    ctx: &Context,
    sem: &SemanticContext,
) -> Result<(String, Receiver), Verdict> {
    let ver = envelope::verify(publication, ctx, None)?;
    let p = ver.payload.clone();
    if p["publisher"].as_str() != Some(ver.identity.as_str()) {
        return Err(Verdict::reject(RejectCode::PublisherMismatch));
    }
    if !stream_in_namespace(p["stream_id"].as_str().unwrap_or(""), &ver.identity) {
        return Err(Verdict::reject(RejectCode::StreamIdNamespace));
    }
    let pv = check_payload(&p, sem);
    if !pv.ok() {
        return Err(pv);
    }
    let mut results = vec![];
    let (mut delivered, mut transcoded) = (vec![], vec![]);
    for env in provenance {
        let r = match envelope::verify(env, ctx, None) {
            Err(v) => v.to_expect(),
            Ok(pver) => {
                let sp = &pver.payload;
                let vv = check_version(sp, &sem.supported);
                if !vv.ok() {
                    vv.to_expect()
                } else if validate_against("provenance", sp).is_err() {
                    json!({"verdict": "reject", "code": "schema-invalid"})
                } else {
                    evaluate_provenance(sp, &pver.identity, &p)
                }
            }
        };
        if r["verdict"] == "accept" {
            let proc_ = r["processor"].as_str().unwrap_or("").to_string();
            if r["operation"] == "transcode" { transcoded.push(proc_) } else { delivered.push(proc_) }
        }
        results.push(r);
    }
    let empty: Vec<Value> = vec![];
    let selected = select_variant(p["variants"].as_array().unwrap_or(&empty), codecs, transports);
    let mut declared = dsip_core::registry::effective_integrity(p["integrity"].as_str());
    if let Some(v) = p["variants"].as_array().and_then(|vs| vs.iter().find(|v| v["id"].as_str() == selected.as_deref())) {
        if let Some(m) = v["integrity"].as_str() {
            declared = dsip_core::registry::effective_integrity(Some(m)); // variant override (§22.2)
        }
    }
    Ok((
        ver.signer_did.clone(),
        Receiver {
            publisher: ver.identity.clone(),
            publication: p,
            selected_variant: selected,
            provenance: results,
            delivered_by: delivered,
            transcoded_by: transcoded,
            declared_integrity: declared,
        },
    ))
}

/// Helper for hosts: list of `(k, v)` pairs from a JSON object.
pub fn pairs(v: &Value) -> Vec<(String, Value)> {
    v.as_object().map(|m: &Map<String, Value>| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
}
