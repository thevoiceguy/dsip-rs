//! §18.1 trust rendering: turn a verified identity and its claims into the *basis* a client
//! shows a human — never a generic "verified" badge.
//!
//! Spec: §18.1 (display the verification basis, not a badge; explain it to the user), §18.2
//! (display names, and by extension all claims, are claims not truth), §6.3 / Gateway Profile
//! G§7 (a `gateway.downgraded` crossing names what was lost), Gateway Profile G§5 (a PSTN caller
//! is a `tel` claim whose basis is "Gateway attested by …").
//!
//! Pure and vector-pinned (`impl/vectors/trust/`): the CLI, the browser (via `dsip-wasm`), and the
//! gateway all render through these functions so the basis a callee sees is one string, defined
//! once. The gateway's `tel_claim` builds the claim and calls [`tel_basis`] for its `trust_basis`.

use serde_json::Value;

/// The §18.1 verification basis for an identity that verified as `identity_did` and carries
/// `claims`. Most-specific first: a gateway-attested PSTN caller (a `tel` claim) names the
/// gateway; otherwise the basis is the identity's own DID method.
pub fn verification_basis(identity_did: &str, claims: &[Value]) -> String {
    if let Some(tel) = claims.iter().find(|c| c.get("type").and_then(Value::as_str) == Some("tel")) {
        if let Some(b) = tel_basis(tel) {
            return b;
        }
    }
    if let Some(rest) = identity_did.strip_prefix("did:web:") {
        format!("Domain verified (did:web:{rest})")
    } else if identity_did.starts_with("did:key:") {
        "Self-issued identity".to_string()
    } else {
        "Unrecognized identity method".to_string()
    }
}

/// The gateway-attested basis line from a `tel` claim (G§5), or `None` if the claim is not a
/// well-formed `tel` claim. Matches the string the gateway records in `trust_basis`.
pub fn tel_basis(claim: &Value) -> Option<String> {
    if claim.get("type").and_then(Value::as_str) != Some("tel") {
        return None;
    }
    let verifier = claim.get("verifier").and_then(Value::as_str)?;
    let host = verifier.strip_prefix("did:web:").unwrap_or(verifier);
    let attestation = claim.get("attestation").and_then(Value::as_str).unwrap_or("none");
    let verified = claim.get("verified").and_then(Value::as_bool).unwrap_or(false) && attestation != "none";
    Some(if verified {
        format!("Gateway attested by {host} · STIR attestation {attestation} (verified)")
    } else if attestation != "none" {
        format!("Gateway attested by {host} · STIR attestation {attestation} (unverified)")
    } else {
        format!("Gateway attested by {host} · no attestation")
    })
}

/// The `tel` claim's headline for a call surface: `PSTN caller <number>[ · <cnam>]`.
pub fn tel_caller_line(claim: &Value) -> Option<String> {
    if claim.get("type").and_then(Value::as_str) != Some("tel") {
        return None;
    }
    let number = claim.get("number").and_then(Value::as_str)?;
    Some(match claim.get("cnam").and_then(Value::as_str) {
        Some(cnam) => format!("PSTN caller {number} · {cnam}"),
        None => format!("PSTN caller {number}"),
    })
}

/// A human phrase for one named `gateway.downgraded` loss (§6.3 / G§7).
pub fn downgrade_phrase(loss: &str) -> &'static str {
    match loss {
        "no-srtp-on-trunk" => "media is not encrypted on the PSTN trunk",
        "identity-not-assertable" => "your identity could not be asserted into the PSTN",
        "no-attestation" => "the caller carried no verified attestation",
        "policy-unenforceable" => "your media policy cannot be enforced past the gateway",
        _ => "an unspecified guarantee was lost",
    }
}

/// A human summary of a `gateway.downgraded` error's losses (§6.3 / G§7).
pub fn downgrade_summary(losses: &[&str]) -> String {
    if losses.is_empty() {
        return "Trust downgraded crossing the gateway (§6.3)".to_string();
    }
    let phrases: Vec<&str> = losses.iter().map(|l| downgrade_phrase(l)).collect();
    format!("Trust downgraded crossing the gateway (§6.3): {}", phrases.join("; "))
}

/// Vector runner entry (`kind: trust`): dispatch on `input.check`.
pub fn run_vector(v: &Value) -> Value {
    let inp = &v["input"];
    match inp.get("check").and_then(Value::as_str).unwrap_or("") {
        "basis" => {
            let claims: Vec<Value> = inp["claims"].as_array().cloned().unwrap_or_default();
            Value::String(verification_basis(inp["identity"].as_str().unwrap_or(""), &claims))
        }
        "tel-caller" => match tel_caller_line(&inp["claim"]) {
            Some(s) => Value::String(s),
            None => Value::Null,
        },
        "downgrade" => {
            let losses: Vec<&str> = inp["losses"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            Value::String(downgrade_summary(&losses))
        }
        other => Value::String(format!("unknown trust check {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn basis_prefers_tel_then_method() {
        let tel = json!({"type": "tel", "number": "+15551234567", "attestation": "A", "verified": true, "verifier": "did:web:gw.example"});
        assert_eq!(verification_basis("did:web:gw.example", &[tel]), "Gateway attested by gw.example · STIR attestation A (verified)");
        assert_eq!(verification_basis("did:web:example.com:users:bob", &[]), "Domain verified (did:web:example.com:users:bob)");
        assert_eq!(verification_basis("did:key:z6Mk...", &[]), "Self-issued identity");
    }

    #[test]
    fn downgrade_names_losses() {
        assert_eq!(downgrade_summary(&["no-srtp-on-trunk", "no-attestation"]),
                   "Trust downgraded crossing the gateway (§6.3): media is not encrypted on the PSTN trunk; the caller carried no verified attestation");
    }
}
