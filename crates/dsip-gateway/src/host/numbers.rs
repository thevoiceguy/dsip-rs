//! The number-attestation side of the host (Number Attestation Profile draft, stage 4): the gateway's
//! relying-party configuration and the three decisions it makes per crossing, each a call into `dsip-number`.
//!
//! Spec: N§4.1 (an inbound PASSporT verified before the G§5 claim is rendered; a DSIP caller's bound number
//! asserted under the gateway's own certificate), N§6.1 (a dialled number routed by the operator's table, then by
//! a binding found on the hints tier), G§4.2 (`identity.unknown` when nothing routes). Impl: the lookup joins
//! every configured node's answer, as `dsip call --to tel:` does; `origid` is derived from the DSIP session id, so
//! a call's traceback handle is stable across retries of the same session.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use dsip_number::{Assertion, GatewayCert, PassportOutcome, Policy, Route};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// What the gateway holds for the number side: trust, its own certificate, its routes and the nodes it asks.
pub struct Numbers {
    /// The relying-party policy (N§3.2): trust list, `x5u` chains, SPC numbers, status policy.
    pub policy: Policy,
    /// The gateway's own STIR certificate, when it holds one (N§4.1).
    pub gateway: Option<GatewayCert>,
    /// The operator's table, `{number: did}` (N§6.1).
    pub configured: Value,
    /// `dsip-node`s to look numbers up on (N§6 route 1).
    pub nodes: Vec<String>,
    /// Resolved DID documents, by DID (for N§3.4 steps 6–7).
    pub documents: Map<String, Value>,
}

impl Numbers {
    /// Load the configuration: the policy file, the certificate (`x5u` plus a PKCS#8 PEM key file), `number=did`
    /// routes, nodes, and DID document files (one document, or a map of them).
    ///
    /// Spec: none (infrastructure).
    pub fn load(policy: Option<&Path>, x5u: Option<String>, key: Option<&Path>, routes: &[String], nodes: Vec<String>, documents: &[PathBuf]) -> Result<Numbers> {
        let read = |p: &Path| -> Result<Value> { Ok(serde_json::from_slice(&std::fs::read(p).with_context(|| p.display().to_string())?)?) };
        let policy = match policy {
            Some(p) => Policy::from_json(&read(p)?),
            None => Policy::default(),
        };
        let gateway = match (x5u, key) {
            (Some(x5u), Some(k)) => Some(GatewayCert { x5u, key_pem: std::fs::read_to_string(k).with_context(|| k.display().to_string())? }),
            (None, None) => None,
            _ => anyhow::bail!("--sti-x5u and --sti-key go together"),
        };
        let mut configured = Map::new();
        for r in routes {
            let (tn, did) = r.split_once('=').with_context(|| format!("--route {r}: number=did"))?;
            configured.insert(tn.to_string(), Value::String(did.to_string()));
        }
        let mut docs = Map::new();
        for f in documents {
            let v = read(f)?;
            let all: Vec<Value> = if v.get("id").is_some() { vec![v] } else { v.as_object().into_iter().flatten().map(|(_, d)| d.clone()).collect() };
            for d in all {
                if let Some(id) = d["id"].as_str() {
                    docs.insert(id.to_string(), d.clone());
                }
            }
        }
        Ok(Numbers { policy, gateway, configured: Value::Object(configured), nodes, documents: docs })
    }

    /// The facts behind the G§5 claim for an inbound INVITE: its `Identity` header verified (N§4.1, RFC 8224 §6.2).
    pub fn passport(&self, identity: Option<&str>, from_user: &str, to_user: &str, now: i64) -> PassportOutcome {
        dsip_number::verify_passport(identity, from_user, to_user, now, &self.policy)
    }

    /// Where an inbound call to `to_tn` goes (N§6.1): the table, then the nodes' bindings verified and chosen.
    pub async fn route(&self, to_tn: &str, now: i64) -> Route {
        if let Some(did) = self.configured.get(to_tn).and_then(Value::as_str) {
            return Route::Configured(did.to_string());
        }
        let mut bindings: Vec<Value> = vec![];
        if !self.nodes.is_empty() {
            if let Ok(http) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
                for n in &self.nodes {
                    let url = format!("{}/dsip/v1/tn/{}", n.trim_end_matches('/'), to_tn.replace('+', "%2B"));
                    if let Ok(r) = http.get(&url).send().await.and_then(|r| r.error_for_status()) {
                        let v: Value = r.json().await.unwrap_or_default();
                        for b in v["bindings"].as_array().cloned().unwrap_or_default() {
                            if !bindings.contains(&b) {
                                bindings.push(b);
                            }
                        }
                    }
                }
            }
        }
        dsip_number::route(to_tn, &self.configured, &bindings, &self.documents, now, &self.policy)
    }

    /// What to present toward the PSTN for a DSIP caller (N§4.1): the `From`, and a PASSporT when entitled.
    pub fn assert(&self, claims: &[Value], identity: &str, to_tn: &str, now: i64, origid: &str) -> Assertion {
        let doc = self.documents.get(identity).cloned().unwrap_or(Value::Null);
        dsip_number::assert_number(claims, identity, &doc, to_tn, now, origid, &self.policy, self.gateway.as_ref())
    }
}

/// A SIP user part as E.164: `+` and digits as given, or digits alone with a `+` put in front; `None` otherwise.
///
/// Spec: N§6.1 (the dialled number as the gateway canonicalized it); Impl: a trunk that strips the `+` is common.
pub fn e164(user: &str) -> Option<String> {
    let digits = user.strip_prefix('+').unwrap_or(user);
    let ok = (2..=15).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()) && !digits.starts_with('0');
    ok.then(|| format!("+{digits}"))
}

/// The call's SHAKEN `origid` (RFC 8588 §4): a UUID-shaped handle derived from the DSIP session id.
///
/// Spec: N§4.1 ("an `origid` the gateway makes per call"). Impl: version-4-shaped from SHA-256 of the session id.
pub fn origid_for(session: &str) -> String {
    let h = Sha256::digest(session.as_bytes());
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-4{}-8{}-{}", &hex[0..8], &hex[8..12], &hex[13..16], &hex[17..20], &hex[20..32])
}
