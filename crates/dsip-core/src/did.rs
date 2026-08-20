//! DID syntax, `did:key` (native), DID documents, and the resolver trait.
//!
//! Spec: §7.2 (DID usage: `did:key` and `did:web`), §8.1 (the DID document is
//! authoritative for keys and endpoints), §13.2 (endpoint advertisement).
//!
//! Impl: `did:key` is implemented outright (multicodec `ed25519-pub` 0xed01,
//! base58btc). `did:web` resolution is behind [`Resolver`]; the core crate
//! ships only [`StaticResolver`] (a document map, which is what the vector
//! suite supplies). Network fetching lives in `dsip-transport`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Is this string syntactically a DID (`did:method:method-specific-id`)?
///
/// Mirrors the schema `did` pattern: `^did:[a-z0-9]+:[A-Za-z0-9.%_:-]+$`.
pub fn is_did(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:") else { return false };
    let Some((method, id)) = rest.split_once(':') else { return false };
    !method.is_empty()
        && method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b".%_:-".contains(&b))
}

/// Split a DID URL `did#fragment` into (did, fragment). `None` unless both halves are valid and non-empty.
///
/// Spec: §10.2 — `kid` MUST be a DID URL identifying the verification method.
pub fn split_did_url(kid: &str) -> Option<(&str, &str)> {
    let (did, frag) = kid.split_once('#')?;
    if is_did(did) && !frag.is_empty() {
        Some((did, frag))
    } else {
        None
    }
}

/// Multibase (base58btc, `z` prefix) of multicodec ed25519-pub || key.
pub fn multibase_ed25519(public: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(34);
    raw.extend_from_slice(&ED25519_PUB_MULTICODEC);
    raw.extend_from_slice(public);
    format!("z{}", bs58::encode(raw).into_string())
}

/// Decode a `z…` multibase string to an Ed25519 public key, if it is one.
pub fn ed25519_from_multibase(mb: &str) -> Option<[u8; 32]> {
    let rest = mb.strip_prefix('z')?;
    let raw = bs58::decode(rest).into_vec().ok()?;
    if raw.len() != 34 || raw[..2] != ED25519_PUB_MULTICODEC {
        return None;
    }
    raw[2..].try_into().ok()
}

/// `did:key` for an Ed25519 public key.
///
/// Spec: §7.2.
pub fn did_key_from_public(public: &[u8; 32]) -> String {
    format!("did:key:{}", multibase_ed25519(public))
}

/// The canonical verification-method DID URL of a `did:key`: `did:key:z…#z…`.
pub fn did_key_kid(public: &[u8; 32]) -> String {
    let mb = multibase_ed25519(public);
    format!("did:key:{mb}#{mb}")
}

/// Public key embedded in an Ed25519 `did:key`.
pub fn public_from_did_key(did: &str) -> Option<[u8; 32]> {
    ed25519_from_multibase(did.strip_prefix("did:key:")?)
}

/// A verification method entry of a DID document (Multikey form).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// Absolute (`did#frag`) or relative (`#frag`) id.
    pub id: String,
    /// e.g. `Multikey`, `Ed25519VerificationKey2020`.
    #[serde(rename = "type")]
    pub vm_type: String,
    /// Controller DID; MUST equal the document id when present.
    #[serde(default)]
    pub controller: Option<String>,
    /// Multibase public key.
    #[serde(rename = "publicKeyMultibase", default)]
    pub public_key_multibase: Option<String>,
}

/// A DSIP signaling service entry.
///
/// Spec: §13.2 endpoint advertisement — `type: DSIPSignaling`, `serviceEndpoint.uri` (wss), `bindings`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// Service id.
    pub id: String,
    /// Service type.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Endpoint object (or string for non-DSIP services).
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: Value,
}

/// The subset of a DID document DSIP reads.
///
/// Spec: §8.1 rule 4 — authoritative for verification keys and DSIP service endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DidDocument {
    /// The DID.
    pub id: String,
    /// Verification methods.
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    /// Services.
    #[serde(default)]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// Resolve a fragment to an Ed25519 key within this document.
    pub fn ed25519_key(&self, kid: &str, frag: &str) -> Option<[u8; 32]> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.id == kid || vm.id == format!("#{frag}"))?;
        if let Some(c) = &vm.controller {
            if c != &self.id {
                return None;
            }
        }
        ed25519_from_multibase(vm.public_key_multibase.as_deref()?)
    }

    /// First `DSIPSignaling` service endpoint `uri` advertising `ws/1.0`, if any.
    ///
    /// Spec: §13.2 — the URI scheme MUST be `wss`.
    pub fn signaling_uri(&self) -> Option<String> {
        self.service.iter().filter(|s| s.service_type == "DSIPSignaling").find_map(|s| {
            let uri = s.service_endpoint.get("uri")?.as_str()?;
            let bindings = s.service_endpoint.get("bindings")?.as_array()?;
            if uri.starts_with("wss://") && bindings.iter().any(|b| b == "ws/1.0") {
                Some(uri.to_string())
            } else {
                None
            }
        })
    }

    /// Build a minimal document for a `did:web` identity with one Ed25519 key and a signaling endpoint.
    pub fn minimal_web(did: &str, public: &[u8; 32], signaling_uri: Option<&str>) -> DidDocument {
        DidDocument {
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                vm_type: "Multikey".into(),
                controller: Some(did.to_string()),
                public_key_multibase: Some(multibase_ed25519(public)),
            }],
            service: signaling_uri
                .map(|u| {
                    vec![Service {
                        id: format!("{did}#dsip-signaling"),
                        service_type: "DSIPSignaling".into(),
                        service_endpoint: serde_json::json!({"uri": u, "bindings": ["ws/1.0"]}),
                    }]
                })
                .unwrap_or_default(),
        }
    }
}

/// DID resolution.
///
/// Spec: §8.1 — step 2: if the input is a DID, resolve it using the DID method;
/// the DID document is authoritative. Implementations of this trait MUST NOT
/// consult caches, DHTs, or relays as if they were authoritative.
pub trait Resolver {
    /// Resolve a DID to its document. `did:key` needs no backend and is handled by [`resolve_kid`].
    fn resolve(&self, did: &str) -> Option<DidDocument>;
}

/// A resolver over a fixed document map (test vectors, local fixtures).
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    docs: HashMap<String, DidDocument>,
}

impl StaticResolver {
    /// Build from a `{did: document}` JSON map (the vector `context.did_documents` shape).
    pub fn from_json_map(map: &Value) -> StaticResolver {
        let mut docs = HashMap::new();
        if let Some(obj) = map.as_object() {
            for (did, doc) in obj {
                if let Ok(d) = serde_json::from_value::<DidDocument>(doc.clone()) {
                    docs.insert(did.clone(), d);
                }
            }
        }
        StaticResolver { docs }
    }

    /// Insert a document.
    pub fn insert(&mut self, doc: DidDocument) {
        self.docs.insert(doc.id.clone(), doc);
    }
}

impl Resolver for StaticResolver {
    fn resolve(&self, did: &str) -> Option<DidDocument> {
        self.docs.get(did).cloned()
    }
}

/// Resolve a `kid` DID URL to an Ed25519 public key.
///
/// Spec: §10.2 — verifiers resolve `kid` through the DID document. For
/// `did:key` the document is implicit and the fragment MUST name the key itself.
pub fn resolve_kid(kid: &str, resolver: &dyn Resolver) -> Option<[u8; 32]> {
    let (did, frag) = split_did_url(kid)?;
    if let Some(mb) = did.strip_prefix("did:key:") {
        if frag != mb {
            return None;
        }
        return ed25519_from_multibase(mb);
    }
    resolver.resolve(did)?.ed25519_key(kid, frag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_round_trip() {
        let pk = [7u8; 32];
        let did = did_key_from_public(&pk);
        assert!(did.starts_with("did:key:z6Mk"));
        assert_eq!(public_from_did_key(&did), Some(pk));
        assert!(is_did(&did));
        assert!(!is_did("not-a-did"));
        assert_eq!(split_did_url(&did_key_kid(&pk)).map(|(d, _)| d), Some(did.as_str()));
    }
}
