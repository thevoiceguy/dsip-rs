//! `did:web` fetching and the resolver used by live endpoints.
//!
//! Spec: §7.2 (`did:web` for organizations, relays, services), §8.1 (the DID
//! document is authoritative; it is fetched from the DID's own domain over
//! HTTPS), §8.4 (honest treatment: this path depends on DNS and Web PKI).
//! Impl: native implementation of the did:web URL mapping; the `ssi` crate
//! named in the plan is not used — the mapping is ten lines and avoids API churn.

use crate::error::{file, Error, Result};
use dsip_core::did::{DidDocument, StaticResolver};

/// Map a `did:web` to its document URL.
///
/// `did:web:example.com` → `https://example.com/.well-known/did.json`;
/// `did:web:example.com:users:bob` → `https://example.com/users/bob/did.json`;
/// `%3A` in the host decodes to a port.
pub fn did_web_url(did: &str) -> Result<String> {
    let Some(rest) = did.strip_prefix("did:web:") else { return Err(Error::NotDidWeb(did.to_string())) };
    let mut parts = rest.split(':');
    let host = parts.next().filter(|h| !h.is_empty()).ok_or_else(|| Error::NotDidWeb(did.to_string()))?.replace("%3A", ":");
    let path: Vec<&str> = parts.collect();
    Ok(if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{host}/{}/did.json", path.join("/"))
    })
}

/// Fetch and parse a `did:web` document. Verifies that the document `id` matches the DID.
pub async fn fetch_did_web(did: &str) -> Result<DidDocument> {
    let url = did_web_url(did)?;
    let fetch = |source| Error::Fetch { url: url.clone(), source };
    let doc: DidDocument = reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(fetch)?
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(fetch)?
        .json()
        .await
        .map_err(fetch)?;
    if doc.id != did {
        return Err(Error::DocumentMismatch { did: did.to_string(), got: doc.id });
    }
    Ok(doc)
}

/// Build a static resolver from JSON document files plus optionally fetched `did:web` DIDs.
pub async fn build_resolver(files: &[std::path::PathBuf], fetch: &[String]) -> Result<StaticResolver> {
    let mut r = StaticResolver::default();
    for f in files {
        let v: serde_json::Value = serde_json::from_slice(&file(f, std::fs::read(f))?)?;
        if v.get("id").is_some() {
            r.insert(serde_json::from_value(v)?);
        } else {
            for (_, d) in v.as_object().into_iter().flatten() {
                r.insert(serde_json::from_value(d.clone())?);
            }
        }
    }
    for did in fetch.iter().filter(|d| d.starts_with("did:web:")) {
        r.insert(fetch_did_web(did).await?);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_mapping() {
        assert_eq!(did_web_url("did:web:example.com").unwrap(), "https://example.com/.well-known/did.json");
        assert_eq!(did_web_url("did:web:example.com:users:bob").unwrap(), "https://example.com/users/bob/did.json");
        assert_eq!(did_web_url("did:web:localhost%3A8443").unwrap(), "https://localhost:8443/.well-known/did.json");
    }
}
