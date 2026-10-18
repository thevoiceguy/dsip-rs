//! `did:web` fetching and the resolver used by live endpoints.
//!
//! Spec: §7.2 (`did:web` for organizations, relays, services), §8.1 (the DID
//! document is authoritative; it is fetched from the DID's own domain over
//! HTTPS), §8.4 (honest treatment: this path depends on DNS and Web PKI).
//! Impl: native implementation of the did:web URL mapping; the `ssi` crate
//! named in the plan is not used — the mapping is ten lines and avoids API churn.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dsip_core::did::{DidDocument, ResolveError, StaticResolver};

use crate::error::{file, Error, Result};

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
    let client = reqwest::Client::builder().https_only(true).build().map_err(|source| Error::Fetch { url: String::new(), source })?;
    fetch_with(&client, did).await
}

async fn fetch_with(client: &reqwest::Client, did: &str) -> Result<DidDocument> {
    let url = did_web_url(did)?;
    let fetch = |source| Error::Fetch { url: url.clone(), source };
    let doc: DidDocument = client
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

/// What [`DidResolver::resolve`] returns.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = std::result::Result<DidDocument, ResolveError>> + Send + 'a>>;

/// A resolver that may fetch, and so may fail: what a host runs when [`dsip_endpoint::CoreEvent::Resolve`] asks for
/// a document.
///
/// Spec: §8.1 — the DID document is authoritative and is obtained by the DID method; nothing may answer from a
/// cache, a DHT or a relay as if it were authoritative (a cache here only saves refetching what the method returned).
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to its document.
    fn resolve<'a>(&'a self, did: &'a str) -> ResolveFuture<'a>;
}

impl DidResolver for StaticResolver {
    fn resolve<'a>(&'a self, did: &'a str) -> ResolveFuture<'a> {
        let doc = dsip_core::did::Resolver::resolve(self, did);
        Box::pin(async move { doc.ok_or_else(|| ResolveError::NotFound(did.to_string())) })
    }
}

/// Fetches `did:web` documents over HTTPS and reuses each for [`DidWebResolver::ttl`].
///
/// Spec: §7.2 (`did:web`), §8.4 (it depends on DNS and Web PKI).
pub struct DidWebResolver {
    client: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<String, (DidDocument, Instant)>>,
}

impl DidWebResolver {
    /// Seconds a fetched document is reused before it is fetched again.
    pub const TTL_S: u64 = 300;
    /// Seconds a fetch may take.
    pub const TIMEOUT_S: u64 = 5;

    /// A resolver with the default lifetime and timeout.
    pub fn new() -> DidWebResolver {
        DidWebResolver::with(Duration::from_secs(Self::TTL_S), Duration::from_secs(Self::TIMEOUT_S))
    }

    /// A resolver reusing documents for `ttl` and giving each fetch `timeout`.
    pub fn with(ttl: Duration, timeout: Duration) -> DidWebResolver {
        // A client that cannot be built falls back to reqwest's default; https_only is then checked by did_web_url,
        // which only ever builds https URLs.
        let client = reqwest::Client::builder().https_only(true).timeout(timeout).build().unwrap_or_default();
        DidWebResolver { client, ttl, cache: Mutex::new(HashMap::new()) }
    }

    /// How long a fetched document is reused.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for DidWebResolver {
    fn default() -> DidWebResolver {
        DidWebResolver::new()
    }
}

impl DidResolver for DidWebResolver {
    fn resolve<'a>(&'a self, did: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            if !did.starts_with("did:web:") {
                return Err(ResolveError::Unsupported(did.to_string()));
            }
            let cached = self.cache.lock().ok().and_then(|c| c.get(did).filter(|(_, at)| at.elapsed() < self.ttl).map(|(d, _)| d.clone()));
            if let Some(doc) = cached {
                return Ok(doc);
            }
            let doc = fetch_with(&self.client, did).await.map_err(|e| match e {
                Error::DocumentMismatch { did, got } => ResolveError::Mismatch { did, got },
                Error::Fetch { source, .. } if source.is_decode() => ResolveError::Invalid { did: did.to_string(), detail: source.to_string() },
                other => ResolveError::Fetch { did: did.to_string(), detail: other.to_string() },
            })?;
            if let Ok(mut c) = self.cache.lock() {
                c.insert(did.to_string(), (doc.clone(), Instant::now()));
            }
            Ok(doc)
        })
    }
}

/// Ask the first resolver, then the second when the first has no document (or does not handle the method).
pub struct Chain(pub Arc<dyn DidResolver>, pub Arc<dyn DidResolver>);

impl DidResolver for Chain {
    fn resolve<'a>(&'a self, did: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            match self.0.resolve(did).await {
                Err(ResolveError::NotFound(_) | ResolveError::Unsupported(_)) => self.1.resolve(did).await,
                r => r,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_resolvers_chain_held_documents_before_fetching() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let key = dsip_core::keys::KeyPair::from_seed([7; 32]);
        let mut held = StaticResolver::default();
        held.insert(DidDocument::minimal_web("did:web:held.example", &key.public(), None));
        let web = DidWebResolver::new();
        rt.block_on(async {
            assert_eq!(DidResolver::resolve(&held, "did:web:held.example").await.unwrap().id, "did:web:held.example");
            assert!(matches!(DidResolver::resolve(&held, "did:web:other.example").await, Err(ResolveError::NotFound(_))));
            assert!(matches!(web.resolve(&key.did()).await, Err(ResolveError::Unsupported(_))));
            let chain = Chain(Arc::new(held), Arc::new(web));
            assert_eq!(chain.resolve("did:web:held.example").await.unwrap().id, "did:web:held.example");
            // Falls through to the fetcher, which refuses a did:key without touching the network.
            assert!(matches!(chain.resolve(&key.did()).await, Err(ResolveError::Unsupported(_))));
        });
    }

    #[test]
    fn url_mapping() {
        assert_eq!(did_web_url("did:web:example.com").unwrap(), "https://example.com/.well-known/did.json");
        assert_eq!(did_web_url("did:web:example.com:users:bob").unwrap(), "https://example.com/users/bob/did.json");
        assert_eq!(did_web_url("did:web:localhost%3A8443").unwrap(), "https://localhost:8443/.well-known/did.json");
    }
}
