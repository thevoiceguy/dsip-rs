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
    timeout: Duration,
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
        DidWebResolver { client, ttl, timeout, cache: Mutex::new(HashMap::new()) }
    }

    /// This resolver, also trusting the certificates in `pem` (one or more PEM certificates): for document hosts
    /// under a private CA, or a test's self-signed one. The public web PKI roots stay trusted.
    pub fn with_ca(mut self, pem: &[u8]) -> Result<DidWebResolver> {
        let bad = |source| Error::Fetch { url: String::new(), source };
        let mut builder = reqwest::Client::builder().https_only(true).timeout(self.timeout);
        for cert in reqwest::Certificate::from_pem_bundle(pem).map_err(bad)? {
            builder = builder.add_root_certificate(cert);
        }
        self.client = builder.build().map_err(bad)?;
        Ok(self)
    }

    /// How long a fetched document is reused.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The document fetched for `did`, while it is within [`DidWebResolver::ttl`]; never fetches.
    pub fn cached(&self, did: &str) -> Option<DidDocument> {
        let c = self.cache.lock().ok()?;
        c.get(did).filter(|(_, at)| at.elapsed() < self.ttl).map(|(d, _)| d.clone())
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
            if let Some(doc) = self.cached(did) {
                return Ok(doc);
            }
            let doc = fetch_with(&self.client, did).await.map_err(|e| match e {
                Error::DocumentMismatch { did, got } => ResolveError::Mismatch { did, got },
                Error::Fetch { source, .. } if source.is_decode() => ResolveError::Invalid { did: did.to_string(), detail: source.to_string() },
                other => ResolveError::Fetch { did: did.to_string(), detail: other.to_string() },
            })?;
            if let Ok(mut c) = self.cache.lock() {
                if c.len() >= CACHE_MAX {
                    c.retain(|_, (_, at)| at.elapsed() < self.ttl);
                }
                c.insert(did.to_string(), (doc.clone(), Instant::now()));
            }
            Ok(doc)
        })
    }
}

/// Entries a cache keeps before expired ones are dropped.
const CACHE_MAX: usize = 4096;

/// The `did:web` documents a service fetches for the frames it verifies. A service's verification is synchronous
/// (the envelope pipeline takes a [`dsip_core::did::Resolver`]), so documents are fetched first: [`WebDocuments::missing`]
/// names the ones a frame needs, [`WebDocuments::fetch`] fetches them, and [`Over`] verifies with the service's own
/// documents and then these.
///
/// Spec: §8.1 — the fetched document is authoritative; it is reused only for the resolver's TTL, and a frame naming a
/// DID whose document cannot be fetched fails verification (`kid-unresolvable`), never falls back to a hint. §8.4 —
/// a fetch depends on DNS and Web PKI.
/// Impl: frames are unauthenticated until verified, so a fetch is a cost any sender can impose: a DID that failed is
/// not fetched again for [`WebDocuments::RETRY_S`], at most [`WebDocuments::PER_FRAME`] DIDs are fetched per frame
/// and at most [`WebDocuments::CONCURRENT`] at once; beyond that the frame is verified without them.
pub struct WebDocuments {
    web: DidWebResolver,
    failed: Mutex<HashMap<String, Instant>>,
    slots: tokio::sync::Semaphore,
}

impl WebDocuments {
    /// Seconds before a DID whose fetch failed is fetched again.
    pub const RETRY_S: u64 = 60;
    /// DIDs fetched for one frame: its signer and its delegations' issuers.
    pub const PER_FRAME: usize = 4;
    /// Fetches in flight at once, across all frames.
    pub const CONCURRENT: usize = 16;

    /// Documents fetched by `web`.
    pub fn new(web: DidWebResolver) -> WebDocuments {
        WebDocuments { web, failed: Mutex::new(HashMap::new()), slots: tokio::sync::Semaphore::new(Self::CONCURRENT) }
    }

    /// The `did:web` DIDs `frame` needs documents for that neither `held` nor this has, less those that failed
    /// within [`WebDocuments::RETRY_S`]. Empty when the frame does not parse.
    pub fn missing(&self, frame: &str, held: &dyn dsip_core::did::Resolver) -> Vec<String> {
        let mut dids = dsip_core::did::missing_web_dids(frame, &Over(held, Some(self)));
        dids.retain(|d| !self.recently_failed(d));
        dids.truncate(Self::PER_FRAME);
        dids
    }

    /// Whether `did` needs fetching for `held`: a `did:web` neither has, that has not failed recently.
    pub fn needs(&self, did: &str, held: &dyn dsip_core::did::Resolver) -> bool {
        did.starts_with("did:web:") && dsip_core::did::Resolver::resolve(&Over(held, Some(self)), did).is_none() && !self.recently_failed(did)
    }

    /// Fetch `dids`, concurrently. A failure is logged and remembered; the frame that needed it then fails
    /// verification.
    pub async fn fetch(&self, dids: &[String]) {
        let one = |did: String| async move {
            let Ok(_slot) = self.slots.try_acquire() else {
                tracing::info!("did:web {did}: not fetched, {} fetches in flight", Self::CONCURRENT);
                return;
            };
            match self.web.resolve(&did).await {
                Ok(_) => {
                    tracing::info!("did:web {did}: document fetched");
                    if let Ok(mut f) = self.failed.lock() {
                        f.remove(&did);
                    }
                }
                Err(e) => {
                    tracing::info!("did:web {did}: {e}");
                    if let Ok(mut f) = self.failed.lock() {
                        if f.len() >= CACHE_MAX {
                            f.retain(|_, at| at.elapsed() < Duration::from_secs(Self::RETRY_S));
                        }
                        f.insert(did, Instant::now());
                    }
                }
            }
        };
        futures_util::future::join_all(dids.iter().cloned().map(one)).await;
    }

    /// The document of `did` this holds, if fetched within the TTL.
    pub fn held(&self, did: &str) -> Option<DidDocument> {
        self.web.cached(did)
    }

    fn recently_failed(&self, did: &str) -> bool {
        self.failed.lock().is_ok_and(|f| f.get(did).is_some_and(|at| at.elapsed() < Duration::from_secs(Self::RETRY_S)))
    }
}

/// What a service binary's `did:web` flags build: `None` when fetching is off, else documents fetched with a
/// `ttl_s` lifetime, trusting `ca` (PEM) besides the public web PKI.
pub fn web_documents(fetch: bool, ttl_s: u64, ca: Option<&std::path::Path>) -> Result<Option<Arc<WebDocuments>>> {
    if !fetch {
        tracing::info!("did:web: document files only (fetching off)");
        return Ok(None);
    }
    let mut web = DidWebResolver::with(Duration::from_secs(ttl_s), Duration::from_secs(DidWebResolver::TIMEOUT_S));
    if let Some(ca) = ca {
        web = web.with_ca(&file(ca, std::fs::read(ca))?)?;
    }
    tracing::info!("did:web: documents fetched over HTTPS, reused for {ttl_s} s");
    Ok(Some(Arc::new(WebDocuments::new(web))))
}

impl std::fmt::Debug for WebDocuments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDocuments").field("ttl", &self.web.ttl()).finish_non_exhaustive()
    }
}

/// A service's own documents, then the `did:web` documents it has fetched: the synchronous resolver it verifies with.
///
/// Spec: §8.1 — the service's documents (its configured files) answer first, as overrides.
pub struct Over<'a>(pub &'a dyn dsip_core::did::Resolver, pub Option<&'a WebDocuments>);

impl dsip_core::did::Resolver for Over<'_> {
    fn resolve(&self, did: &str) -> Option<DidDocument> {
        self.0.resolve(did).or_else(|| self.1?.held(did))
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
    fn a_failed_fetch_is_not_retried_at_once() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let key = dsip_core::keys::KeyPair::from_seed([9; 32]);
        // Port 1 on loopback refuses at once: the fetch fails without waiting for the timeout.
        let did = "did:web:127.0.0.1%3A1";
        let frame = dsip_core::envelope::sign(&serde_json::json!({"type": "hello"}), &key, &format!("{did}#k1")).frame();
        let mut held = StaticResolver::default();
        let docs = WebDocuments::new(DidWebResolver::new());
        assert_eq!(docs.missing(&frame, &held), [did]);
        assert!(docs.needs(did, &held));
        rt.block_on(docs.fetch(&[did.to_string()]));
        assert!(docs.held(did).is_none());
        assert!(docs.missing(&frame, &held).is_empty(), "failed within RETRY_S");
        assert!(!docs.needs(did, &held));
        // A document the service holds answers first, and is never fetched.
        held.insert(DidDocument::minimal_web("did:web:held.example", &key.public(), None));
        assert!(!docs.needs("did:web:held.example", &held));
        assert!(dsip_core::did::Resolver::resolve(&Over(&held, Some(&docs)), "did:web:held.example").is_some());
    }

    #[test]
    fn url_mapping() {
        assert_eq!(did_web_url("did:web:example.com").unwrap(), "https://example.com/.well-known/did.json");
        assert_eq!(did_web_url("did:web:example.com:users:bob").unwrap(), "https://example.com/users/bob/did.json");
        assert_eq!(did_web_url("did:web:localhost%3A8443").unwrap(), "https://localhost:8443/.well-known/did.json");
    }
}
