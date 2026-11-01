//! The gateway over HTTPS: `POST` of one envelope at the `DSIPWake` endpoint's path, and the gateway's own `did:web`
//! document at the path its DID maps to, so that the DID resolves to the endpoint it serves.
//!
//! Spec: W§2 (the `DSIPWake` service entry), W§2.1 (`POST`, `application/dsip+json`, `200` with one signed envelope;
//! any other status is a transport failure), §7.2 (the `did:web` document at `/.well-known/did.json`, or at the DID's
//! path), §13.2 (TLS 1.3, as every DSIP endpoint).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::{Gateway, Reply};

/// The path a `did:web` DID's document is served at (§7.2): `/.well-known/did.json`, or `/<path>/did.json`.
pub fn document_path(did: &str) -> Option<String> {
    let url = dsip_transport::resolver::did_web_url(did).ok()?;
    let rest = url.strip_prefix("https://")?;
    rest.find('/').map(|i| rest[i..].to_string())
}

struct Shared {
    gateway: Arc<Gateway>,
    document: serde_json::Value,
}

/// The routes: `POST` at `endpoint`'s path, `GET` of the document at the DID's path.
pub fn router(gateway: Arc<Gateway>, endpoint: &str) -> Router {
    let wake_path = endpoint.strip_prefix("https://").and_then(|r| r.find('/').map(|i| r[i..].to_string())).unwrap_or_else(|| "/".into());
    let doc_path = document_path(gateway.did()).unwrap_or_else(|| "/.well-known/did.json".into());
    let document = serde_json::to_value(gateway.document(endpoint)).unwrap_or_default();
    let shared = Arc::new(Shared { gateway, document });
    Router::new().route(&wake_path, post(request)).route(&doc_path, get(document_route)).with_state(shared)
}

async fn request(State(s): State<Arc<Shared>>, body: Bytes) -> Response {
    let Ok(text) = std::str::from_utf8(&body) else { return (StatusCode::BAD_REQUEST, "not UTF-8").into_response() };
    match s.gateway.handle(text, dsip_transport::now_s()).await {
        Reply::Answer(frame) => ([(header::CONTENT_TYPE, "application/dsip+json")], frame).into_response(),
        Reply::Status(code, why) => (StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST), why).into_response(),
    }
}

async fn document_route(State(s): State<Arc<Shared>>) -> Response {
    ([(header::CONTENT_TYPE, "application/did+json")], s.document.to_string()).into_response()
}

/// TCP connections through TLS, each handshake on its own task so a slow one holds up no other.
struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<tokio::net::TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn new(tcp: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<TlsListener> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = tcp.accept().await else { continue };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!("{peer}: TLS handshake failed: {e}"),
                        Err(_) => tracing::debug!("{peer}: TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(TlsListener { rx, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(c) = self.rx.recv().await {
                return c;
            }
            // the accept task has ended; there will be no more connections
            std::future::pending::<()>().await;
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Serve `gateway` on `tcp` through `acceptor`, its endpoint being `endpoint`, for ever.
pub async fn serve(gateway: Arc<Gateway>, endpoint: &str, tcp: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<()> {
    let app = router(gateway, endpoint);
    axum::serve(TlsListener::new(tcp, acceptor)?, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_web_document_path() {
        assert_eq!(document_path("did:web:push.dsip.example").as_deref(), Some("/.well-known/did.json"));
        assert_eq!(document_path("did:web:localhost%3A8445").as_deref(), Some("/.well-known/did.json"));
        assert_eq!(document_path("did:web:example.com:push").as_deref(), Some("/push/did.json"));
    }
}
