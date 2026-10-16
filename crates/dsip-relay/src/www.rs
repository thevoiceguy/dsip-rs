//! Static file serving on the relay's TLS port, so the browser client and the
//! `wss` signaling share one origin and one certificate, plus what a deployed
//! client needs from its origin: the operator's defaults (`/config.json`),
//! short-lived TURN credentials (`/turn`) and the co-located hints node
//! (`/dsip/v1/*`, proxied), so a page served over `https` reaches a node that
//! itself speaks plain HTTP on the loopback.
//!
//! Spec: none (infrastructure). A connection's first bytes are peeked: an
//! HTTP `Upgrade: websocket` request is handed to the WebSocket acceptor with
//! the bytes replayed; any other request is answered here and closed. Impl:
//! ICE servers and node addresses reach the client from the origin that served
//! it, not from the protocol: `hello` capabilities are untouched (spec-gap 114).
//! TURN credentials follow the TURN REST API convention coturn implements
//! (`use-auth-secret`): username `<expiry>:<name>`, password
//! `base64(HMAC-SHA1(secret, username))`.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// TURN credential minting: the shared secret coturn holds as `static-auth-secret`.
pub struct Turn {
    /// `turn:` / `turns:` / `stun:` URIs handed to the client as one ICE server.
    pub uris: Vec<String>,
    /// The secret shared with the TURN server.
    pub secret: String,
    /// Credential lifetime in seconds.
    pub ttl_s: i64,
}

/// What the origin answers besides the WebSocket.
#[derive(Default)]
pub struct Routes {
    /// Static files (the client).
    pub www: Option<PathBuf>,
    /// `/config.json`: the operator's defaults for the client (relay, nodes, gateway, policy, ICE), as given.
    pub client_config: Option<Value>,
    /// `/turn`: short-lived TURN credentials.
    pub turn: Option<Turn>,
    /// `/dsip/v1/*` is forwarded to this hints node (`host:port`, plain HTTP).
    pub node_proxy: Option<String>,
}

impl Routes {
    /// Short-lived TURN credentials: `{"iceServers":[{urls, username, credential}], "ttl": s}`.
    pub fn turn_credentials(&self, now: i64) -> Option<Value> {
        let t = self.turn.as_ref()?;
        let username = format!("{}:dsip", now + t.ttl_s);
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(t.secret.as_bytes()).ok()?;
        mac.update(username.as_bytes());
        let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Some(json!({"iceServers": [{"urls": t.uris, "username": username, "credential": credential}], "ttl": t.ttl_s}))
    }
}

/// A stream with already-read bytes replayed before the inner stream.
pub struct Prefixed<S> {
    inner: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(out.remaining());
            let (pos, buf) = (self.pos, &self.buf);
            out.put_slice(&buf[pos..pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What the first request on a connection is.
pub enum First<S> {
    /// A WebSocket upgrade; hand this to the WS acceptor.
    WebSocket(Prefixed<S>),
    /// A plain HTTP request that was answered (static file or 404); the connection is done.
    Served,
}

/// Peek the request head and either wrap for WebSocket or answer the request here. `client` is the connection's
/// address, passed to the hints node as `X-Forwarded-For` on a proxied request.
pub async fn dispatch<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, routes: &Routes, client: std::net::IpAddr) -> std::io::Result<First<S>> {
    let mut head = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed before request head"));
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 16_384 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let is_ws = text.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("upgrade:") && l.contains("websocket")
    });
    if is_ws {
        return Ok(First::WebSocket(Prefixed { inner: stream, buf: head, pos: 0 }));
    }
    let target = text.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/");
    if path.starts_with("/dsip/v1/") {
        if let Some(upstream) = &routes.node_proxy {
            let r = proxy(&mut stream, upstream, &text, head, client).await;
            let _ = stream.shutdown().await;
            return r.map(|()| First::Served);
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (status, ctype, body): (&str, &str, Vec<u8>) = match path {
        "/config.json" => match &routes.client_config {
            Some(c) => ("200 OK", "application/json", c.to_string().into_bytes()),
            None => ("404 Not Found", "text/plain", b"no client config".to_vec()),
        },
        "/turn" => match routes.turn_credentials(now) {
            Some(c) => ("200 OK", "application/json", c.to_string().into_bytes()),
            None => ("404 Not Found", "text/plain", b"no turn".to_vec()),
        },
        _ => match routes.www.as_deref().and_then(|w| resolve(w, path)) {
            Some((p, ct)) => match std::fs::read(&p) {
                Ok(b) => ("200 OK", ct, b),
                Err(_) => ("404 Not Found", "text/plain", b"not found".to_vec()),
            },
            None => ("404 Not Found", "text/plain", b"not found".to_vec()),
        },
    };
    // a page served by another relay may ask this origin for credentials or defaults: answered to any origin, as a
    // node answers (profile §10); the files are the page itself and need no CORS
    let cors = if matches!(path, "/config.json" | "/turn") { "Access-Control-Allow-Origin: *\r\n" } else { "" };
    let hdr = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{cors}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(hdr.as_bytes()).await?;
    stream.write_all(&body).await?;
    let _ = stream.shutdown().await;
    Ok(First::Served)
}

/// The request head sent to the hints node: the client's request line and headers, with `Host` and `Connection` ours,
/// and `X-Forwarded-For` set to the connection's address — replacing any the client sent, so a client cannot name
/// someone else's address to the node's per-client limit (the node trusts the header only from loopback).
///
/// Spec: none (infrastructure).
fn upstream_head(head: &str, upstream: &str, client: std::net::IpAddr) -> String {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("GET / HTTP/1.1");
    let mut out = format!("{request_line}\r\nHost: {upstream}\r\nConnection: close\r\nX-Forwarded-For: {client}\r\n");
    for l in lines {
        let k = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if l.is_empty() || matches!(k.as_str(), "host" | "connection" | "keep-alive" | "upgrade" | "x-forwarded-for" | "forwarded") {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

/// Forward one request (head already read, body possibly partly read) to the hints node and copy its answer back.
///
/// Impl: HTTP/1.1 with `Connection: close` both ways, so neither side needs to parse past the headers: the node
/// answers one request and closes, and the client sees the answer end with the connection.
async fn proxy<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, upstream: &str, text: &str, head: Vec<u8>, client: std::net::IpAddr) -> std::io::Result<()> {
    let body_at = head.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(head.len());
    let content_length: usize = text
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
        .unwrap_or(0);
    let mut body = head[body_at..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; (content_length - body.len()).min(65_536)];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let out = upstream_head(&text[..text.len().min(String::from_utf8_lossy(&head[..body_at]).len())], upstream, client);
    let mut up = match tokio::net::TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("hints node unreachable: {e}");
            let hdr = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", msg.len());
            stream.write_all(hdr.as_bytes()).await?;
            return stream.write_all(msg.as_bytes()).await;
        }
    };
    up.write_all(out.as_bytes()).await?;
    up.write_all(&body).await?;
    let mut buf = [0u8; 16_384];
    loop {
        let n = up.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n]).await?;
    }
}

fn resolve(www: &Path, path: &str) -> Option<(PathBuf, &'static str)> {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.contains("..") {
        return None;
    }
    let full = www.join(rel);
    let ct = match full.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    };
    Some((full, ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_sees_the_connections_address_never_the_clients_claim() {
        let head = "POST /dsip/v1/hints HTTP/1.1\r\nHost: relay.example\r\nX-Forwarded-For: 203.0.113.9\r\nForwarded: for=203.0.113.9\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n";
        let out = upstream_head(head, "127.0.0.1:8090", "192.0.2.1".parse().unwrap());
        assert!(out.starts_with("POST /dsip/v1/hints HTTP/1.1\r\nHost: 127.0.0.1:8090\r\nConnection: close\r\nX-Forwarded-For: 192.0.2.1\r\n"), "{out}");
        assert!(out.contains("Content-Length: 4\r\n"), "{out}");
        assert!(!out.contains("203.0.113.9") && !out.contains("keep-alive") && !out.contains("relay.example"), "{out}");
        assert!(out.ends_with("\r\n\r\n"));
    }
}
