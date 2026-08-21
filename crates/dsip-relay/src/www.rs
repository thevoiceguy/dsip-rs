//! Static file serving on the relay's TLS port, so the browser demo and the
//! `wss` signaling share one origin and one certificate.
//!
//! Spec: none (infrastructure). A connection's first bytes are peeked: an
//! HTTP `Upgrade: websocket` request is handed to the WebSocket acceptor with
//! the bytes replayed; any other `GET` is answered from `--www` and closed.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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

/// Peek the request head and either wrap for WebSocket or serve a static file.
pub async fn dispatch<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, www: Option<&Path>) -> std::io::Result<First<S>> {
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
    let (status, ctype, body) = match www.and_then(|w| resolve(w, &target)) {
        Some((p, ct)) => match std::fs::read(&p) {
            Ok(b) => ("200 OK", ct, b),
            Err(_) => ("404 Not Found", "text/plain", b"not found".to_vec()),
        },
        None => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    let hdr = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(hdr.as_bytes()).await?;
    stream.write_all(&body).await?;
    let _ = stream.shutdown().await;
    Ok(First::Served)
}

fn resolve(www: &Path, target: &str) -> Option<(PathBuf, &'static str)> {
    let path = target.split('?').next().unwrap_or("/");
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
