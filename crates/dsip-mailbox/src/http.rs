//! The blob endpoint on the mailbox's TLS port, beside `ws/1.0`.
//!
//! Spec: M§5.6 (`PUT {blob_endpoint}/{sha256}` with `Authorization: DSIP <compact envelope>`, answered
//! with a signed `accepted` as the JSON body), M§8.4 (`GET {blob_endpoint}/{sha256}` as a capability URL).
//!
//! Impl: one listener serves both. A connection's request head is read first: a WebSocket upgrade is
//! handed to the `ws/1.0` acceptor with the bytes replayed ([`Prefixed`]); anything else is one HTTP/1.1
//! request, answered and closed. Decisions come from `dsip_messaging::mailbox::{blob_put, blob_get}`.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Path prefix of the blob endpoint.
pub const BLOB_PATH: &str = "/blobs/";

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

/// One plain HTTP request head, with whatever body bytes arrived alongside it.
pub struct Request<S> {
    /// Method, upper case.
    pub method: String,
    /// Request target.
    pub path: String,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    /// Body bytes already read past the head.
    pub body_start: Vec<u8>,
    /// The connection.
    pub stream: S,
}

impl<S> Request<S> {
    /// A header value by lower-case name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// What the first request on a connection is.
pub enum First<S> {
    /// A WebSocket upgrade, to hand to the `ws/1.0` acceptor.
    WebSocket(Prefixed<S>),
    /// A plain HTTP request.
    Http(Request<S>),
}

/// Read the request head and classify the connection.
pub async fn classify<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> std::io::Result<First<S>> {
    let mut head = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed before request head"));
        }
        head.extend_from_slice(&chunk[..n]);
        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if head.len() > 32_768 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request head too large"));
        }
    };
    let text = String::from_utf8_lossy(&head[..end]).to_string();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_ascii_uppercase();
    let path = first.next().unwrap_or("/").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    if headers.iter().any(|(k, v)| k == "upgrade" && v.to_ascii_lowercase().contains("websocket")) {
        return Ok(First::WebSocket(Prefixed { inner: stream, buf: head, pos: 0 }));
    }
    let body_start = head[end..].to_vec();
    Ok(First::Http(Request { method, path, headers, body_start, stream }))
}

/// Read exactly `len` body bytes, starting from those that came with the head.
pub async fn read_body<S: AsyncRead + Unpin>(req: &mut Request<S>, len: usize) -> std::io::Result<Vec<u8>> {
    let mut body = std::mem::take(&mut req.body_start);
    body.truncate(len);
    let mut rest = vec![0u8; len - body.len()];
    req.stream.read_exact(&mut rest).await?;
    body.extend(rest);
    Ok(body)
}

/// Write one response and close the connection.
pub async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        _ => "Error",
    };
    let hdr = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(hdr.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}
