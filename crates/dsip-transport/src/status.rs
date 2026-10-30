//! An operator's status port: plain HTTP, `GET /status` (JSON), `GET /metrics` (Prometheus text) and the admin
//! commands, `/admin/<command>` (JSON; the binaries' `admin` subcommand, [`crate::admin`]).
//!
//! Spec: none (infrastructure). Nothing here is protocol: a service renders its own state and this serves it. The
//! port is meant for loopback (`dsipctl relay-status`, a local Prometheus, `dsip-mailbox admin`): it shows who is bound
//! and what is held, and its admin commands change what a service holds, so a non-loopback address is logged as a
//! warning.
//!
//! Impl (service-nodes plan S5): an admin command that changes state is a `POST` carrying the header [`ADMIN_HEADER`].
//! A web page the operator has open can make the browser send a plain `POST` to a loopback port, but not one with a
//! header of its own without a CORS preflight, which this port never answers; a `POST` without it is refused 403.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The header an admin command that changes state carries.
pub const ADMIN_HEADER: &str = "x-dsip-admin";

/// What a status request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// `GET /status`: the service's state as JSON. `detail` (`?detail=1`) adds per-identity and per-session rows,
    /// with DIDs; without it the page carries counts only.
    Status {
        /// `?detail=1` was given.
        detail: bool,
    },
    /// `GET /metrics`: the same numbers in the Prometheus text format.
    Metrics,
    /// `/admin/<command>?<args>`: an operator's command, answered with JSON (`{"error": …}` when refused).
    Admin {
        /// The command, as the service names it (`enrolments`, `release`, `bindings`).
        command: String,
        /// The query's `key=value` pairs, percent-decoded.
        args: BTreeMap<String, String>,
        /// A `POST` (with [`ADMIN_HEADER`]): the command may change state. A `GET` only reads.
        write: bool,
    },
}

/// Parse a request line's method and target into a [`Page`]; `None` for anything else.
pub fn page_of(method: &str, target: &str) -> Option<Page> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match (method, path) {
        ("GET", "/status") => Some(Page::Status { detail: query.split('&').any(|q| q == "detail=1" || q == "detail=true") }),
        ("GET", "/metrics") => Some(Page::Metrics),
        ("GET" | "POST", p) if p.starts_with("/admin/") && p.len() > "/admin/".len() => Some(Page::Admin {
            command: p["/admin/".len()..].to_string(),
            args: query.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (decode(k), decode(v))).collect(),
            write: method == "POST",
        }),
        _ => None,
    }
}

/// Percent-encode a query value: everything but unreserved characters (RFC 3986 §2.3) and `:`.
pub fn encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())) {
            (b'%', Some(x)) => {
                out.push(x);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serve status requests on `listen` until the process ends. `render` answers each [`Page`] with a content type and
/// a body; one request per connection.
pub async fn serve<F, Fut>(listen: SocketAddr, render: F) -> crate::Result<()>
where
    F: Fn(Page) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = (&'static str, String)> + Send,
{
    let listener = tokio::net::TcpListener::bind(listen).await?;
    if listen.ip().is_loopback() {
        tracing::info!("status on http://{listen}/status and /metrics");
    } else {
        tracing::warn!("status on http://{listen}/status and /metrics: not loopback, so anyone who can reach it sees who is bound here");
    }
    loop {
        let (mut tcp, _) = listener.accept().await?;
        let render = render.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut n = 0;
            let head = tokio::time::timeout(Duration::from_secs(5), async {
                while n < buf.len() {
                    let k = tcp.read(&mut buf[n..]).await?;
                    if k == 0 {
                        break;
                    }
                    n += k;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Ok::<_, std::io::Error>(())
            })
            .await;
            if !matches!(head, Ok(Ok(()))) {
                return;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            let mut line = text.lines().next().unwrap_or("").split_whitespace();
            let (method, target) = (line.next().unwrap_or(""), line.next().unwrap_or("/"));
            let admin_header = text.lines().skip(1).any(|l| l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(ADMIN_HEADER)));
            let (status, ctype, body) = match page_of(method, target) {
                Some(Page::Admin { write: true, .. }) if !admin_header => {
                    ("403 Forbidden", JSON_TYPE, format!("{{\"error\": \"an admin POST carries the {ADMIN_HEADER} header\"}}\n"))
                }
                Some(p) => {
                    let (c, b) = render(p).await;
                    ("200 OK", c, b)
                }
                None => ("404 Not Found", "text/plain; charset=utf-8", "GET /status, /status?detail=1, /metrics or /admin/<command>\n".to_string()),
            };
            let head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = tcp.write_all(head.as_bytes()).await;
            let _ = tcp.write_all(body.as_bytes()).await;
        });
    }
}

/// Send one request to a status port, as an admin command does: `method` (`GET`, or `POST` with [`ADMIN_HEADER`]) and
/// `target` (path and query). Returns the HTTP status code and the body.
pub async fn request(addr: SocketAddr, method: &str, target: &str) -> crate::Result<(u16, String)> {
    let mut tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{addr}: no answer")))??;
    let extra = if method == "POST" { format!("{ADMIN_HEADER}: 1\r\nContent-Length: 0\r\n") } else { String::new() };
    tcp.write_all(format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n").as_bytes()).await?;
    let mut r = String::new();
    tokio::time::timeout(Duration::from_secs(30), tcp.read_to_string(&mut r))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{addr}: no answer")))??;
    let (head, body) = r.split_once("\r\n\r\n").unwrap_or((&r, ""));
    let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((code, body.to_string()))
}

/// The content type of [`Metrics::finish`]'s text.
pub const METRICS_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// The content type of a `/status` body.
pub const JSON_TYPE: &str = "application/json";

/// Prometheus text exposition, built one sample at a time; `# HELP`/`# TYPE` are written before a name's first sample.
#[derive(Debug, Default)]
pub struct Metrics {
    out: String,
    named: BTreeSet<String>,
}

impl Metrics {
    /// A gauge sample: a value that goes up and down (bound devices, bytes held).
    pub fn gauge(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: i64) {
        self.sample(name, "gauge", help, labels, value);
    }

    /// A counter sample: a total since the process started.
    pub fn counter(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: u64) {
        self.sample(name, "counter", help, labels, value as i64);
    }

    fn sample(&mut self, name: &str, kind: &str, help: &str, labels: &[(&str, &str)], value: i64) {
        if self.named.insert(name.to_string()) {
            let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        }
        let _ = write!(self.out, "{name}");
        if !labels.is_empty() {
            let l: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
            let _ = write!(self.out, "{{{}}}", l.join(","));
        }
        let _ = writeln!(self.out, " {value}");
    }

    /// The exposition text.
    pub fn finish(self) -> String {
        self.out
    }
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_status_detail_metrics_and_admin() {
        assert_eq!(page_of("GET", "/status"), Some(Page::Status { detail: false }));
        assert_eq!(page_of("GET", "/status?detail=1"), Some(Page::Status { detail: true }));
        assert_eq!(page_of("GET", "/metrics"), Some(Page::Metrics));
        assert_eq!(page_of("POST", "/status"), None);
        assert_eq!(page_of("GET", "/"), None);
        assert_eq!(page_of("GET", "/admin/"), None);
        let did = "did:web:example.com%3A8443:alice";
        assert_eq!(page_of("POST", &format!("/admin/release?identity={}", encode(did))), Some(Page::Admin {
            command: "release".into(), args: [("identity".to_string(), did.to_string())].into(), write: true }));
        assert_eq!(encode(did), "did:web:example.com%253A8443:alice");
    }

    #[test]
    fn metrics_write_help_and_type_once_and_escape_labels() {
        let mut m = Metrics::default();
        m.counter("x_total", "things", &[("reason", "a\"b")], 2);
        m.counter("x_total", "things", &[("reason", "c")], 3);
        m.gauge("y", "level", &[], 7);
        assert_eq!(m.finish(), "# HELP x_total things\n# TYPE x_total counter\nx_total{reason=\"a\\\"b\"} 2\nx_total{reason=\"c\"} 3\n# HELP y level\n# TYPE y gauge\ny 7\n");
    }

    #[tokio::test]
    async fn serves_a_page_and_404s_the_rest() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(serve(addr, |p| async move { (JSON_TYPE, format!("{p:?}")) }));
        let get = |path: &'static str| async move {
            for _ in 0..50 {
                if let Ok(mut s) = tokio::net::TcpStream::connect(addr).await {
                    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
                    let mut r = String::new();
                    s.read_to_string(&mut r).await.unwrap();
                    return r;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("status port never came up");
        };
        let r = get("/status?detail=1").await;
        assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("Status { detail: true }"), "{r}");
        assert!(get("/nope").await.starts_with("HTTP/1.1 404"));
        // an admin POST: with the header it is served, without it refused
        let (code, body) = request(addr, "POST", "/admin/release?identity=did:key:z").await.unwrap();
        assert_eq!(code, 200);
        assert!(body.contains("write: true") && body.contains("did:key:z"), "{body}");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST /admin/release?identity=did:key:z HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut r = String::new();
        s.read_to_string(&mut r).await.unwrap();
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    }
}
