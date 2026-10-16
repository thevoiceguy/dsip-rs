//! An operator's status port: plain HTTP, read-only, `GET /status` (JSON) and `GET /metrics` (Prometheus text).
//!
//! Spec: none (infrastructure). Nothing here is protocol: a service renders its own state and this serves it. The
//! port is meant for loopback (`dsipctl relay-status`, a local Prometheus): it shows who is bound and what is held,
//! so a non-loopback address is logged as a warning.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What a status request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// `GET /status`: the service's state as JSON. `detail` (`?detail=1`) adds per-identity and per-session rows,
    /// with DIDs; without it the page carries counts only.
    Status {
        /// `?detail=1` was given.
        detail: bool,
    },
    /// `GET /metrics`: the same numbers in the Prometheus text format.
    Metrics,
}

/// Parse a request line's method and target into a [`Page`]; `None` for anything else.
pub fn page_of(method: &str, target: &str) -> Option<Page> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match (method, path) {
        ("GET", "/status") => Some(Page::Status { detail: query.split('&').any(|q| q == "detail=1" || q == "detail=true") }),
        ("GET", "/metrics") => Some(Page::Metrics),
        _ => None,
    }
}

/// Serve status requests on `listen` until the process ends. `render` answers each [`Page`] with a content type and
/// a body; one request per connection.
pub async fn serve<F, Fut>(listen: SocketAddr, render: F) -> anyhow::Result<()>
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
            let (status, ctype, body) = match page_of(method, target) {
                Some(p) => {
                    let (c, b) = render(p).await;
                    ("200 OK", c, b)
                }
                None => ("404 Not Found", "text/plain; charset=utf-8", "GET /status, /status?detail=1 or /metrics\n".to_string()),
            };
            let head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = tcp.write_all(head.as_bytes()).await;
            let _ = tcp.write_all(body.as_bytes()).await;
        });
    }
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
    fn pages_are_status_detail_and_metrics_only() {
        assert_eq!(page_of("GET", "/status"), Some(Page::Status { detail: false }));
        assert_eq!(page_of("GET", "/status?detail=1"), Some(Page::Status { detail: true }));
        assert_eq!(page_of("GET", "/metrics"), Some(Page::Metrics));
        assert_eq!(page_of("POST", "/status"), None);
        assert_eq!(page_of("GET", "/"), None);
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
    }
}
