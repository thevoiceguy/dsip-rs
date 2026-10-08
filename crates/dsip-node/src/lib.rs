//! `dsip-node` — a deployable DSIP hints node: a member of DSIP's own overlay, a participant in the Mainline DHT,
//! and an HTTP hints API for clients that join neither (browsers, light clients).
//!
//! Spec: sections owned by this crate — DHT Reachability Hints Profile §10 (HTTP access, v0.11): the routes, their
//! answers, and verify-before-store on each ([`dsip_core::pkarr::store`] for Pkarr packets, the overlay's own
//! evaluation for §2 records). It is a hints tier only (§8.1): it never answers with authority, and every client
//! verifies what it receives, so withholding is its only power. Plan: `impl/docs/dsip-node-plan.md`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod config;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, MatchedPath, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dsip_core::pkarr::{self, Store};
use mainline::async_dht::AsyncDht;
use mainline::MutableItem;
use serde_json::{json, Value};
use tokio::sync::Mutex;

/// The node's shared state: the overlay handle, the Mainline node, and the Pkarr packets it holds.
///
/// Spec: none (infrastructure).
pub struct Node {
    /// The DSIP overlay (libp2p Kademlia), when this node is a member.
    pub overlay: Option<dsip_dht::node::Handle>,
    /// The Mainline DHT, when this node participates.
    pub mainline: Option<AsyncDht>,
    /// Pkarr packets held, by canonical z-base-32 key.
    pub held: Mutex<HashMap<String, Vec<u8>>>,
    /// This node's overlay PeerId, for `/dsip/v1/node`.
    pub peer_id: String,
    /// Where held Pkarr packets are written as they are stored, so a restart serves them at once.
    pub state: Option<config::StateDir>,
    /// HTTP limits.
    pub limits: Limits,
    /// Counters for `/metrics`.
    pub metrics: Metrics,
    buckets: std::sync::Mutex<HashMap<IpAddr, (f64, std::time::Instant)>>,
    /// When each held packet was last looked for on Mainline.
    checked: std::sync::Mutex<HashMap<String, std::time::Instant>>,
}

/// HTTP limits (profile §10: a node MAY limit request rates, answering 429).
///
/// Spec: DHT Reachability Hints Profile §10.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Requests per client IP per minute (a token bucket of this size, refilled evenly); 0 turns it off.
    pub http_per_ip_per_min: u32,
    /// Take the client IP from the first `X-Forwarded-For` entry: only behind a reverse proxy that sets it.
    pub trust_forwarded_for: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { http_per_ip_per_min: 120, trust_forwarded_for: false }
    }
}

/// Counters exposed at `/metrics`.
///
/// Spec: none (infrastructure).
#[derive(Debug, Default)]
pub struct Metrics {
    /// HTTP requests by (route, status).
    pub http: std::sync::Mutex<BTreeMap<(String, u16), u64>>,
    /// `PUT /<z32>` outcomes by (outcome, reason).
    pub pkarr_puts: std::sync::Mutex<BTreeMap<(String, String), u64>>,
}

impl Node {
    /// A node with default limits and empty counters.
    pub fn new(overlay: Option<dsip_dht::node::Handle>, mainline: Option<AsyncDht>, peer_id: String,
               state: Option<config::StateDir>) -> Node {
        Node { overlay, mainline, held: Default::default(), peer_id, state, limits: Limits::default(),
               metrics: Metrics::default(), buckets: Default::default(), checked: Default::default() }
    }

    /// Whether `z32` was last looked for on Mainline more than [`MAINLINE_RECHECK`] ago; if so, it is now.
    fn recheck_due(&self, z32: &str) -> bool {
        let mut checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if checked.get(z32).is_some_and(|t| now.duration_since(*t) < MAINLINE_RECHECK) {
            return false;
        }
        checked.insert(z32.to_string(), now);
        true
    }

    /// The most recent packet for `key` on Mainline, when it passes the store check against what is held: it is
    /// then held, and returned.
    async fn fetch_mainline(&self, dht: &AsyncDht, z32: &str, key: &[u8; 32]) -> Option<Vec<u8>> {
        let item = tokio::time::timeout(MAINLINE_QUERY, dht.get_mutable_most_recent(key, None)).await.ok().flatten()?;
        let mut payload = item.signature().to_vec();
        payload.extend_from_slice(&(item.seq() as u64).to_be_bytes());
        payload.extend_from_slice(item.value());
        // what Mainline returns is verified like any PUT before it is cached or served
        let verdict = pkarr::store(z32, &payload, self.held.lock().await.get(z32).map(Vec::as_slice), now_s());
        if verdict != Store::Stored {
            return None;
        }
        self.hold(z32, payload.clone()).await;
        Some(payload)
    }

    /// Take one token from `ip`'s bucket; `false` when it is empty.
    fn admit(&self, ip: IpAddr) -> bool {
        let per_min = self.limits.http_per_ip_per_min as f64;
        if per_min == 0.0 {
            return true;
        }
        let now = std::time::Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if b.len() > 100_000 {
            // full buckets carry no information: drop them before the map grows without bound
            b.retain(|_, (tokens, at)| *tokens + now.duration_since(*at).as_secs_f64() * per_min / 60.0 < per_min);
        }
        let (tokens, at) = b.entry(ip).or_insert((per_min, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * per_min / 60.0).min(per_min);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
    /// Hold a packet that passed the store check, on disk too when there is a state directory.
    async fn hold(&self, z32: &str, payload: Vec<u8>) {
        if let Some(st) = &self.state {
            if let Err(e) = config::write_atomic(&st.pkarr(z32), &payload) {
                tracing::warn!("could not write the packet for {z32}: {e}");
            }
        }
        self.held.lock().await.insert(z32.to_string(), payload);
    }

    /// Restore the packets kept in the state directory, each checked again as a fresh `PUT` would be.
    ///
    /// Spec: DHT Reachability Hints Profile §10 (`check: "store"`): a node's own disk is no exception.
    pub async fn restore(&self) -> (usize, usize) {
        let Some(st) = &self.state else { return (0, 0) };
        let (mut kept, mut dropped) = (0, 0);
        let mut held = self.held.lock().await;
        for (z32, payload) in st.pkarr_all() {
            if pkarr::store(&z32, &payload, held.get(&z32).map(Vec::as_slice), now_s()) == Store::Stored {
                held.insert(z32, payload);
                kept += 1;
            } else {
                let _ = std::fs::remove_file(st.pkarr(&z32));
                dropped += 1;
            }
        }
        (kept, dropped)
    }
}

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// How long a Mainline lookup may take on behalf of an HTTP client.
const MAINLINE_QUERY: Duration = Duration::from_secs(5);
/// How often a held packet is looked for again on Mainline while it is fresh, in the background of a `GET`.
const MAINLINE_RECHECK: Duration = Duration::from_secs(60);

/// The HTTP hints API (profile §10), with `Access-Control-Allow-Origin: *` on every answer.
///
/// Spec: DHT Reachability Hints Profile §10.
pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/dsip/v1/node", get(node_info))
        .route("/dsip/v1/hints/{did}", get(overlay_get))
        .route("/dsip/v1/hints", post(overlay_post))
        .route("/metrics", get(metrics))
        .route("/{z32}", get(pkarr_get).put(pkarr_put))
        .layer(axum::middleware::from_fn_with_state(node.clone(), limit_and_count))
        .layer(axum::middleware::map_response(|mut r: Response| async move {
            r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
            r
        }))
        .with_state(node)
}

/// The per-IP rate limit (429) and the request counters, around every route.
///
/// Spec: DHT Reachability Hints Profile §10 (a node MAY limit request rates, answering 429).
async fn limit_and_count(State(node): State<Arc<Node>>, req: Request, next: axum::middleware::Next) -> Response {
    let route = req.extensions().get::<MatchedPath>().map(|m| m.as_str().to_string()).unwrap_or_else(|| "other".into());
    let forwarded = if node.limits.trust_forwarded_for {
        req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
    } else {
        None
    };
    let ip = forwarded.or_else(|| req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()));
    let resp = if route != "/metrics" && ip.is_some_and(|ip| !node.admit(ip)) {
        (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")], "rate-limited").into_response()
    } else {
        next.run(req).await
    };
    *node.metrics.http.lock().unwrap_or_else(|e| e.into_inner()).entry((route, resp.status().as_u16())).or_default() += 1;
    resp
}

/// `GET /metrics`: Prometheus text exposition.
///
/// Spec: none (infrastructure).
async fn metrics(State(node): State<Arc<Node>>) -> Response {
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, kind: &str, lines: Vec<(String, f64)>| {
        out += &format!("# HELP {name} {help}\n# TYPE {name} {kind}\n");
        for (labels, v) in lines {
            out += &format!("{name}{labels} {v}\n");
        }
    };
    if let Some(h) = &node.overlay {
        if let Ok(s) = h.stats().await {
            gauge("dsip_node_overlay_peers", "Peers in the overlay routing table.", "gauge", vec![(String::new(), s.routing_peers as f64)]);
            gauge("dsip_node_overlay_records", "Overlay records held.", "gauge", vec![(String::new(), s.stored as f64)]);
            gauge("dsip_node_overlay_puts_accepted_total", "Inbound overlay PUTs stored.", "counter", vec![(String::new(), s.puts_accepted as f64)]);
            gauge("dsip_node_overlay_puts_rejected_total", "Inbound overlay PUTs refused, by reason.", "counter",
                  s.puts_rejected.iter().map(|(r, n)| (format!("{{reason=\"{r}\"}}"), *n as f64)).collect());
            gauge("dsip_node_overlay_bans_total", "Peers banned after spending their rejection budget.", "counter", vec![(String::new(), s.bans as f64)]);
            gauge("dsip_node_overlay_banned", "Peers banned now.", "gauge", vec![(String::new(), s.banned as f64)]);
            gauge("dsip_node_overlay_refused_connections_total", "Connections refused from banned IPs.", "counter",
                  vec![(String::new(), s.refused_connections as f64)]);
        }
    }
    if let Some(d) = &node.mainline {
        let i = d.info().await;
        gauge("dsip_node_mainline_server_mode", "1 when this node serves the Mainline DHT.", "gauge",
              vec![(String::new(), if i.server_mode() { 1.0 } else { 0.0 })]);
        gauge("dsip_node_mainline_dht_size_estimate", "The Mainline DHT's estimated size.", "gauge",
              vec![(String::new(), i.dht_size_estimate().0 as f64)]);
    }
    let held = node.held.lock().await.len();
    gauge("dsip_node_pkarr_held", "Pkarr packets held.", "gauge", vec![(String::new(), held as f64)]);
    let puts = node.metrics.pkarr_puts.lock().unwrap_or_else(|e| e.into_inner()).clone();
    gauge("dsip_node_pkarr_puts_total", "PUT /<z32> by outcome and reason.", "counter",
          puts.iter().map(|((o, r), n)| (format!("{{outcome=\"{o}\",reason=\"{r}\"}}"), *n as f64)).collect());
    let http = node.metrics.http.lock().unwrap_or_else(|e| e.into_inner()).clone();
    gauge("dsip_node_http_requests_total", "HTTP requests by route and status.", "counter",
          http.iter().map(|((r, c), n)| (format!("{{route=\"{r}\",status=\"{c}\"}}"), *n as f64)).collect());
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response()
}

/// `GET /<z32>`: the held packet, or one fetched from Mainline that passes the store check; else 404.
///
/// A fresh held packet is served at once and looked for again on Mainline in the background, at most once a
/// minute; one past its TTL is looked for first, so a publisher's re-signed packet replaces it. Without that, a node
/// keeps serving the first packet it fetched long after it expired — measured on the WAN.
///
/// Spec: DHT Reachability Hints Profile §10 (Pkarr's relay interface; a held packet is a cache: SHOULD look again
/// once it is past its TTL, MAY while it is fresh).
/// Impl: while it is fresh, at most once a minute per key, in the background.
async fn pkarr_get(State(node): State<Arc<Node>>, Path(z32): Path<String>) -> Response {
    let Ok(key) = pkarr::z32_decode(&z32) else { return (StatusCode::BAD_REQUEST, "bad-key").into_response() };
    let held = node.held.lock().await.get(&z32).cloned();
    let Some(dht) = node.mainline.clone() else {
        return held.map_or_else(|| StatusCode::NOT_FOUND.into_response(), pkarr_payload);
    };
    if let Some(p) = &held {
        if pkarr::fresh_until(p).is_some_and(|t| now_s() < t) {
            if node.recheck_due(&z32) {
                let (n, z) = (node.clone(), z32.clone());
                tokio::spawn(async move { n.fetch_mainline(&dht, &z, &key).await });
            }
            return pkarr_payload(p.clone());
        }
        node.recheck_due(&z32);
    }
    match node.fetch_mainline(&dht, &z32, &key).await {
        Some(p) => pkarr_payload(p),
        // nothing newer: what is held is still served, and readers judge it
        None => held.map_or_else(|| StatusCode::NOT_FOUND.into_response(), pkarr_payload),
    }
}

fn pkarr_payload(p: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/pkarr.org/relays#payload")], p).into_response()
}

/// `PUT /<z32>`: verify, apply §8.3's `ts` rule against the held packet, store, and put it on Mainline.
///
/// Spec: DHT Reachability Hints Profile §10; README `pkarr`, `check: "store"` (204 / 409 / 400).
async fn pkarr_put(State(node): State<Arc<Node>>, Path(z32): Path<String>, body: Bytes) -> Response {
    // one store decision at a time, so two racing PUTs cannot both pass the ts rule against the same held packet
    let mut held = node.held.lock().await;
    let verdict = pkarr::store(&z32, &body, held.get(&z32).map(Vec::as_slice), now_s());
    let (o, r) = match &verdict {
        Store::Stored => ("stored", ""),
        Store::Kept(r) => ("kept", *r),
        Store::Rejected(r) => ("rejected", *r),
    };
    *node.metrics.pkarr_puts.lock().unwrap_or_else(|e| e.into_inner()).entry((o.into(), r.into())).or_default() += 1;
    match verdict {
        Store::Stored => {
            if let Some(st) = &node.state {
                if let Err(e) = config::write_atomic(&st.pkarr(&z32), &body) {
                    tracing::warn!("could not write the packet for {z32}: {e}");
                }
            }
            held.insert(z32.clone(), body.to_vec());
            drop(held);
            if let (Some(dht), Ok(key)) = (&node.mainline, pkarr::z32_decode(&z32)) {
                let sig: [u8; 64] = body[..64].try_into().expect("checked by store");
                let ts = u64::from_be_bytes(body[64..72].try_into().expect("checked by store"));
                let item = MutableItem::new_signed_unchecked(key, sig, &body[72..], ts as i64, None);
                let dht = dht.clone();
                tokio::spawn(async move {
                    if let Err(e) = dht.put_mutable(item, None).await {
                        tracing::info!("mainline put for {z32}: {e}");
                    }
                });
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Store::Kept("same") => StatusCode::NO_CONTENT.into_response(),
        Store::Kept(reason) => (StatusCode::CONFLICT, reason).into_response(),
        Store::Rejected(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
    }
}

/// `GET /dsip/v1/hints/<did>`: the overlay records for a DID that verify and are unexpired.
///
/// Spec: DHT Reachability Hints Profile §10, §2, §4.
async fn overlay_get(State(node): State<Arc<Node>>, Path(did): Path<String>) -> Response {
    let Some(h) = &node.overlay else { return StatusCode::NOT_FOUND.into_response() };
    match h.get(did).await {
        Ok(out) => {
            // each peer holding the record returns its copy: one entry per distinct verified record
            let mut hints: Vec<&String> = vec![];
            for (frame, v) in &out.candidates {
                if v["verdict"] == "accept" && !hints.contains(&frame) {
                    hints.push(frame);
                }
            }
            Json(json!({"hints": hints})).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

/// `POST /dsip/v1/hints`: a §2 record, verified before it is stored and put on the overlay.
///
/// Spec: DHT Reachability Hints Profile §10, §4.
async fn overlay_post(State(node): State<Arc<Node>>, body: String) -> Response {
    let Some(h) = &node.overlay else { return StatusCode::NOT_FOUND.into_response() };
    // the overlay verifies before it stores: `Ok` is stored (here, and on the peers that acknowledged), an error
    // is a refusal (§4: unverifiable; §8.3: superseded by a held record) or a stopped node
    match h.publish(body.trim().to_string()).await {
        Ok(out) => (StatusCode::ACCEPTED, Json(json!({"key": out.key, "acknowledged": out.acknowledged}))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.starts_with("refusing to publish an unverifiable") {
                StatusCode::BAD_REQUEST
            } else if msg.starts_with("refusing to publish: superseded") {
                StatusCode::CONFLICT
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (status, msg).into_response()
        }
    }
}

/// `GET /dsip/v1/node`: what this node is, for operators and directories.
///
/// Spec: none (infrastructure).
async fn node_info(State(node): State<Arc<Node>>) -> Json<Value> {
    let overlay = match &node.overlay {
        Some(h) => h.stats().await.ok().map(|s| json!({"peers": s.routing_peers, "records": s.stored})),
        None => None,
    };
    let mainline = match &node.mainline {
        Some(d) => {
            let i = d.info().await;
            Some(json!({"local_addr": i.local_addr().to_string(), "server_mode": i.server_mode()}))
        }
        None => None,
    };
    Json(json!({"peer_id": node.peer_id, "overlay": overlay, "mainline": mainline,
                "pkarr_held": node.held.lock().await.len(), "version": env!("CARGO_PKG_VERSION")}))
}
