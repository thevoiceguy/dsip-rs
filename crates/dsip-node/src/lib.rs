//! `dsip-node` — a deployable DSIP hints node: a member of DSIP's own overlay, a participant in the Mainline DHT,
//! and an HTTP hints API for clients that join neither (browsers, light clients).
//!
//! Spec: sections owned by this crate — DHT Reachability Hints Profile §10 (HTTP access, v0.11): the routes, their
//! answers, and verify-before-store on each ([`dsip_core::pkarr::store`] for Pkarr packets, the overlay's own
//! evaluation for §2 records). It is a hints tier only (§8.1): it never answers with authority, and every client
//! verifies what it receives, so withholding is its only power. Plan: `impl/docs/dsip-node-plan.md`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
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
}

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// How long a Mainline lookup may take on behalf of an HTTP client.
const MAINLINE_QUERY: Duration = Duration::from_secs(5);

/// The HTTP hints API (profile §10), with `Access-Control-Allow-Origin: *` on every answer.
///
/// Spec: DHT Reachability Hints Profile §10.
pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/dsip/v1/node", get(node_info))
        .route("/dsip/v1/hints/{did}", get(overlay_get))
        .route("/dsip/v1/hints", post(overlay_post))
        .route("/{z32}", get(pkarr_get).put(pkarr_put))
        .layer(axum::middleware::map_response(|mut r: Response| async move {
            r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
            r
        }))
        .with_state(node)
}

/// `GET /<z32>`: the held packet, or one fetched from Mainline that passes the store check; else 404.
///
/// Spec: DHT Reachability Hints Profile §10 (Pkarr's relay interface).
async fn pkarr_get(State(node): State<Arc<Node>>, Path(z32): Path<String>) -> Response {
    let Ok(key) = pkarr::z32_decode(&z32) else { return (StatusCode::BAD_REQUEST, "bad-key").into_response() };
    if let Some(p) = node.held.lock().await.get(&z32) {
        return pkarr_payload(p.clone());
    }
    let Some(dht) = &node.mainline else { return StatusCode::NOT_FOUND.into_response() };
    let item = tokio::time::timeout(MAINLINE_QUERY, dht.get_mutable_most_recent(&key, None)).await.ok().flatten();
    let Some(item) = item else { return StatusCode::NOT_FOUND.into_response() };
    let mut payload = item.signature().to_vec();
    payload.extend_from_slice(&(item.seq() as u64).to_be_bytes());
    payload.extend_from_slice(item.value());
    // what Mainline returns is verified like any PUT before it is cached or served
    let mut held = node.held.lock().await;
    match pkarr::store(&z32, &payload, held.get(&z32).map(Vec::as_slice), now_s()) {
        Store::Stored => {
            held.insert(z32, payload.clone());
            pkarr_payload(payload)
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn pkarr_payload(p: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/pkarr.org/relays#payload")], p).into_response()
}

/// `PUT /<z32>`: verify, apply §8.3's `ts` rule against the held packet, store, and put it on Mainline.
///
/// Spec: DHT Reachability Hints Profile §10; README `pkarr`, `check: "store"` (204 / 409 / 400).
async fn pkarr_put(State(node): State<Arc<Node>>, Path(z32): Path<String>, body: Bytes) -> Response {
    let mut held = node.held.lock().await;
    match pkarr::store(&z32, &body, held.get(&z32).map(Vec::as_slice), now_s()) {
        Store::Stored => {
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
