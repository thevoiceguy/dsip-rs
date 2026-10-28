//! The mailbox's status page (`--status-listen`): who it serves against `--serve-any`, each owner's storage against
//! the quota, the hubs it runs, what is waiting to be fanned out or replicated, and what it refused and why.
//!
//! Spec: none (infrastructure). The numbers are the machines' own (`Mailbox::used_bytes` is what the quota is
//! checked against, M§4.3 `quota_bytes`, spec-gap 99); the blob directory is measured on disk.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use dsip_transport::status::{Metrics, Page, JSON_TYPE, METRICS_TYPE};

use super::Service;

/// Counters since the service started.
#[derive(Debug, Default)]
pub struct Stats {
    started: i64,
    frames_in: BTreeMap<String, u64>,
    refused: BTreeMap<(String, String), u64>,
    blob_requests: BTreeMap<(String, u16), u64>,
    binds: u64,
    tls_failed: u64,
}

impl Stats {
    /// Counters from `now`.
    pub fn new(now: i64) -> Stats {
        Stats { started: now, ..Default::default() }
    }

    /// A verified frame, by type.
    pub fn frame_in(&mut self, msg_type: &str) {
        *self.frames_in.entry(msg_type.to_string()).or_default() += 1;
    }

    /// An `error` this service signed, by reason token and code.
    pub fn refused(&mut self, reason: &str, code: &str) {
        *self.refused.entry((reason.to_string(), code.to_string())).or_default() += 1;
    }

    /// Count the `error`s among frames about to leave.
    pub fn refusals_in(&mut self, envs: &[&dsip_core::envelope::Envelope]) {
        for env in envs {
            let Some(p) = dsip_core::b64::decode(&env.payload).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
            if p["type"] == "error" {
                self.refused(p["reason"].as_str().unwrap_or(""), p["detail"].as_str().unwrap_or(""));
            }
        }
    }

    /// A blob endpoint request, by method and the status answered.
    pub fn blob(&mut self, method: &str, status: u16) {
        *self.blob_requests.entry((method.to_string(), status)).or_default() += 1;
    }

    /// A device bound.
    pub fn bound(&mut self) {
        self.binds += 1;
    }

    /// A TLS handshake failed.
    pub fn tls_failed(&mut self) {
        self.tls_failed += 1;
    }
}

/// One owner's numbers.
struct OwnerRow {
    identity: String,
    configured: bool,
    items: usize,
    used_bytes: i64,
    devices: usize,
    devices_bound: usize,
    groups: usize,
    key_packages: i64,
    last_hello_s: Option<i64>,
}

fn owners(st: &Service, now: i64) -> Vec<OwnerRow> {
    let last: BTreeMap<&str, i64> = st.enrolment.entries().iter().map(|(i, t)| (i.as_str(), *t)).collect();
    st.owned
        .iter()
        .map(|(id, o)| {
            let snap = o.mailbox.snapshot();
            let devices = o.mailbox.devices();
            OwnerRow {
                identity: id.clone(),
                configured: st.configured.contains(id),
                items: snap["items"].as_array().map_or(0, Vec::len),
                used_bytes: o.mailbox.used_bytes(),
                devices: devices.len(),
                devices_bound: devices.iter().filter(|d| st.bound.contains_key(*d)).count(),
                groups: snap["groups"].as_object().map_or(0, |g| g.len()),
                key_packages: snap["key_packages"].as_object().map_or(0, |k| k.values().map(|v| v["one_time"].as_i64().unwrap_or(0)).sum()),
                last_hello_s: last.get(id.as_str()).map(|t| now - t),
            }
        })
        .collect()
}

fn blob_dir(st: &Service) -> (usize, u64) {
    std::fs::read_dir(&st.blob_dir)
        .map(|d| {
            d.flatten()
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .fold((0, 0), |(n, b), m| (n + 1, b + m.len()))
        })
        .unwrap_or((0, 0))
}

fn quota_pct(used: i64, quota: i64) -> f64 {
    if quota > 0 { (used as f64 * 1000.0 / quota as f64).round() / 10.0 } else { 0.0 }
}

/// The `/status` JSON.
pub fn status(st: &Service, now: i64, detail: bool) -> Value {
    let s = &st.stats;
    let rows = owners(st, now);
    let (blobs, blob_bytes) = blob_dir(st);
    let enrolled = st.enrolment.entries().len();
    let fullest = rows.iter().max_by_key(|r| r.used_bytes);
    let pending_fanout: usize = st.hubs.values().map(|h| h.snapshot()["pending"].as_object().map_or(0, |p| p.values().map(|q| q.as_array().map_or(0, Vec::len)).sum())).sum();
    let mut v = json!({
        "mailbox": st.key.did(),
        "version": env!("CARGO_PKG_VERSION"),
        "now": now,
        "uptime_s": now - s.started,
        "enrolment": {
            "configured": st.configured.len(), "enrolled": enrolled, "serve_any": st.serve_any,
            "free": st.serve_any.map(|n| n.saturating_sub(enrolled)), "release_idle": st.release_idle, "mls_retention_s": st.mls_retention,
        },
        "connections": {"devices_bound": st.bound.len(), "standby": st.standby.len(), "peer_mailboxes": st.peers.len()},
        "storage": {
            "owners": rows.len(), "items": rows.iter().map(|r| r.items).sum::<usize>(),
            "used_bytes": rows.iter().map(|r| r.used_bytes).sum::<i64>(), "quota_bytes_each": st.quota_bytes,
            "fullest": fullest.map(|r| json!({"used_bytes": r.used_bytes, "quota_pct": quota_pct(r.used_bytes, st.quota_bytes)})),
            "max_blob_bytes": st.max_blob_bytes, "blobs_on_disk": blobs, "blob_bytes_on_disk": blob_bytes,
        },
        "hubs": {"groups": st.hubs.len(), "pending_fanout": pending_fanout, "fanout_payloads": st.fanout.len(),
                 "retrying": st.retry.len(), "replicate_later": st.replicate_later.len()},
        "totals": {
            "binds": s.binds, "tls_failed": s.tls_failed, "frames_in": s.frames_in,
            "refused": s.refused.iter().map(|((r, c), n)| json!({"reason": r, "detail": c, "count": n})).collect::<Vec<_>>(),
            "blob_requests": s.blob_requests.iter().map(|((m, c), n)| json!({"method": m, "status": c, "count": n})).collect::<Vec<_>>(),
        },
    });
    if detail {
        v["owners"] = rows
            .iter()
            .map(|r| {
                (r.identity.clone(), json!({"configured": r.configured, "items": r.items, "used_bytes": r.used_bytes,
                    "quota_pct": quota_pct(r.used_bytes, st.quota_bytes), "devices": r.devices, "devices_bound": r.devices_bound,
                    "groups": r.groups, "one_time_key_packages": r.key_packages, "last_hello_s": r.last_hello_s,
                    "released_in_s": (st.release_idle && !r.configured).then(|| r.last_hello_s.map(|l| st.mls_retention - l)).flatten()}))
            })
            .collect::<serde_json::Map<_, _>>()
            .into();
        v["hubs"]["list"] = st
            .hubs
            .iter()
            .map(|(g, h)| {
                let snap = h.snapshot();
                (g.clone(), json!({"epoch": snap["epoch"], "next_seq": snap["next_seq"],
                    "members": snap["roster"].as_object().map_or(0, |r| r.len()),
                    "pending": snap["pending"].as_object().map_or(0, |p| p.values().map(|q| q.as_array().map_or(0, Vec::len)).sum::<usize>()),
                    "moved_to": snap["moved_to"]}))
            })
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    v
}

/// The `/metrics` text.
pub fn metrics(st: &Service, now: i64) -> String {
    let s = &st.stats;
    let rows = owners(st, now);
    let (blobs, blob_bytes) = blob_dir(st);
    let mut m = Metrics::default();
    m.gauge("dsip_mailbox_uptime_seconds", "Seconds since the mailbox started.", &[], now - s.started);
    m.gauge("dsip_mailbox_identities", "Identities served, by how (configured --owner, enrolled by binding).", &[("how", "configured")], st.configured.len() as i64);
    m.gauge("dsip_mailbox_identities", "Identities served, by how (configured --owner, enrolled by binding).", &[("how", "enrolled")], st.enrolment.entries().len() as i64);
    if let Some(n) = st.serve_any {
        m.gauge("dsip_mailbox_serve_any", "Places for identities that enrol by binding (--serve-any).", &[], n as i64);
    }
    m.gauge("dsip_mailbox_devices_bound", "Devices bound now.", &[], st.bound.len() as i64);
    m.gauge("dsip_mailbox_peer_mailboxes", "Connections to other mailboxes (federation).", &[], st.peers.len() as i64);
    m.gauge("dsip_mailbox_items", "Items stored across owners.", &[], rows.iter().map(|r| r.items as i64).sum());
    m.gauge("dsip_mailbox_used_bytes", "Bytes counted against owners' quotas, summed.", &[], rows.iter().map(|r| r.used_bytes).sum());
    m.gauge("dsip_mailbox_used_bytes_max", "The fullest owner's bytes counted against its quota.", &[], rows.iter().map(|r| r.used_bytes).max().unwrap_or(0));
    m.gauge("dsip_mailbox_quota_bytes", "Each owner's quota (--quota-bytes).", &[], st.quota_bytes);
    m.gauge("dsip_mailbox_blobs", "Blobs on disk.", &[], blobs as i64);
    m.gauge("dsip_mailbox_blob_bytes", "Bytes of blobs on disk.", &[], blob_bytes as i64);
    m.gauge("dsip_mailbox_hub_groups", "Groups this service hubs.", &[], st.hubs.len() as i64);
    m.gauge("dsip_mailbox_fanout_payloads", "Fan-out payloads held until every member mailbox acknowledges.", &[], st.fanout.len() as i64);
    m.counter("dsip_mailbox_binds_total", "Devices bound since start.", &[], s.binds);
    m.counter("dsip_mailbox_tls_failed_total", "TLS handshakes that failed.", &[], s.tls_failed);
    for (t, n) in &s.frames_in {
        m.counter("dsip_mailbox_frames_in_total", "Verified frames, by type.", &[("type", t)], *n);
    }
    for ((r, c), n) in &s.refused {
        m.counter("dsip_mailbox_refused_total", "Errors signed, by reason token and code.", &[("reason", r), ("detail", c)], *n);
    }
    for ((meth, code), n) in &s.blob_requests {
        m.counter("dsip_mailbox_blob_requests_total", "Blob endpoint requests, by method and status.", &[("method", meth), ("status", &code.to_string())], *n);
    }
    m.finish()
}

/// Answer one status request.
pub async fn render(service: std::sync::Arc<tokio::sync::Mutex<Service>>, page: Page) -> (&'static str, String) {
    // read-only: the machines' clocks advance on traffic and on the retry tick, not on a status read
    let st = service.lock().await;
    let now = dsip_transport::now_s();
    match page {
        Page::Status { detail } => (JSON_TYPE, format!("{:#}\n", status(&st, now, detail))),
        Page::Metrics => (METRICS_TYPE, metrics(&st, now)),
    }
}
