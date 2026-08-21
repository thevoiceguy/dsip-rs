//! `dsip-relay` — Phase 1 relay: `wss` listener, `hello` binding, routing, per-leg forking.
//!
//! Spec: §13.2 (connection binding — the first envelope MUST be a verified
//! `hello`; the relay answers with its own signed `hello` echoing the client
//! id; unbound connections receive no session traffic and close after 10 s;
//! no silent drops on a live connection — refusals are signed `error`s),
//! §12.7 rules 3 and 6 (leg tracking, per-leg cancel, attempt outcome, legs
//! added mid-attempt — all via `dsip_session::Relay`), §13.3 (store-and-forward:
//! envelopes for known-but-offline recipients are held until
//! `min(expires_at, offline_retention_s)` and flushed on the next `hello`;
//! never-seen recipients get `transport.unknown-recipient` — spec-gap 17),
//! §19.4 (introductions: mandatory per-sender and per-inbox rate limits; unknown
//! and offline recipients treated identically — Impl, spec-gap 14).
//!
//! Envelopes are forwarded as the exact text frames received (§10.2: the
//! signature covers the bytes; a relay never re-serializes).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::{version_block, Supported};
use dsip_broadcast::Authority;
use dsip_session::fork::{RelayAction, RelayEvent};
use dsip_session::{Emission, Message, Relay};
use dsip_transport::conn::ws_config;
use dsip_transport::verify::{verify_frame, Inbound, SeenIds};
use dsip_transport::{now_s, tls, HELLO_TIMEOUT_S};

mod www;

#[derive(Parser)]
#[command(name = "dsip-relay", version, about = "DSIP relay (ws/1.0, forking with leg tracking, store-and-forward within the §13.3 boundary)")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// State directory (relay key seed, self-signed cert/key).
    #[arg(long, default_value = ".dsip-relay")]
    state: PathBuf,
    /// Extra hostnames for the self-signed certificate.
    #[arg(long)]
    host: Vec<String>,
    /// Introductions allowed per sender identity and per recipient inbox within --intro-window (§19.4 mandatory rate limit).
    #[arg(long, default_value_t = 5)]
    intro_limit: usize,
    /// Rate-limit window in seconds.
    #[arg(long, default_value_t = 3600)]
    intro_window: i64,
    /// Maximum queued envelopes per recipient (§13.3 store-and-forward boundary).
    #[arg(long, default_value_t = 100)]
    inbox_cap: usize,
    /// Maximum seconds an envelope is held for an offline recipient (advertised as offline_retention_s).
    #[arg(long, default_value_t = 86_400)]
    offline_retention: i64,
    /// Serve static files from this directory on the same TLS port (browser demo; one origin, one cert).
    #[arg(long)]
    www: Option<PathBuf>,
}

type Tx = mpsc::UnboundedSender<String>;

struct State {
    key: KeyPair,
    supported: Supported,
    resolver: StaticResolver,
    seen: SeenIds,
    devices: HashMap<String, Tx>,
    identities: HashMap<String, HashSet<String>>,
    tracker: Relay,
    /// Per (session, leg): the leg's reject frame, forwarded if chosen as the attempt outcome.
    reject_frames: HashMap<(String, String), String>,
    /// Per session: the initiator device connection.
    initiators: HashMap<String, String>,
    /// Every verified frame within the retention window, by envelope id (served for queued deliveries).
    frames: HashMap<String, (String, i64)>,
    /// §19.4 rate limiting: key (sender identity or recipient) → recent introduction times.
    intro_log: HashMap<String, Vec<i64>>,
    intro_limit: usize,
    intro_window: i64,
    inbox_cap: usize,
    offline_retention: i64,
    /// §9.3/§22: this relay is the authority for identities bound to it.
    authority: Authority,
    /// Publication record frames by publication id (notify bodies carry them for third-party verification).
    records: HashMap<String, String>,
    /// Provenance statement frames by publication id (statements reference a specific record, §22.3).
    statements: HashMap<String, Vec<String>>,
}

impl State {
    /// Act on authority emissions: sign and deliver notifies/rejects.
    fn apply_authority(&mut self, em: Vec<Value>) {
        for e in em {
            if let Some(send) = e.get("send") {
                let to = send["to"].as_str().unwrap_or("").to_string();
                let now = now_s();
                let mut p = json!({
                    "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [dsip_broadcast::PROFILE], "extensions": [], "critical": []},
                    "type": send["type"], "id": Ulid::generate().as_str(), "from": self.key.did(), "to": to,
                    "issued_at": now, "expires_at": now + 30,
                });
                if send["type"] == "notify" {
                    let mut body = send["body"].clone();
                    // Impl (spec-gap 21): the record and provenance statements ride in the body so the
                    // subscriber can verify the publisher independently of this relay (§9.3 RECOMMENDED).
                    if let Some(pid) = body["publication"].as_str().map(String::from) {
                        if let Some(f) = self.records.get(&pid) {
                            body["record"] = f.clone().into();
                        }
                        if let Some(st) = self.statements.get(&pid) {
                            body["statements"] = json!(st);
                        }
                    }
                    p["subscription"] = send["subscription"].clone();
                    p["seq"] = send["seq"].clone();
                    p["state"] = send["state"].clone();
                    if let Some(r) = send.get("reason") {
                        p["reason"] = r.clone();
                    }
                    p["body"] = body;
                } else {
                    p["session"] = send["session"].clone();
                    p["reason"] = send["reason"].clone();
                }
                let f = sign(&p, &self.key, &self.key.kid()).frame();
                self.deliver(&to, &f);
            } else {
                tracing::info!("authority: {e}");
            }
        }
    }

    fn error_frame(&self, to: &str, reason: &str, in_reply_to: Option<&str>, session: Option<&str>, detail: Option<&str>) -> String {
        let now = now_s();
        let mut p = json!({
            "dsip": version_block(&self.supported, &[]), "type": "error", "id": Ulid::generate().as_str(),
            "from": self.key.did(), "to": to, "reason": reason, "issued_at": now, "expires_at": now + 30,
        });
        if let Some(i) = in_reply_to {
            p["in_reply_to"] = i.into();
        }
        if let Some(s) = session {
            p["session"] = s.into();
        }
        if let Some(d) = detail {
            p["detail"] = d.into();
        }
        sign(&p, &self.key, &self.key.kid()).frame()
    }

    fn deliver(&self, device: &str, frame: &str) -> bool {
        match self.devices.get(device) {
            Some(tx) => tx.send(frame.to_string()).is_ok(),
            None => false,
        }
    }

    /// §19.4: sliding-window rate limit; returns seconds until a slot frees, or 0 if allowed (and records it).
    fn intro_rate(&mut self, key: &str) -> i64 {
        let now = now_s();
        let log = self.intro_log.entry(key.to_string()).or_default();
        log.retain(|t| *t + self.intro_window > now);
        if log.len() >= self.intro_limit {
            return log[0] + self.intro_window - now;
        }
        log.push(now);
        0
    }

    /// Advance the tracker's clock to now (expires queues) and forget frames past retention.
    fn tick(&mut self) -> Vec<Emission> {
        let now = now_s();
        self.frames.retain(|_, (_, deadline)| *deadline > now);
        let delta = now - self.tracker.now;
        if delta > 0 {
            self.tracker.step(&RelayEvent::Advance { advance: delta })
        } else {
            vec![]
        }
    }

    /// Act on tracker emissions for a frame that just arrived (or `None` on bind/advance).
    fn apply(&mut self, em: Vec<Emission>, sender: Option<&str>, inbound: Option<&Inbound>, sid: &str) {
        for e in em {
            match e {
                Emission::Deliver { leg, msg_type, id: Some(id), .. } => {
                    // A queued envelope, or an invite for a leg added mid-attempt: served from the frame store.
                    if let Some((frame, _)) = self.frames.get(&id).cloned() {
                        tracing::info!("deliver stored {msg_type} {id} → {leg}");
                        self.deliver(&leg, &frame);
                    }
                }
                Emission::Deliver { leg, msg_type, id: None, .. } => {
                    if let Some(inb) = inbound {
                        tracing::info!("{msg_type} {sid} → leg {leg}");
                        self.deliver(&leg, &inb.frame);
                    }
                }
                Emission::Forward { msg_type, from, .. } => {
                    let Some(initiator) = self.tracker.attempt_initiator(sid).map(String::from) else { continue };
                    if msg_type == "reject" {
                        // §12.7 rule 6: forward the most informative leg's reject as the attempt outcome
                        if let Some(f) = self.reject_frames.get(&(sid.to_string(), from.clone())).cloned() {
                            tracing::info!("attempt {sid} outcome: reject from {from}");
                            self.deliver(&initiator, &f);
                        }
                    } else if let Some(inb) = inbound {
                        self.deliver(&initiator, &inb.frame);
                    }
                }
                Emission::Queue { to, msg_type } => tracing::info!("queued {msg_type} for {to} (§13.3)"),
                Emission::Dequeue { to, msg_type, why } => tracing::info!("dequeued {msg_type} for {to}: {why}"),
                Emission::Send(m) if m.msg_type == "error" => {
                    if let Some(s) = sender {
                        let f = self.error_frame(s, m.reason.as_deref().unwrap_or("transport.routing-refused"), m.in_reply_to.as_deref(), None, None);
                        self.deliver(s, &f);
                    }
                }
                Emission::Drop(why) => tracing::info!("dropped on {sid}: {why}"),
                _ => {}
            }
        }
    }

    /// Route one verified frame from `sender` (a bound device) acting for `sender_identity`.
    fn route(&mut self, sender: &str, sender_identity: &str, inbound: &Inbound) {
        let p = &inbound.verified.payload;
        let t = inbound.verified.msg_type().to_string();
        let id = p["id"].as_str().unwrap_or("").to_string();
        let to = p["to"].as_str().unwrap_or("").to_string();
        let Some(msg) = Message::from_payload(p) else { return };
        let sid = msg.session_id().to_string();
        let _ = self.tick();

        if t == "introduction" {
            // §19.4: relays MUST rate-limit introductions per sender identity and per recipient inbox.
            let wait = self.intro_rate(&format!("from:{sender_identity}")).max(self.intro_rate(&format!("to:{to}")));
            if wait > 0 {
                let mut f = self.error_frame(sender, "policy.rate-limited", Some(&id), None, None);
                if let Ok(mut env) = Envelope::from_frame(&f) {
                    if let Some(mut payload) = dsip_core::b64::decode(&env.payload).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
                        payload["retry_after"] = wait.into();
                        env = sign(&payload, &self.key, &self.key.kid());
                        f = env.frame();
                    }
                }
                self.deliver(sender, &f);
                return;
            }
        }
        // Inbox cap (§13.3 boundary): refuse when the recipient's queue is full.
        if self.tracker.legs_for(&to).is_empty() && self.tracker.inbox.get(&to).map(|q| q.len()).unwrap_or(0) >= self.inbox_cap {
            if t != "introduction" {
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some("recipient inbox full"));
                self.deliver(sender, &f);
            }
            return;
        }
        // Keep the frame within retention so queued deliveries and mid-attempt legs can be served.
        let deadline = p["expires_at"].as_i64().unwrap_or(now_s()).min(now_s() + self.offline_retention);
        self.frames.insert(id.clone(), (inbound.frame.clone(), deadline));
        if t == "invite" {
            self.initiators.insert(sid.clone(), sender.to_string());
        }
        if t == "reject" && self.tracker.attempt_initiator(&sid).is_some_and(|i| i != sender) {
            self.reject_frames.insert((sid.clone(), sender.to_string()), inbound.frame.clone());
        }
        if matches!(t.as_str(), "publish" | "unpublish" | "subscribe" | "provenance") {
            // §9.3/§22: addressed to this relay as the target's authority (publish/unpublish carry no `to`).
            if t == "subscribe" && to != self.key.did() {
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some("subscribe must address this relay"));
                self.deliver(sender, &f);
                return;
            }
            let mut m = p.clone();
            m["from"] = sender.into();
            self.authority.learn_identity(sender, sender_identity);
            if t == "publish" {
                self.records.insert(id.clone(), inbound.frame.clone());
            }
            if t == "provenance" {
                self.statements.entry(p["original_publication"].as_str().unwrap_or("").to_string()).or_default().push(inbound.frame.clone());
            }
            let _ = self.authority.advance_to(now_s());
            let em = self.authority.recv_value(&m);
            self.apply_authority(em);
            return;
        }
        let em = self.tracker.step(&RelayEvent::Recv { recv: msg });
        self.apply(em, Some(sender), Some(inbound), &sid);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    ).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.state)?;

    // Relay identity: a did:key from a persisted seed. Spec §7.2 recommends did:web for relays;
    // Impl: did:key keeps the local demo free of DNS/Web PKI; a did:web document can wrap this key.
    let seed_path = args.state.join("relay.key");
    let key = if seed_path.exists() {
        let hex = std::fs::read_to_string(&seed_path)?;
        let mut seed = [0u8; 32];
        for (i, c) in hex.trim().as_bytes().chunks(2).enumerate().take(32) {
            seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
        }
        KeyPair::from_seed(seed)
    } else {
        let k = KeyPair::generate();
        std::fs::write(&seed_path, k.seed().iter().map(|b| format!("{b:02x}")).collect::<String>())?;
        k
    };
    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    hosts.extend(args.host.iter().cloned());
    let (cert, keyfile) = tls::ensure_self_signed(&args.state, &hosts)?;
    let acceptor = tls::acceptor(&cert, &keyfile)?;

    tracing::info!("relay did: {}", key.did());
    tracing::info!("listening on wss://{}/dsip  (clients: --ca {})", args.listen, cert.display());

    let state = Arc::new(Mutex::new(State {
        key,
        supported: Supported::all_known(),
        resolver: StaticResolver::default(),
        seen: SeenIds::default(),
        devices: HashMap::new(),
        identities: HashMap::new(),
        tracker: Relay::with_retention(now_s(), args.offline_retention),
        reject_frames: HashMap::new(),
        initiators: HashMap::new(),
        frames: HashMap::new(),
        intro_log: HashMap::new(),
        intro_limit: args.intro_limit,
        intro_window: args.intro_window,
        inbox_cap: args.inbox_cap,
        offline_retention: args.offline_retention,
        authority: Authority::new(now_s(), HashMap::new()),
        records: HashMap::new(),
        statements: HashMap::new(),
    }));

    if let Some(w) = &args.www {
        tracing::info!("serving {} at https://{}/", w.display(), args.listen);
    }
    let www = args.www.clone();
    let listener = TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        let www = www.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => match www::dispatch(tls_stream, www.as_deref()).await {
                    Ok(www::First::WebSocket(stream)) => {
                        if let Err(e) = serve(stream, peer, state).await {
                            tracing::info!("{peer}: {e}");
                        }
                    }
                    Ok(www::First::Served) => {}
                    Err(e) => tracing::info!("{peer}: {e}"),
                },
                Err(e) => tracing::info!("{peer}: TLS handshake failed: {e}"),
            }
        });
    }
}

async fn serve(
    stream: www::Prefixed<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config())).await?;

    // --- hello phase (§13.2): first envelope, within HELLO_TIMEOUT_S
    let first = match tokio::time::timeout(Duration::from_secs(HELLO_TIMEOUT_S), ws.next()).await {
        Ok(Some(Ok(WsMessage::Text(t)))) => t.to_string(),
        Ok(Some(Ok(_))) | Ok(None) => anyhow::bail!("no hello"),
        Ok(Some(Err(e))) => return Err(e.into()),
        Err(_) => {
            let _ = ws.close(None).await;
            anyhow::bail!("no hello within {HELLO_TIMEOUT_S} s")
        }
    };
    let (device, identity, hello_id) = {
        let mut st = state.lock().await;
        let sem = dsip_schema::SemanticContext { supported: st.supported.clone(), ..Default::default() };
        let State { resolver, seen, .. } = &mut *st;
        match verify_frame(&first, now_s(), resolver, &[], seen, &sem) {
            Ok(inb) if inb.verified.msg_type() == "hello" && inb.verified.payload.get("in_reply_to").is_none() => {
                let p = &inb.verified.payload;
                (inb.verified.signer_did.clone(), inb.verified.identity.clone(), p["id"].as_str().unwrap_or("").to_string())
            }
            Ok(inb) => {
                let to = inb.verified.signer_did.clone();
                let f = st.error_frame(&to, "transport.hello-required", Some(inb.verified.payload["id"].as_str().unwrap_or("")), None, None);
                let _ = ws.send(WsMessage::Text(f.into())).await;
                let _ = ws.close(None).await;
                anyhow::bail!("first envelope was {} not a client hello", inb.verified.msg_type());
            }
            Err(v) => {
                // We cannot address the sender before verification; close with the reason in the close frame.
                let _ = ws
                    .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                        reason: format!("transport.hello-rejected: {:?}", v.code).into(),
                    }))
                    .await;
                anyhow::bail!("hello rejected: {:?} {}", v.code, v.detail.unwrap_or_default());
            }
        }
    };

    // --- bind and answer with the relay hello
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut st = state.lock().await;
        if st.devices.insert(device.clone(), tx).is_some() {
            // §13.2: a new verified hello from an already-bound device replaces the prior connection
            tracing::info!("{peer}: rebinding {device} (replacing prior connection)");
        }
        st.identities.entry(identity.clone()).or_default().insert(device.clone());
        let now = now_s();
        let hello = json!({
            "dsip": version_block(&st.supported, &[]), "type": "hello", "id": Ulid::generate().as_str(),
            "in_reply_to": hello_id, "from": st.key.did(),
            "capabilities": {"max_envelope_bytes": dsip_core::WS_MAX_ENVELOPE_BYTES, "store_and_forward": true,
                             "offline_retention_s": st.offline_retention,
                             "rate_limit": {"envelopes_per_minute": 600, "invites_per_minute": 30}},
            "issued_at": now, "expires_at": now + 30,
        });
        let env: Envelope = sign(&hello, &st.key, &st.key.kid());
        ws.send(WsMessage::Text(env.frame().into())).await?;
        tracing::info!("{peer}: bound device {device} for identity {identity}");
        // §13.3: binding flushes the store-and-forward queues and adds this device as a leg to live attempts (§12.7 rule 3)
        let _ = st.tick();
        let em = st.tracker.step(&RelayEvent::Relay(RelayAction::Bind { device: device.clone(), identity: identity.clone() }));
        st.apply(em, None, None, "");
        let _ = st.authority.advance_to(now_s());
        let em = st.authority.step(&dsip_broadcast::AuthorityEvent::Relay(dsip_broadcast::authority::Binding::Bind { device: device.clone(), identity: identity.clone() }));
        st.apply_authority(em);
    }

    // --- steady state
    let result: Result<()> = async {
        loop {
            tokio::select! {
                inbound = ws.next() => match inbound {
                    Some(Ok(WsMessage::Text(t))) => {
                        let mut st = state.lock().await;
                        let sem = dsip_schema::SemanticContext { supported: st.supported.clone(), ..Default::default() };
                        let verdict = {
                            let State { resolver, seen, .. } = &mut *st;
                            verify_frame(&t, now_s(), resolver, &[], seen, &sem)
                        };
                        match verdict {
                            Ok(inb) => {
                                if inb.verified.msg_type() == "hello" {
                                    tracing::info!("{peer}: re-hello ignored (binding unchanged)");
                                } else if inb.verified.signer_did != device {
                                    let f = st.error_frame(&device, "transport.routing-refused", Some(inb.verified.payload["id"].as_str().unwrap_or("")), None, Some("signer is not the bound device"));
                                    st.deliver(&device, &f);
                                } else {
                                    st.route(&device, &identity, &inb);
                                }
                            }
                            Err(v) => {
                                // §13.2: no silent drops on a live connection
                                // A verdict that names a reason token (e.g. `policy.subscription-lifetime`, §9.3 v0.7) is
                                // answered with that token; otherwise the generic routing refusal.
                                let f = st.error_frame(&device, v.reason.unwrap_or("transport.routing-refused"), None, None, Some(&format!("{:?}", v.code)));
                                st.deliver(&device, &f);
                            }
                        }
                    }
                    Some(Ok(WsMessage::Ping(p))) => ws.send(WsMessage::Pong(p)).await?,
                    Some(Ok(WsMessage::Pong(_))) => {}
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(_)) => {
                        let _ = ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported,
                            reason: "text frames only".into() })).await;
                        break;
                    }
                    Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                        // §13.2: oversize → close 1009
                        let _ = ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                            reason: "transport.envelope-too-large".into() })).await;
                        break;
                    }
                    Some(Err(e)) => return Err(e.into()),
                },
                outbound = rx.recv() => match outbound {
                    Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                    None => break,
                },
            }
        }
        Ok(())
    }
    .await;

    let mut st = state.lock().await;
    st.devices.remove(&device);
    if let Some(set) = st.identities.get_mut(&identity) {
        set.remove(&device);
    }
    let _ = st.tracker.step(&RelayEvent::Relay(RelayAction::Unbind { device: device.clone(), identity: identity.clone() }));
    if !st.identities.get(&identity).is_some_and(|s| !s.is_empty()) {
        let em = st.authority.step(&dsip_broadcast::AuthorityEvent::Relay(dsip_broadcast::authority::Binding::Unbind { device: device.clone(), identity: identity.clone() }));
        st.apply_authority(em);
    }
    tracing::info!("{peer}: unbound {device}");
    result
}
