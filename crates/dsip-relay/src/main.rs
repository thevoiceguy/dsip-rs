//! `dsip-relay` — Phase 1 relay: `wss` listener, `hello` binding, routing, per-leg forking.
//!
//! Spec: §13.2 (connection binding — the first envelope MUST be a verified
//! `hello`; the relay answers with its own signed `hello` echoing the client
//! id; unbound connections receive no session traffic and close after 10 s;
//! no silent drops on a live connection — refusals are signed `error`s),
//! §12.7 rules 3 and 6 (leg tracking, per-leg cancel, attempt outcome via
//! `dsip_session::Relay`), §13.3 (store-and-forward only for `introduction`:
//! session traffic to unknown recipients gets `transport.unknown-recipient`),
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
use dsip_session::fork::{RelayAction, RelayEvent};
use dsip_session::{Emission, Message, Relay};
use dsip_transport::conn::ws_config;
use dsip_transport::verify::{verify_frame, Inbound, SeenIds};
use dsip_transport::{now_s, tls, HELLO_TIMEOUT_S};

#[derive(Parser)]
#[command(name = "dsip-relay", version, about = "DSIP Phase 1 relay (ws/1.0, forking, no store-and-forward)")]
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
    /// Maximum queued introductions per recipient inbox (§13.3 store-and-forward boundary).
    #[arg(long, default_value_t = 100)]
    inbox_cap: usize,
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
    /// §19.4 inbox: identity → queued (frame, expires_at). Unknown and offline identities alike.
    inbox: HashMap<String, Vec<(String, i64)>>,
    /// §19.4 rate limiting: key (sender identity or recipient) → recent introduction times.
    intro_log: HashMap<String, Vec<i64>>,
    intro_limit: usize,
    intro_window: i64,
    inbox_cap: usize,
}

impl State {
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

    fn legs_for(&self, to: &str) -> Vec<String> {
        if self.devices.contains_key(to) {
            return vec![to.to_string()];
        }
        let mut v: Vec<String> = self.identities.get(to).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        v.sort();
        v
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

    /// Deliver queued introductions to a newly bound device (§13.3 boundary).
    fn flush_inbox(&mut self, identity: &str, device: &str) {
        let now = now_s();
        if let Some(q) = self.inbox.remove(identity) {
            for (frame, exp) in q {
                if exp >= now {
                    self.deliver(device, &frame);
                }
            }
        }
    }

    /// Route one verified frame from `sender` (a bound device) acting for `sender_identity`.
    fn route(&mut self, sender: &str, sender_identity: &str, inbound: &Inbound) {
        let p = &inbound.verified.payload;
        let t = inbound.verified.msg_type().to_string();
        let id = p["id"].as_str().unwrap_or("").to_string();
        let to = p["to"].as_str().unwrap_or("").to_string();
        let session = p.get("session").and_then(Value::as_str).map(String::from);
        let Some(msg) = Message::from_payload(p) else { return };
        let sid = msg.session_id().to_string();
        let tracked = self.initiators.contains_key(&sid);

        match t.as_str() {
            "introduction" => {
                // §19.4: relays MUST rate-limit introductions per sender identity and per recipient inbox.
                let wait = self.intro_rate(&format!("from:{sender_identity}")).max(self.intro_rate(&format!("to:{to}")));
                if wait > 0 {
                    let mut f = self.error_frame(sender, "policy.rate-limited", Some(&id), None, None);
                    // retry_after rides in the signed error payload
                    if let Ok(mut env) = Envelope::from_frame(&f) {
                        if let Some(mut payload) = dsip_core::b64::decode(&env.payload)
                            .and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
                            payload["retry_after"] = wait.into();
                            env = sign(&payload, &self.key, &self.key.kid());
                            f = env.frame();
                        }
                    }
                    self.deliver(sender, &f);
                    return;
                }
                // §19.4 anti-enumeration (Impl, spec-gap 14): unknown and offline recipients are treated identically —
                // queued until the introduction expires, no routing error. Bound devices get it now.
                let legs = self.legs_for(&to);
                if legs.is_empty() {
                    let exp = p["expires_at"].as_i64().unwrap_or(now_s());
                    let q = self.inbox.entry(to.clone()).or_default();
                    q.retain(|(_, e)| *e >= now_s());
                    if q.len() < self.inbox_cap {
                        q.push((inbound.frame.clone(), exp));
                    }
                    tracing::info!("queued introduction for {to} (inbox {})", q.len());
                } else {
                    for leg in legs {
                        self.deliver(&leg, &inbound.frame);
                    }
                }
            }
            "invite" => {
                let legs = self.legs_for(&to);
                if legs.is_empty() {
                    let f = self.error_frame(sender, "transport.unknown-recipient", Some(&id), None, None);
                    self.deliver(sender, &f);
                    return;
                }
                // §12.7 rule 3: fork with leg tracking
                self.initiators.insert(sid.clone(), sender.to_string());
                let em = self.tracker.step(&RelayEvent::Relay(RelayAction::Invite {
                    session: sid.clone(),
                    from: sender.to_string(),
                    to: to.clone(),
                    legs: legs.clone(),
                }));
                for e in em {
                    if let Emission::Deliver { leg, .. } = e {
                        tracing::info!("fork invite {sid} → leg {leg}");
                        self.deliver(&leg, &inbound.frame);
                    }
                }
            }
            "cancel" if tracked && self.initiators.get(&sid) == Some(&sender.to_string()) => {
                let em = self.tracker.step(&RelayEvent::Recv { recv: msg });
                for e in em {
                    if let Emission::Deliver { leg, .. } = e {
                        tracing::info!("per-leg cancel {sid} → {leg}");
                        self.deliver(&leg, &inbound.frame);
                    }
                }
            }
            "progress" | "answer" | "reject" if tracked && self.initiators.get(&sid) != Some(&sender.to_string()) => {
                if t == "reject" {
                    self.reject_frames.insert((sid.clone(), sender.to_string()), inbound.frame.clone());
                }
                let initiator = self.initiators[&sid].clone();
                let em = self.tracker.step(&RelayEvent::Recv { recv: msg });
                for e in em {
                    match e {
                        Emission::Forward { msg_type, from, .. } if msg_type == "reject" => {
                            // §12.7 rule 6: forward the most informative leg's reject as the attempt outcome
                            if let Some(f) = self.reject_frames.get(&(sid.clone(), from.clone())).cloned() {
                                tracing::info!("attempt {sid} outcome: reject from {from}");
                                self.deliver(&initiator, &f);
                            }
                        }
                        Emission::Forward { .. } => {
                            self.deliver(&initiator, &inbound.frame);
                        }
                        Emission::Drop(why) => tracing::info!("dropped {t} from {sender} on {sid}: {why}"),
                        _ => {}
                    }
                }
            }
            _ => {
                // Plain routing by `to` (device, or every device of an identity).
                let legs = self.legs_for(&to);
                if legs.is_empty() {
                    let f = self.error_frame(sender, "transport.unknown-recipient", Some(&id), session.as_deref(), None);
                    self.deliver(sender, &f);
                    return;
                }
                for leg in legs {
                    self.deliver(&leg, &inbound.frame);
                }
            }
        }
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
        supported: Supported::default(),
        resolver: StaticResolver::default(),
        seen: SeenIds::default(),
        devices: HashMap::new(),
        identities: HashMap::new(),
        tracker: Relay::new(now_s()),
        reject_frames: HashMap::new(),
        initiators: HashMap::new(),
        inbox: HashMap::new(),
        intro_log: HashMap::new(),
        intro_limit: args.intro_limit,
        intro_window: args.intro_window,
        inbox_cap: args.inbox_cap,
    }));

    let listener = TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => {
                    if let Err(e) = serve(tls_stream, peer, state).await {
                        tracing::info!("{peer}: {e}");
                    }
                }
                Err(e) => tracing::info!("{peer}: TLS handshake failed: {e}"),
            }
        });
    }
}

async fn serve(stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, peer: SocketAddr, state: Arc<Mutex<State>>) -> Result<()> {
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
        st.flush_inbox(&identity, &device);
        st.flush_inbox(&device, &device);
        let now = now_s();
        let hello = json!({
            "dsip": version_block(&st.supported, &[]), "type": "hello", "id": Ulid::generate().as_str(),
            "in_reply_to": hello_id, "from": st.key.did(),
            "capabilities": {"max_envelope_bytes": dsip_core::WS_MAX_ENVELOPE_BYTES, "store_and_forward": false,
                             "rate_limit": {"envelopes_per_minute": 600, "invites_per_minute": 30}},
            "issued_at": now, "expires_at": now + 30,
        });
        let env: Envelope = sign(&hello, &st.key, &st.key.kid());
        ws.send(WsMessage::Text(env.frame().into())).await?;
        tracing::info!("{peer}: bound device {device} for identity {identity}");
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
                                let f = st.error_frame(&device, "transport.routing-refused", None, None, Some(&format!("{:?}", v.code)));
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
    tracing::info!("{peer}: unbound {device}");
    result
}
