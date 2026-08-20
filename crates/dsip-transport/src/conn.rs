//! A client `ws/1.0` connection: dial, `hello` exchange, framed send/receive.
//!
//! Spec: §13.2 — connections are client-initiated over `wss`; the first
//! envelope MUST be a `hello`; the relay's `hello` MUST echo our id in
//! `in_reply_to` (close on mismatch, §20.5) and carry `capabilities` with
//! `max_envelope_bytes = 65536`; one envelope per text frame; frames over
//! 65,536 bytes are rejected (close 1009); Ping/Pong keepalive.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use dsip_core::did::Resolver;
use dsip_core::envelope::{sign_bytes, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::Supported;
use dsip_core::WS_MAX_ENVELOPE_BYTES;
use dsip_schema::SemanticContext;

use crate::verify::{verify_frame, SeenIds};
use crate::{now_s, BINDING, PING_IDLE_S};

/// WebSocket configuration enforcing the §13.2 size cap at the framing layer.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_ENVELOPE_BYTES))
        .max_frame_size(Some(WS_MAX_ENVELOPE_BYTES))
}

/// What we learned from the relay's `hello`.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Relay identity DID (from the verified `hello`).
    pub did: String,
    /// Advertised capabilities object.
    pub capabilities: Value,
}

/// Parameters for dialing a relay.
pub struct ConnectParams<'a> {
    /// `wss://host:port/path`.
    pub url: String,
    /// Explicit trust anchor (self-signed relay); `None` = native roots.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Device key that signs `hello` and all session messages.
    pub device: &'a KeyPair,
    /// Identity the device acts for (`on_behalf_of`), if different from the device.
    pub on_behalf_of: Option<String>,
    /// Delegations to present inline in the `hello` header (so the relay can verify `on_behalf_of`).
    pub delegations: Vec<Envelope>,
    /// Supported versions.
    pub supported: Supported,
}

/// A bound client connection.
pub struct Connection {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Relay identity and capabilities.
    pub relay: RelayInfo,
    last_activity: std::time::Instant,
}

impl Connection {
    /// Dial, send `hello`, verify the relay's `hello`. Fails closed on any binding error.
    pub async fn connect(p: &ConnectParams<'_>, resolver: &dyn Resolver, seen: &mut SeenIds) -> Result<Connection> {
        if !p.url.starts_with("wss://") {
            bail!("ws/1.0 requires a wss:// URL (spec §13.2); refusing {}", p.url);
        }
        let connector = p.tls.clone().map(Connector::Rustls);
        let (mut ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(p.url.as_str(), Some(ws_config()), false, connector)
                .await
                .with_context(|| format!("connecting to {}", p.url))?;

        // Client hello (§13.2)
        let now = now_s();
        let id = Ulid::generate();
        let mut hello = json!({
            "dsip": dsip_core::version::version_block(&p.supported, &[]),
            "type": "hello", "id": id.as_str(), "from": p.device.did(),
            "bindings": [BINDING], "issued_at": now, "expires_at": now + 30,
        });
        if let Some(obo) = &p.on_behalf_of {
            hello["on_behalf_of"] = obo.clone().into();
        }
        let env = sign_bytes(&serde_json::to_vec(&hello)?, p.device, &p.device.kid(), p.delegations.clone());
        ws.send(WsMessage::Text(env.frame().into())).await?;

        // Relay hello: first text frame, verified, bound via in_reply_to (§20.5)
        let frame = loop {
            match tokio::time::timeout(Duration::from_secs(crate::HELLO_TIMEOUT_S), ws.next()).await {
                Ok(Some(Ok(WsMessage::Text(t)))) => break t.to_string(),
                Ok(Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_)))) => continue,
                Ok(Some(Ok(WsMessage::Close(c)))) => bail!("relay closed during hello: {c:?}"),
                Ok(Some(Ok(_))) => bail!("relay sent a non-text frame during hello"),
                Ok(Some(Err(e))) => return Err(e.into()),
                Ok(None) => bail!("connection ended during hello"),
                Err(_) => bail!("no relay hello within {} s", crate::HELLO_TIMEOUT_S),
            }
        };
        let sem = SemanticContext { supported: p.supported.clone(), sent_hello_id: Some(id.to_string()), ..Default::default() };
        let inbound = verify_frame(&frame, now_s(), resolver, &[], seen, &sem).map_err(|v| {
            anyhow!("relay hello rejected: {:?} ({})", v.code, v.detail.unwrap_or_default())
        })?;
        if inbound.verified.msg_type() != "hello" {
            let _ = ws.close(None).await;
            bail!("first frame from relay was {}, not hello", inbound.verified.msg_type());
        }
        // The schema enforces relay form (in_reply_to ⇔ capabilities, max_envelope_bytes const).
        let caps = inbound.verified.payload["capabilities"].clone();
        Ok(Connection {
            ws,
            relay: RelayInfo { did: inbound.verified.identity.clone(), capabilities: caps },
            last_activity: std::time::Instant::now(),
        })
    }

    /// Send one envelope as one text frame. Enforces the size cap before sending.
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let frame = env.frame();
        if frame.len() > WS_MAX_ENVELOPE_BYTES {
            bail!("envelope is {} bytes; ws/1.0 cap is {}", frame.len(), WS_MAX_ENVELOPE_BYTES);
        }
        self.ws.send(WsMessage::Text(frame.into())).await?;
        self.last_activity = std::time::Instant::now();
        Ok(())
    }

    /// Receive the next text frame (handles Ping/Pong and idle keepalive). `None` when closed.
    pub async fn recv(&mut self) -> Result<Option<String>> {
        loop {
            let idle = Duration::from_secs(PING_IDLE_S).saturating_sub(self.last_activity.elapsed());
            tokio::select! {
                msg = self.ws.next() => match msg {
                    Some(Ok(WsMessage::Text(t))) => {
                        self.last_activity = std::time::Instant::now();
                        if t.len() > WS_MAX_ENVELOPE_BYTES {
                            self.close(CloseCode::Size, "envelope too large").await;
                            bail!("peer sent an oversize frame");
                        }
                        return Ok(Some(t.to_string()));
                    }
                    Some(Ok(WsMessage::Binary(_))) => {
                        // §13.2: text frames only
                        self.close(CloseCode::Unsupported, "text frames only").await;
                        bail!("peer sent a binary frame");
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_))) => {
                        self.last_activity = std::time::Instant::now();
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
                    Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                        self.close(CloseCode::Size, "envelope too large").await;
                        bail!("peer sent an oversize frame");
                    }
                    Some(Err(e)) => return Err(e.into()),
                },
                _ = tokio::time::sleep(idle) => {
                    self.ws.send(WsMessage::Ping(Vec::new().into())).await?;
                    self.last_activity = std::time::Instant::now();
                }
            }
        }
    }

    /// Close with a status code.
    pub async fn close(&mut self, code: CloseCode, reason: &str) {
        let _ = self.ws.close(Some(CloseFrame { code, reason: reason.to_string().into() })).await;
    }
}
