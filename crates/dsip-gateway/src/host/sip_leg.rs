//! SIP leg: one UDP socket, siphon-rs `UserAgentClient`/`UserAgentServer` helpers for message
//! construction, a per-call table. Round one: UDP only, no authentication, no SRTP toward the
//! trunk (the §6.3 downgrade names it), single contact per INVITE.
//!
//! Spec: none (infrastructure) — RFC 3261 message handling; the DSIP-visible semantics are in
//! the controller.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use sip_core::{Method, Request, Response, SipUri};
use sip_dialog::Dialog;
use sip_parse::{parse_request, parse_response, serialize_request, serialize_response};
use sip_uac::UserAgentClient;
use sip_uas::UserAgentServer;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

/// What a remote SDP told us about the peer's RTP endpoint.
#[derive(Debug, Clone)]
pub struct RemoteRtp {
    /// Peer RTP address.
    pub addr: SocketAddr,
    /// Payload types offered/answered (first is preferred).
    pub payload_types: Vec<u8>,
    /// `sendrecv` | `sendonly` | `recvonly` | `inactive`.
    pub direction: String,
}

/// Parse `c=` and `m=audio` out of a trunk's SDP.
pub fn parse_remote_rtp(sdp: &str) -> Option<RemoteRtp> {
    let mut ip = None;
    let mut port = None;
    let mut pts = vec![];
    let mut direction = "sendrecv".to_string();
    for line in sdp.lines().map(|l| l.trim_end_matches('\r')) {
        if let Some(c) = line.strip_prefix("c=IN IP4 ") {
            ip = Some(c.trim().to_string());
        } else if let Some(m) = line.strip_prefix("m=audio ") {
            let parts: Vec<&str> = m.split_whitespace().collect();
            port = parts.first().and_then(|p| p.parse::<u16>().ok());
            pts = parts.iter().skip(2).filter_map(|p| p.parse::<u8>().ok()).collect();
        } else if let Some(d) = line.strip_prefix("a=") {
            if ["sendrecv", "sendonly", "recvonly", "inactive"].contains(&d) {
                direction = d.to_string();
            }
        }
    }
    let addr = format!("{}:{}", ip?, port?).parse().ok()?;
    Some(RemoteRtp { addr, payload_types: pts, direction })
}

/// Our SDP toward the trunk: G.711 µ-law/A-law, plain RTP (round one).
pub fn local_sdp(ip: &str, port: u16, direction: &str) -> String {
    format!(
        "v=0\r\no=dsip-gateway 1 1 IN IP4 {ip}\r\ns=DSIP gateway\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na={direction}\r\n"
    )
}

/// Events the SIP leg reports to the host.
#[derive(Debug)]
pub enum SipEvent {
    /// A new inbound INVITE.
    Invite {
        /// SIP Call-ID.
        call_id: String,
        /// Caller number (From user), if present.
        from_tn: String,
        /// Called number (Request-URI user).
        to_user: String,
        /// Remote SDP summary.
        remote: Option<RemoteRtp>,
        /// Raw Identity header (STIR), if any.
        identity_header: Option<String>,
    },
    /// A response to our INVITE.
    Response {
        /// SIP Call-ID.
        call_id: String,
        /// Status code.
        status: u16,
        /// Remote SDP summary if the response carried one.
        remote: Option<RemoteRtp>,
    },
    /// The peer sent BYE (answered 200 already).
    Bye {
        /// SIP Call-ID.
        call_id: String,
        /// Q.850 cause from a Reason header, if any.
        q850: Option<u32>,
    },
    /// The peer cancelled its INVITE (answered 200 + 487 already).
    Cancel {
        /// SIP Call-ID.
        call_id: String,
    },
    /// ACK for our 200.
    Ack {
        /// SIP Call-ID.
        call_id: String,
    },
}

struct SipCall {
    invite: Request,
    remote_addr: SocketAddr,
    dialog: Option<Dialog>,
    #[allow(dead_code)]
    outbound: bool,
}

/// The SIP leg.
pub struct SipLeg {
    socket: Arc<UdpSocket>,
    uac: UserAgentClient,
    uas: UserAgentServer,
    calls: Arc<Mutex<HashMap<String, SipCall>>>,
    events: mpsc::Sender<SipEvent>,
    local_ip: String,
}

impl SipLeg {
    /// Bind `listen` and start the receive loop.
    pub async fn new(listen: SocketAddr, local_ip: &str, user: &str) -> Result<(Arc<SipLeg>, mpsc::Receiver<SipEvent>)> {
        let socket = Arc::new(UdpSocket::bind(listen).await.with_context(|| format!("bind SIP {listen}"))?);
        let port = socket.local_addr()?.port();
        let local_uri = SipUri::parse(&format!("sip:{user}@{local_ip}:{port}")).map_err(|e| anyhow!("local uri: {e}"))?;
        let (events, rx) = mpsc::channel(64);
        let leg = Arc::new(SipLeg {
            socket,
            uac: UserAgentClient::new(local_uri.clone(), local_uri.clone()),
            uas: UserAgentServer::new(local_uri.clone(), local_uri),
            calls: Arc::new(Mutex::new(HashMap::new())),
            events,
            local_ip: local_ip.to_string(),
        });
        let l = leg.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = l.socket.recv_from(&mut buf).await else { continue };
                let data = Bytes::copy_from_slice(&buf[..n]);
                if let Err(e) = l.handle(data, from).await {
                    warn!("sip: {e}");
                }
            }
        });
        info!("SIP leg listening on {listen} as sip:{user}@{local_ip}:{port}");
        Ok((leg, rx))
    }

    /// Local IP advertised in SDP.
    pub fn local_ip(&self) -> &str {
        &self.local_ip
    }

    async fn send_req(&self, req: &Request, to: SocketAddr) -> Result<()> {
        self.socket.send_to(&serialize_request(req), to).await?;
        debug!("→ {} to {to}", req.method());
        Ok(())
    }

    async fn send_resp(&self, resp: &Response, to: SocketAddr) -> Result<()> {
        self.socket.send_to(&serialize_response(resp), to).await?;
        debug!("→ {} to {to}", resp.code());
        Ok(())
    }

    /// Send an INVITE; returns the Call-ID.
    pub async fn invite(&self, target: &str, sdp: &str) -> Result<String> {
        let uri = SipUri::parse(target).map_err(|e| anyhow!("target uri: {e}"))?;
        let req = self.uac.create_invite(&uri, Some(sdp));
        let call_id = header(&req, "Call-ID").unwrap_or_default();
        let addr = resolve_uri_addr(&uri)?;
        self.calls.lock().await.insert(call_id.clone(), SipCall { invite: req.clone(), remote_addr: addr, dialog: None, outbound: true });
        self.send_req(&req, addr).await?;
        Ok(call_id)
    }

    /// CANCEL an outbound INVITE.
    pub async fn cancel(&self, call_id: &str) -> Result<()> {
        let calls = self.calls.lock().await;
        let c = calls.get(call_id).ok_or_else(|| anyhow!("unknown call"))?;
        let req = cancel_for(&c.invite)?;
        self.send_req(&req, c.remote_addr).await
    }

    /// ACK a 2xx.
    pub async fn ack(&self, call_id: &str, response_status: u16) -> Result<()> {
        let calls = self.calls.lock().await;
        let c = calls.get(call_id).ok_or_else(|| anyhow!("unknown call"))?;
        let _ = response_status;
        // The last 2xx we saw is kept in the dialog; build the ACK from the INVITE + a synthetic OK.
        let Some(dialog) = &c.dialog else { return Ok(()) };
        let resp = ok_for(&c.invite, dialog)?;
        let ack = self.uac.create_ack(&c.invite, &resp, None);
        self.send_req(&ack, c.remote_addr).await
    }

    /// BYE (either role), with a Reason header.
    pub async fn bye(&self, call_id: &str, q850: Option<u32>, dsip_reason: &str) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let Some(c) = calls.remove(call_id) else { return Ok(()) };
        let Some(dialog) = &c.dialog else { return Ok(()) };
        let mut req = self.uac.create_bye(dialog);
        let mut reason = format!("DSIP;text=\"{dsip_reason}\"");
        if let Some(q) = q850 {
            reason = format!("Q.850;cause={q};text=\"{dsip_reason}\", {reason}");
        }
        req.headers_mut().push("Reason", reason).ok();
        self.send_req(&req, c.remote_addr).await
    }

    /// Provisional response to an inbound INVITE.
    pub async fn ringing(&self, call_id: &str) -> Result<()> {
        let calls = self.calls.lock().await;
        let c = calls.get(call_id).ok_or_else(|| anyhow!("unknown call"))?;
        let resp = self.uas.create_ringing(&c.invite);
        self.send_resp(&resp, c.remote_addr).await
    }

    /// 200 OK with our SDP to an inbound INVITE.
    pub async fn accept(&self, call_id: &str, sdp: &str) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let c = calls.get_mut(call_id).ok_or_else(|| anyhow!("unknown call"))?;
        let (resp, dialog) = self.uas.accept_invite(&c.invite, Some(sdp)).map_err(|e| anyhow!("accept: {e}"))?;
        c.dialog = Some(dialog);
        self.send_resp(&resp, c.remote_addr).await
    }

    /// Final non-2xx to an inbound INVITE with a Reason header.
    pub async fn reject(&self, call_id: &str, status: u16, q850: Option<u32>, dsip_reason: &str) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let Some(c) = calls.remove(call_id) else { return Ok(()) };
        let phrase = match status { 403 => "Forbidden", 404 => "Not Found", 480 => "Temporarily Unavailable", 486 => "Busy Here", 488 => "Not Acceptable Here", 500 => "Server Internal Error", 503 => "Service Unavailable", 603 => "Decline", _ => "Error" };
        let mut resp = UserAgentServer::reject_invite(&c.invite, status, phrase);
        let mut reason = format!("DSIP;text=\"{dsip_reason}\"");
        if let Some(q) = q850 {
            reason = format!("Q.850;cause={q}, {reason}");
        }
        resp.headers_mut().push("Reason", reason).ok();
        self.send_resp(&resp, c.remote_addr).await
    }

    async fn handle(&self, data: Bytes, from: SocketAddr) -> Result<()> {
        if let Some(req) = parse_request(&data) {
            let call_id = header(&req, "Call-ID").unwrap_or_default();
            match req.method() {
                m if *m == Method::Invite => {
                    let trying = UserAgentServer::create_trying(&req);
                    self.send_resp(&trying, from).await?;
                    let sdp = String::from_utf8_lossy(req.body()).to_string();
                    let from_tn = user_of(header(&req, "From").as_deref());
                    let to_user = user_of(Some(&req.uri().to_string()));
                    self.calls.lock().await.insert(call_id.clone(), SipCall { invite: req.clone(), remote_addr: from, dialog: None, outbound: false });
                    let _ = self.events.send(SipEvent::Invite { call_id, from_tn, to_user, remote: parse_remote_rtp(&sdp), identity_header: header(&req, "Identity") }).await;
                }
                m if *m == Method::Ack => {
                    let _ = self.events.send(SipEvent::Ack { call_id }).await;
                }
                m if *m == Method::Bye => {
                    let ok = self.uas.create_ok(&req, None).map_err(|e| anyhow!("ok: {e}"))?;
                    self.send_resp(&ok, from).await?;
                    self.calls.lock().await.remove(&call_id);
                    let _ = self.events.send(SipEvent::Bye { call_id, q850: q850_of(header(&req, "Reason").as_deref()) }).await;
                }
                m if *m == Method::Cancel => {
                    let ok = self.uas.create_ok(&req, None).map_err(|e| anyhow!("ok: {e}"))?;
                    self.send_resp(&ok, from).await?;
                    if let Some(c) = self.calls.lock().await.remove(&call_id) {
                        let terminated = UserAgentServer::create_request_terminated_from_cancel(&c.invite);
                        self.send_resp(&terminated, from).await?;
                    }
                    let _ = self.events.send(SipEvent::Cancel { call_id }).await;
                }
                m if *m == Method::Options => {
                    let ok = UserAgentServer::accept_options(&req);
                    self.send_resp(&ok, from).await?;
                }
                _ => {
                    let resp = UserAgentServer::create_response(&req, 501, "Not Implemented");
                    self.send_resp(&resp, from).await?;
                }
            }
        } else if let Some(resp) = parse_response(&data) {
            let call_id = resp.headers().get("Call-ID").map(String::from).unwrap_or_default();
            let status = resp.code();
            let cseq = resp.headers().get("CSeq").map(String::from).unwrap_or_default();
            if !cseq.ends_with("INVITE") {
                return Ok(()); // BYE/CANCEL responses need no action in round one
            }
            let mut calls = self.calls.lock().await;
            let Some(c) = calls.get_mut(&call_id) else { return Ok(()) };
            if (200..300).contains(&status) {
                c.dialog = self.uac.process_invite_response(&c.invite, &resp);
                let ack = self.uac.create_ack(&c.invite, &resp, None);
                let addr = c.remote_addr;
                drop(calls);
                self.send_req(&ack, addr).await?;
            } else if status >= 300 {
                drop(calls);
                self.calls.lock().await.remove(&call_id);
            } else {
                drop(calls);
            }
            let sdp = String::from_utf8_lossy(resp.body()).to_string();
            let _ = self.events.send(SipEvent::Response { call_id, status, remote: if sdp.is_empty() { None } else { parse_remote_rtp(&sdp) } }).await;
        }
        Ok(())
    }
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).map(String::from)
}

fn user_of(uri: Option<&str>) -> String {
    let s = uri.unwrap_or("");
    let s = s.split('<').nth(1).unwrap_or(s);
    let s = s.split('>').next().unwrap_or(s);
    let s = s.split(':').nth(1).unwrap_or(s);
    s.split('@').next().unwrap_or(s).split(';').next().unwrap_or("").to_string()
}

fn q850_of(reason: Option<&str>) -> Option<u32> {
    let r = reason?;
    r.split(';').find_map(|p| p.trim().strip_prefix("cause=").and_then(|c| c.parse().ok()))
}

fn resolve_uri_addr(uri: &SipUri) -> Result<SocketAddr> {
    let host = uri.host().to_string();
    let port = uri.port().unwrap_or(5060);
    format!("{host}:{port}").parse().with_context(|| format!("sip target {host}:{port} must be ip:port in round one"))
}

fn cancel_for(invite: &Request) -> Result<Request> {
    let (line, headers, _) = invite.clone().into_parts();
    let (_, uri, _version) = line.into_parts();
    let mut h = sip_core::Headers::new();
    for name in ["Via", "From", "To", "Call-ID", "Max-Forwards"] {
        if let Some(v) = headers.get(name) {
            h.push(name, v).map_err(|e| anyhow!("{e}"))?;
        }
    }
    let cseq = headers.get("CSeq").unwrap_or("1 INVITE").split_whitespace().next().unwrap_or("1").to_string();
    h.push("CSeq", format!("{cseq} CANCEL")).map_err(|e| anyhow!("{e}"))?;
    h.push("Content-Length", "0").map_err(|e| anyhow!("{e}"))?;
    Request::new(sip_core::RequestLine::new(Method::Cancel, uri), h, Bytes::new()).map_err(|e| anyhow!("{e}"))
}

fn ok_for(invite: &Request, dialog: &Dialog) -> Result<Response> {
    let mut resp = UserAgentServer::create_response(invite, 200, "OK");
    let _ = dialog;
    resp.headers_mut().set_or_push("Content-Length", "0").ok();
    Ok(resp)
}
