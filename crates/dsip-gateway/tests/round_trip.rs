//! G2 round trip, in-process and deterministic: a DSIP caller (forge media, 440 Hz tone) reaches
//! the gateway, the gateway dials a SIP UAS peer (standing in for siphond) over real UDP, the peer
//! answers with G.711, and audio crosses the gateway's Opus⇄G.711 bridge — proven by the peer
//! receiving transcoded RTP.
//!
//! No relay, no external processes: real SIP on the wire, real forge DTLS-SRTP on the DSIP side,
//! the real `GatewayCall` controller mediating, real transcoding. DTMF crosses both ways as SIP INFO
//! dtmf-relay ⇄ DSIP `info` about `media:dtmf` (G§9, spec-gap 70).
#![cfg(feature = "host")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dsip_gateway::controller::GatewayCall;
use dsip_gateway::host::dsip_leg::DsipMedia;
use dsip_gateway::host::media::{bridge, RtpLeg};
use dsip_gateway::host::sip_leg::{local_sdp, SipEvent, SipLeg};
use forge_webrtc::{IceCandidate, PeerConnection, PeerEvent};
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct SipPeer {
    sip: Arc<UdpSocket>,
    rtp: Arc<UdpSocket>,
    rtp_in: Arc<AtomicU64>,
    /// INFO requests received: (CSeq header, body).
    info_in: Arc<Mutex<Vec<(String, String)>>>,
    /// Status of the last response to an INFO we sent.
    info_status: Arc<AtomicU64>,
    /// The INVITE we answered and where it came from, for in-dialog requests of our own.
    invite: Arc<Mutex<Option<(String, std::net::SocketAddr)>>>,
}

impl SipPeer {
    async fn spawn() -> (Arc<SipPeer>, u16) {
        let peer = Arc::new(SipPeer {
            sip: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            rtp: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            rtp_in: Arc::new(AtomicU64::new(0)),
            info_in: Arc::new(Mutex::new(vec![])),
            info_status: Arc::new(AtomicU64::new(0)),
            invite: Arc::new(Mutex::new(None)),
        });
        let port = peer.sip.local_addr().unwrap().port();
        let (rtp, rtp_in) = (peer.rtp.clone(), peer.rtp_in.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = rtp.recv_from(&mut buf).await {
                rtp_in.fetch_add(1, Ordering::Relaxed);
                let _ = rtp.send_to(&buf[..n], from).await; // echo (a real trunk sources its own)
            }
        });
        let p = peer.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = p.sip.recv_from(&mut buf).await {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = msg.lines().next().unwrap_or("");
                if first.starts_with("INVITE") {
                    *p.invite.lock().unwrap() = Some((msg.clone(), from));
                    let h = copy_headers(&msg);
                    let _ = p.sip.send_to(status(&h, 100, "Trying").as_bytes(), from).await;
                    let rp = p.rtp.local_addr().unwrap().port();
                    let sdp = format!("v=0\r\no=peer 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {rp} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n");
                    let ok = format!("{}Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}", ok_headers(&h), sdp.len(), sdp);
                    let _ = p.sip.send_to(ok.as_bytes(), from).await;
                } else if first.starts_with("BYE") || first.starts_with("CANCEL") {
                    let _ = p.sip.send_to(status(&copy_headers(&msg), 200, "OK").as_bytes(), from).await;
                } else if first.starts_with("INFO") {
                    let body = msg.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default();
                    p.info_in.lock().unwrap().push((hval(&msg, "CSeq"), body));
                    let _ = p.sip.send_to(status(&copy_headers(&msg), 200, "OK").as_bytes(), from).await;
                } else if first.starts_with("SIP/2.0") && hval(&msg, "CSeq").ends_with("INFO") {
                    let code: u64 = first.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
                    p.info_status.store(code, Ordering::SeqCst);
                }
            }
        });
        (peer, port)
    }
}

fn hval(msg: &str, name: &str) -> String {
    msg.lines().find(|l| l.to_ascii_lowercase().starts_with(&format!("{}:", name.to_ascii_lowercase())))
        .and_then(|l| l.split_once(':')).map(|x| x.1.trim().to_string()).unwrap_or_default()
}
fn copy_headers(msg: &str) -> Vec<(String, String)> {
    ["Via", "From", "To", "Call-ID", "CSeq"].iter().map(|h| (h.to_string(), hval(msg, h))).collect()
}
fn status(h: &[(String, String)], code: u16, reason: &str) -> String {
    let mut s = format!("SIP/2.0 {code} {reason}\r\n");
    for (k, v) in h { s += &format!("{k}: {v}\r\n"); }
    s + "Content-Length: 0\r\n\r\n"
}
fn ok_headers(h: &[(String, String)]) -> String {
    let mut s = "SIP/2.0 200 OK\r\n".to_string();
    for (k, v) in h {
        let v = if k == "To" && !v.contains("tag=") { format!("{v};tag=peer") } else { v.clone() };
        s += &format!("{k}: {v}\r\n");
    }
    s + "Contact: <sip:peer@127.0.0.1>\r\n"
}

/// One long-lived pump per peer connection: forward local candidates to `cand_out`, forward inbound
/// RTP payloads to `rtp_out`, and report the first `Connected`.
fn pump(
    mut ev: mpsc::Receiver<PeerEvent>,
    cand_out: mpsc::UnboundedSender<IceCandidate>,
    rtp_out: Option<mpsc::UnboundedSender<Bytes>>,
    connected: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        while let Some(e) = ev.recv().await {
            match e {
                PeerEvent::LocalCandidate(c) => { let _ = cand_out.send(c); }
                PeerEvent::Connected => connected.store(1, Ordering::SeqCst),
                PeerEvent::Rtp(p) => { if let Some(tx) = &rtp_out { let _ = tx.send(p.payload.clone()); } }
                _ => {}
            }
        }
    });
}

#[tokio::test]
async fn dsip_caller_reaches_sip_peer_with_transcoded_audio() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (peer, peer_port) = SipPeer::spawn().await;
    let (sip, mut sip_rx) = SipLeg::new("127.0.0.1:0".parse().unwrap(), "127.0.0.1", "gateway").await.unwrap();
    let rtp = RtpLeg::bind("127.0.0.1", 0, 0x1234).await.unwrap();

    // DSIP media: caller (offerer, tone) ↔ gateway leg (answerer). Connect in-process.
    let mut caller = PeerConnection::with_config(forge_webrtc::PeerConfig::default()).await.unwrap();
    let mut gw = DsipMedia::new().await.unwrap();
    let offer = caller.create_offer().await.unwrap();
    let answer = gw.answer(&offer).await.unwrap();
    caller.set_remote_answer(&answer).await.unwrap();

    let (caller_cand_tx, mut caller_cand_rx) = mpsc::unbounded_channel();
    let (gw_cand_tx, mut gw_cand_rx) = mpsc::unbounded_channel();
    let (rtp_in_tx, rtp_in_rx) = mpsc::unbounded_channel::<Bytes>(); // gateway's inbound Opus → bridge
    let caller_up = Arc::new(AtomicU64::new(0));
    let gw_up = Arc::new(AtomicU64::new(0));
    pump(caller.take_events().unwrap(), caller_cand_tx, None, caller_up.clone());
    pump(gw.take_events().unwrap(), gw_cand_tx, Some(rtp_in_tx), gw_up.clone());

    // Trickle candidates until both report Connected.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while caller_up.load(Ordering::SeqCst) == 0 || gw_up.load(Ordering::SeqCst) == 0 {
        tokio::select! {
            Some(c) = caller_cand_rx.recv() => { gw.add_candidate(&c.to_sdp_attribute()).await.ok(); }
            Some(c) = gw_cand_rx.recv() => { caller.add_ice_candidate(c).await.ok(); }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        assert!(tokio::time::Instant::now() < deadline, "DSIP media never connected");
    }

    // Controller drives the real legs (outbound: DSIP → PSTN).
    let mut ctrl = GatewayCall::new(&json!({"direction": "outbound"}));
    assert_eq!(ctrl.step(&json!({"dsip": {"type": "invite"}})), vec![json!({"sip": "INVITE"})]);
    let g711 = local_sdp("127.0.0.1", rtp.port(), "sendrecv");
    let call_id = sip.invite(&format!("sip:+15551234567@127.0.0.1:{peer_port}"), &g711).await.unwrap();

    // Await the peer's 200; learn its RTP endpoint.
    let mut remote = None;
    let d2 = tokio::time::Instant::now() + Duration::from_secs(5);
    while remote.is_none() {
        if let Ok(Some(SipEvent::Response { status, remote: r, .. })) = tokio::time::timeout(Duration::from_millis(500), sip_rx.recv()).await {
            if (200..300).contains(&status) { remote = r; }
        }
        assert!(tokio::time::Instant::now() < d2, "no 200 from the SIP peer");
    }
    rtp.set_remote(remote.unwrap().addr).await;
    let emits = ctrl.step(&json!({"sip": {"status": 200, "sdp": true}}));
    assert!(emits.iter().any(|e| e["dsip"]["local"] == "accept" && e["dsip"]["answered_by"] == "gateway"), "{emits:?}");
    assert!(emits.iter().any(|e| e["media"] == "bridge"));

    // Bridge: gateway inbound Opus → G.711 → peer; peer echo → Opus → caller.
    let sender = gw.sender().unwrap();
    tokio::spawn(async move { let _ = bridge(rtp_in_rx, sender, rtp, false).await; });

    // Caller sources a 440 Hz Opus tone for ~0.8 s.
    let caller_send = caller.sender().unwrap();
    let enc = audiopus::coder::Encoder::new(audiopus::SampleRate::Hz48000, audiopus::Channels::Mono, audiopus::Application::Voip).unwrap();
    let (mut phase, step) = (0f32, 440.0 * 2.0 * std::f32::consts::PI / 48000.0);
    let (mut pcm, mut out) = (vec![0i16; 960], vec![0u8; 4000]);
    for _ in 0..40 {
        for s in pcm.iter_mut() { *s = (phase.sin() * 8000.0) as i16; phase += step; if phase > std::f32::consts::TAU { phase -= std::f32::consts::TAU; } }
        let n = enc.encode(&pcm, &mut out).unwrap();
        caller_send.send_audio(Bytes::copy_from_slice(&out[..n]), 960).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let at_peer = peer.rtp_in.load(Ordering::Relaxed);
    assert!(at_peer >= 10, "SIP peer should have received transcoded G.711 RTP through the gateway, got {at_peer}");

    // DTMF, DSIP → PSTN: the controller maps the signed `info` to INFO; the leg puts one dtmf-relay per digit on
    // the wire, CSeq increasing (G§9, spec-gap 70).
    let emits = ctrl.step(&json!({"dsip": {"type": "info", "about": "media:dtmf", "data": {"digits": "12#"}}}));
    assert_eq!(emits, vec![json!({"sip": {"request": "INFO", "dtmf": "12#"}})]);
    sip.info_dtmf(&call_id, "12#", None).await.unwrap();
    let d3 = tokio::time::Instant::now() + Duration::from_secs(5);
    while peer.info_in.lock().unwrap().len() < 3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tokio::time::Instant::now() < d3, "SIP peer should have received three INFOs, got {:?}", peer.info_in.lock().unwrap());
    }
    let infos = peer.info_in.lock().unwrap().clone();
    let signals: Vec<String> = infos.iter().map(|(_, b)| dsip_gateway::host::sip_leg::dtmf_relay_of(b).unwrap().0).collect();
    assert_eq!(signals, ["1", "2", "#"]);
    assert!(infos.iter().all(|(_, b)| b.contains("Duration=160")), "{infos:?}");
    let cseqs: Vec<u32> = infos.iter().map(|(c, _)| c.split_whitespace().next().unwrap().parse().unwrap()).collect();
    assert!(cseqs.windows(2).all(|w| w[1] > w[0]), "INFO CSeqs must increase: {cseqs:?}");

    // DTMF, PSTN → DSIP: the peer sends INFO dtmf-relay in the dialog; the leg answers 200 and reports it; the
    // controller maps it to a DSIP `info` about media:dtmf.
    let (invite_msg, gw_addr) = peer.invite.lock().unwrap().clone().unwrap();
    let info = format!(
        "INFO sip:gateway@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK-peer-info\r\nFrom: {};tag=peer\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 1 INFO\r\nMax-Forwards: 70\r\nContent-Type: application/dtmf-relay\r\nContent-Length: 24\r\n\r\nSignal=5\r\nDuration=160\r\n",
        peer_port, hval(&invite_msg, "To"), hval(&invite_msg, "From"), hval(&invite_msg, "Call-ID")
    );
    peer.sip.send_to(info.as_bytes(), gw_addr).await.unwrap();
    let mut got = None;
    let d4 = tokio::time::Instant::now() + Duration::from_secs(5);
    while got.is_none() {
        if let Ok(Some(SipEvent::Info { call_id: cid, digits, duration_ms })) = tokio::time::timeout(Duration::from_millis(500), sip_rx.recv()).await {
            assert_eq!(cid, call_id);
            got = Some((digits, duration_ms));
        }
        assert!(tokio::time::Instant::now() < d4, "the leg should have reported the peer's INFO");
    }
    let (digits, duration_ms) = got.unwrap();
    assert_eq!((digits.as_str(), duration_ms), ("5", Some(160)));
    let emits = ctrl.step(&json!({"sip": {"request": "INFO", "dtmf": digits, "duration_ms": 160}}));
    assert!(emits.iter().any(|e| e["dsip"]["local"] == "info" && e["dsip"]["about"] == "media:dtmf" && e["dsip"]["data"]["digits"] == "5"), "{emits:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(peer.info_status.load(Ordering::SeqCst), 200, "the leg answers dtmf-relay INFO with 200");

    // BYE both ways.
    assert!(ctrl.step(&json!({"dsip": {"type": "bye", "reason": "user.hangup"}})).iter().any(|e| e["sip"]["request"] == "BYE"));
    sip.bye(&call_id, Some(16), "user.hangup").await.unwrap();
    caller.close();
    gw.close();
}
