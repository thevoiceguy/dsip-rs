//! G2 round trip, in-process and deterministic: a DSIP caller (forge media, 440 Hz tone) reaches
//! the gateway, the gateway dials a SIP UAS peer (standing in for siphond) over real UDP, the peer
//! answers with G.711, and audio crosses the gateway's Opus⇄G.711 bridge — proven by the peer
//! receiving transcoded RTP.
//!
//! No relay, no external processes: real SIP on the wire, real forge DTLS-SRTP on the DSIP side,
//! the real `GatewayCall` controller mediating, real transcoding. DTMF crosses both ways (G§9, spec-gap 70):
//! as SIP INFO dtmf-relay when the trunk offered no `telephone-event`, as RFC 4733 RTP events when it did.
#![cfg(feature = "host")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dsip_gateway::controller::GatewayCall;
use dsip_gateway::host::dsip_leg::DsipMedia;
use dsip_gateway::host::call::send_dtmf;
use dsip_gateway::host::media::{bridge, telephone_event_of, DtmfEvent, RtpLeg};
use dsip_gateway::host::sip_leg::{local_sdp, RemoteRtp, SipEvent, SipLeg, TELEPHONE_EVENT_PT};
use forge_webrtc::{IceCandidate, PeerConnection, PeerEvent};
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// One RFC 4733 event packet as the trunk saw it: (event, end, duration, marker).
type EventPacket = (u8, bool, u16, bool);

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
    /// RFC 4733 event packets received.
    events_in: Arc<Mutex<Vec<EventPacket>>>,
    /// Whether our SDP answer offers telephone-event (payload type 101).
    telephone_event: bool,
}

impl SipPeer {
    async fn spawn(telephone_event: bool) -> (Arc<SipPeer>, u16) {
        let peer = Arc::new(SipPeer {
            sip: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            rtp: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            rtp_in: Arc::new(AtomicU64::new(0)),
            info_in: Arc::new(Mutex::new(vec![])),
            info_status: Arc::new(AtomicU64::new(0)),
            invite: Arc::new(Mutex::new(None)),
            events_in: Arc::new(Mutex::new(vec![])),
            telephone_event,
        });
        let port = peer.sip.local_addr().unwrap().port();
        let (rtp, rtp_in, events_in) = (peer.rtp.clone(), peer.rtp_in.clone(), peer.events_in.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = rtp.recv_from(&mut buf).await {
                if n >= 12 && buf[1] & 0x7f == TELEPHONE_EVENT_PT {
                    // an RFC 4733 event: record it, never echo it (a trunk plays it, it does not send it back)
                    if let Some((code, end, dur)) = telephone_event_of(&buf[12..n]) {
                        events_in.lock().unwrap().push((code, end, dur, buf[1] & 0x80 != 0));
                    }
                    continue;
                }
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
                    let te = if p.telephone_event { format!(" {TELEPHONE_EVENT_PT}") } else { String::new() };
                    let te_attr = if p.telephone_event { format!("a=rtpmap:{TELEPHONE_EVENT_PT} telephone-event/8000\r\na=fmtp:{TELEPHONE_EVENT_PT} 0-15\r\n") } else { String::new() };
                    let sdp = format!("v=0\r\no=peer 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {rp} RTP/AVP 0{te}\r\na=rtpmap:0 PCMU/8000\r\n{te_attr}a=sendrecv\r\n");
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

/// A connected DSIP→PSTN call with audio proven across the bridge, ready for DTMF.
struct Live {
    peer: Arc<SipPeer>,
    peer_port: u16,
    sip: Arc<SipLeg>,
    sip_rx: mpsc::Receiver<SipEvent>,
    rtp: Arc<RtpLeg>,
    remote: RemoteRtp,
    caller: PeerConnection,
    gw: DsipMedia,
    call_id: String,
    ctrl: GatewayCall,
    dtmf_rx: mpsc::UnboundedReceiver<DtmfEvent>,
}

async fn live_call(telephone_event: bool) -> Live {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (peer, peer_port) = SipPeer::spawn(telephone_event).await;
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
    let remote = remote.unwrap();
    assert_eq!(remote.telephone_event, telephone_event.then_some(TELEPHONE_EVENT_PT), "SDP parse of telephone-event");
    rtp.set_remote(remote.addr).await;
    let emits = ctrl.step(&json!({"sip": {"status": 200, "sdp": true}}));
    assert!(emits.iter().any(|e| e["dsip"]["local"] == "accept" && e["dsip"]["answered_by"] == "gateway"), "{emits:?}");
    assert!(emits.iter().any(|e| e["media"] == "bridge"));

    // Bridge: gateway inbound Opus → G.711 → peer; peer echo → Opus → caller.
    let sender = gw.sender().unwrap();
    let (dtmf_tx, dtmf_rx) = mpsc::unbounded_channel();
    let bridge_rtp = rtp.clone();
    tokio::spawn(async move { let _ = bridge(rtp_in_rx, sender, bridge_rtp, false, remote_te(telephone_event), Some(dtmf_tx)).await; });

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

    Live { peer, peer_port, sip, sip_rx, rtp, remote, caller, gw, call_id, ctrl, dtmf_rx }
}

fn remote_te(negotiated: bool) -> Option<u8> {
    negotiated.then_some(TELEPHONE_EVENT_PT)
}

async fn hang_up(mut live: Live) {
    // BYE both ways.
    assert!(live.ctrl.step(&json!({"dsip": {"type": "bye", "reason": "user.hangup"}})).iter().any(|e| e["sip"]["request"] == "BYE"));
    live.sip.bye(&live.call_id, Some(16), "user.hangup").await.unwrap();
    live.caller.close();
    live.gw.close();
}

#[tokio::test]
async fn dsip_caller_reaches_sip_peer_with_transcoded_audio_and_dtmf_as_info() {
    let mut live = live_call(false).await;
    let Live { peer, peer_port, sip, sip_rx, rtp, remote, call_id, ctrl, .. } = &mut live;
    let _ = rtp;

    // DTMF, DSIP → PSTN: the controller maps the signed `info` to INFO; the leg puts one dtmf-relay per digit on
    // the wire, CSeq increasing (G§9, spec-gap 70).
    let emits = ctrl.step(&json!({"dsip": {"type": "info", "about": "media:dtmf", "data": {"digits": "12#"}}}));
    assert_eq!(emits, vec![json!({"sip": {"request": "INFO", "dtmf": "12#"}})]);
    send_dtmf(sip, Some(rtp), Some(remote), call_id, "12#", None).await.unwrap();
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
        *peer_port, hval(&invite_msg, "To"), hval(&invite_msg, "From"), hval(&invite_msg, "Call-ID")
    );
    peer.sip.send_to(info.as_bytes(), gw_addr).await.unwrap();
    let mut got = None;
    let d4 = tokio::time::Instant::now() + Duration::from_secs(5);
    while got.is_none() {
        if let Ok(Some(SipEvent::Info { call_id: cid, digits, duration_ms })) = tokio::time::timeout(Duration::from_millis(500), sip_rx.recv()).await {
            assert_eq!(&cid, call_id);
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
    assert!(peer.events_in.lock().unwrap().is_empty(), "no telephone-event negotiated: nothing rides RTP");

    hang_up(live).await;
}

#[tokio::test]
async fn dtmf_as_rfc4733_events_when_the_trunk_negotiated_telephone_event() {
    let mut live = live_call(true).await;
    let Live { peer, sip, rtp, remote, call_id, ctrl, dtmf_rx, .. } = &mut live;

    // DSIP → PSTN: the same controller emission, carried as RTP events because the trunk offered telephone-event
    // (G§9): per digit a marked start packet, updates, and the end packet three times, at the full duration.
    let emits = ctrl.step(&json!({"dsip": {"type": "info", "about": "media:dtmf", "data": {"digits": "12#", "duration_ms": 100}}}));
    assert_eq!(emits, vec![json!({"sip": {"request": "INFO", "dtmf": "12#", "duration_ms": 100}})]);
    send_dtmf(sip, Some(rtp), Some(remote), call_id, "12#", Some(100)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = peer.events_in.lock().unwrap().clone();
    let ended: Vec<(u8, u16)> = events.iter().filter(|(_, end, _, _)| *end).map(|(c, _, d, _)| (*c, *d)).collect();
    assert_eq!(ended, [(1, 800); 3].iter().chain([(2, 800); 3].iter()).chain([(11, 800); 3].iter()).copied().collect::<Vec<_>>(), "{events:?}");
    assert_eq!(events.iter().filter(|(_, _, _, marker)| *marker).count(), 3, "one marked start per digit: {events:?}");
    assert!(events.iter().any(|(c, end, d, _)| *c == 1 && !*end && *d < 800), "updates before the end: {events:?}");
    assert!(peer.info_in.lock().unwrap().is_empty(), "telephone-event negotiated: no INFO on the wire");

    // PSTN → DSIP: the trunk sends an RFC 4733 event for '5' (start, updates, end ×3); the bridge reports it once,
    // and the controller maps it to a DSIP info about media:dtmf with nothing to answer on the SIP leg.
    let gw_rtp = std::net::SocketAddr::from(([127, 0, 0, 1], rtp.port()));
    let ts = 123_456u32;
    let mut seq = 500u16;
    let mut send = |code: u8, end: bool, dur: u16, marker: bool| {
        let payload = Bytes::from(vec![code, if end { 0x8a } else { 0x0a }, (dur >> 8) as u8, dur as u8]);
        let pkt = forge_rtp::rtp::RtpPacket::build(TELEPHONE_EVENT_PT, seq, ts, 0xabcd, payload, marker);
        seq = seq.wrapping_add(1);
        pkt.to_bytes()
    };
    let mut packets = vec![send(5, false, 160, true), send(5, false, 320, false), send(5, false, 480, false)];
    packets.extend([send(5, true, 1280, false), send(5, true, 1280, false), send(5, true, 1280, false)]);
    for p in packets {
        peer.rtp.send_to(&p, gw_rtp).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let ev = tokio::time::timeout(Duration::from_secs(5), dtmf_rx.recv()).await.expect("the bridge reports the event").unwrap();
    assert_eq!(ev, DtmfEvent { digits: "5".into(), duration_ms: 160 });
    assert!(tokio::time::timeout(Duration::from_millis(300), dtmf_rx.recv()).await.is_err(), "the end packet's retransmissions report nothing more");
    let emits = ctrl.step(&json!({"sip": {"event": "dtmf", "dtmf": ev.digits, "duration_ms": ev.duration_ms}}));
    assert_eq!(emits, vec![json!({"dsip": {"local": "info", "about": "media:dtmf", "data": {"digits": "5", "duration_ms": 160}}})]);

    hang_up(live).await;
}
