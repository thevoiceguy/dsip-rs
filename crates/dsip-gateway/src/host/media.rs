//! Media bridge: one forge-webrtc peer connection (DSIP side, Opus over DTLS-SRTP) and one plain
//! RTP socket (SIP side, G.711 8 kHz), transcoded frame by frame.
//!
//! Spec: §14.1 (media flows only once both sides are up), §17.1 (Opus), §17.2 (encryption floor
//! on the DSIP side; the SIP side's plain RTP is the §6.3 downgrade this gateway names). Impl:
//! Opus decode → 48 kHz PCM → naive 6:1 decimate → G.711 encode, and the reverse with 1:6
//! sample-hold; round one favours simplicity over resampler quality.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use forge_codecs::g711;
use forge_rtp::rtp::RtpPacket;
use forge_webrtc::AudioSender;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// PCM sample-rate hop between Opus (48 kHz) and G.711 (8 kHz).
const DECIMATE: usize = 6;

/// The SIP-side RTP endpoint (plain RTP, symmetric-latching to where packets come from).
pub struct RtpLeg {
    socket: Arc<UdpSocket>,
    remote: Arc<Mutex<Option<SocketAddr>>>,
    payload_type: u8, // 0 = PCMU, 8 = PCMA
    seq: AtomicU16,
    ts: AtomicU32,
    ssrc: u32,
}

impl RtpLeg {
    /// Bind an RTP socket on `bind_ip:0`.
    pub async fn bind(bind_ip: &str, payload_type: u8, ssrc: u32) -> Result<Arc<RtpLeg>> {
        let socket = Arc::new(UdpSocket::bind(format!("{bind_ip}:0")).await.context("bind rtp")?);
        Ok(Arc::new(RtpLeg {
            socket,
            remote: Arc::new(Mutex::new(None)),
            payload_type,
            seq: AtomicU16::new(0),
            ts: AtomicU32::new(0),
            ssrc,
        }))
    }

    /// Local RTP port.
    pub fn port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Set the remote RTP address (from the trunk's SDP).
    pub async fn set_remote(&self, addr: SocketAddr) {
        *self.remote.lock().await = Some(addr);
    }

    /// Send one 20 ms G.711 frame (160 bytes).
    pub async fn send(&self, g711_payload: Bytes) -> Result<()> {
        let Some(to) = *self.remote.lock().await else { return Ok(()) };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts = self.ts.fetch_add(160, Ordering::Relaxed);
        let pkt = RtpPacket::build(self.payload_type, seq, ts, self.ssrc, g711_payload, seq == 0);
        self.socket.send_to(&pkt.to_bytes(), to).await?;
        Ok(())
    }
}

/// Start the two transcoding pumps for a connected call. Returns when either side closes.
///
/// - DSIP→SIP: forge `PeerEvent::Rtp` (Opus) → decode → decimate → G.711 → RTP to the trunk.
/// - SIP→DSIP: RTP from the trunk → G.711 decode → upsample → Opus encode → `AudioSender`.
pub async fn bridge(
    mut dsip_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>, // decoded Opus payloads from the DSIP leg
    dsip_tx: AudioSender,
    rtp: Arc<RtpLeg>,
    pcma: bool,
) -> Result<()> {
    // SIP → DSIP: read RTP, learn the remote, decode G.711, upsample, Opus-encode, send.
    let rtp_in = rtp.clone();
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let enc = match audiopus::coder::Encoder::new(audiopus::SampleRate::Hz48000, audiopus::Channels::Mono, audiopus::Application::Voip) {
            Ok(e) => e,
            Err(e) => { debug!("opus enc: {e}"); return; }
        };
        let mut out = vec![0u8; 4000];
        loop {
            let Ok((n, from)) = rtp_in.socket.recv_from(&mut buf).await else { break };
            rtp_in.set_remote(from).await;
            let Ok(pkt) = RtpPacket::parse(Bytes::copy_from_slice(&buf[..n])) else { continue };
            let mut pcm48 = Vec::with_capacity(pkt.payload.len() * DECIMATE);
            for &b in pkt.payload.iter() {
                let s = if pcma { g711::decode_alaw(b) } else { g711::decode_ulaw(b) };
                for _ in 0..DECIMATE { pcm48.push(s); } // 1:6 sample-hold 8k→48k
            }
            if let Ok(len) = enc.encode(&pcm48, &mut out) {
                let _ = dsip_tx.send_audio(Bytes::copy_from_slice(&out[..len]), pcm48.len() as u32).await;
            }
        }
    });
    // DSIP → SIP: decode Opus, decimate, G.711-encode, RTP out.
    let send = tokio::spawn(async move {
        let mut dec = match audiopus::coder::Decoder::new(audiopus::SampleRate::Hz48000, audiopus::Channels::Mono) {
            Ok(d) => d,
            Err(e) => { debug!("opus dec: {e}"); return; }
        };
        let mut pcm48 = vec![0i16; 5760];
        while let Some(opus) = dsip_rx.recv().await {
            let sig = audiopus::packet::Packet::try_from(opus.as_ref());
            let Ok(sig) = sig else { continue };
            let out = audiopus::MutSignals::try_from(&mut pcm48[..]);
            let Ok(out) = out else { continue };
            let Ok(n) = dec.decode(Some(sig), out, false) else { continue };
            let mut g = Vec::with_capacity(n / DECIMATE);
            let mut i = 0;
            while i < n { // decimate 48k→8k
                let s = pcm48[i];
                g.push(if pcma { g711::encode_alaw(s) } else { g711::encode_ulaw(s) });
                i += DECIMATE;
            }
            if !g.is_empty() {
                let _ = rtp.send(Bytes::from(g)).await;
            }
            trace!("dsip→sip {} samples → {} g711 bytes", n, n / DECIMATE);
        }
    });
    let _ = tokio::try_join!(recv, send);
    Ok(())
}
