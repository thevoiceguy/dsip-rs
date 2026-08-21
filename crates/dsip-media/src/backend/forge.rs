//! The forge-media backend: `forge-webrtc` 0.3's endpoint-shaped
//! `PeerConnection` (the project's own stack; `impl/docs/forge-media-plan.md`).
//!
//! Spec: see `leg` — this module satisfies that surface with forge. The
//! mapping is one-to-one with the WebRTC Media Binding draft, Appendix C:
//! answerer role (`set_remote_offer` + `create_answer`, DTLS role from
//! `a=setup`), trickle-out (`PeerEvent::LocalCandidate` → [`MediaEvent::Candidate`],
//! `GatheringComplete` → `Candidate(None)`), single-leg media
//! (`AudioSender::send_audio` / `PeerEvent::Rtp`), re-offer on the same
//! transport (`create_offer` after `Connected`; a screening leg starts
//! `RecvOnly` and [`ForgeLeg::add_source`] switches it to `SendRecv`).
//!
//! Impl: `PeerConnection` methods take `&mut self`, so it sits behind a tokio
//! mutex; the event pump is spawned on the first offer/answer (that is when
//! forge creates its transport and event channel).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use forge_webrtc::{Direction, PeerConfig, PeerConnection, PeerEvent};
use tokio::sync::{mpsc, Mutex};

use crate::leg::{Candidate, MediaConfig, MediaEvent, Stats};
use crate::ogg::{rtp_packet, Recorder};
use crate::source::{self, Source, FRAME_SAMPLES};

/// A forge peer connection with one audio track.
pub struct ForgeLeg {
    pc: Arc<Mutex<PeerConnection>>,
    source: Source,
    record: Option<PathBuf>,
    events_tx: mpsc::UnboundedSender<MediaEvent>,
    events: mpsc::UnboundedReceiver<MediaEvent>,
    pump_started: AtomicBool,
    packets_in: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    frames_out: Arc<AtomicU64>,
    sending: Arc<AtomicBool>,
}

impl ForgeLeg {
    /// Build the peer connection; nothing is sent until [`ForgeLeg::start_sending`].
    pub async fn new(cfg: MediaConfig) -> Result<ForgeLeg> {
        let direction = if cfg.source == Source::None { Direction::RecvOnly } else { Direction::SendRecv };
        let pc = PeerConnection::with_config(PeerConfig {
            stun_servers: cfg.stun.clone(),
            direction,
            opus_pt: 111,
            dtmf: false,
            ..PeerConfig::default()
        })
        .await
        .context("forge peer connection")?;
        let (events_tx, events) = mpsc::unbounded_channel();
        Ok(ForgeLeg {
            pc: Arc::new(Mutex::new(pc)),
            source: cfg.source,
            record: cfg.record,
            events_tx,
            events,
            pump_started: AtomicBool::new(false),
            packets_in: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            frames_out: Arc::new(AtomicU64::new(0)),
            sending: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Forward forge events to the host once the transport exists.
    async fn ensure_pump(&self) {
        if self.pump_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(mut rx) = self.pc.lock().await.take_events() else {
            self.pump_started.store(false, Ordering::SeqCst);
            return;
        };
        let (tx, pi, bi, record) = (self.events_tx.clone(), self.packets_in.clone(), self.bytes_in.clone(), self.record.clone());
        tokio::spawn(async move {
            let mut rec: Option<Recorder> = None;
            let mut first = true;
            while let Some(ev) = rx.recv().await {
                match ev {
                    PeerEvent::LocalCandidate(c) => {
                        // forge emits the `candidate:` attribute form; BUNDLE means one section, mid 0.
                        let _ = tx.send(MediaEvent::Candidate(Some(Candidate {
                            candidate: c.to_sdp_attribute(),
                            sdp_mid: Some("0".into()),
                            sdp_m_line_index: Some(0),
                        })));
                    }
                    PeerEvent::GatheringComplete => {
                        let _ = tx.send(MediaEvent::Candidate(None));
                    }
                    PeerEvent::IceConnected { local, remote } => {
                        let _ = tx.send(MediaEvent::State(format!("ice connected {local} ↔ {remote}")));
                    }
                    PeerEvent::Connected => {
                        let _ = tx.send(MediaEvent::State("connected".into()));
                    }
                    PeerEvent::Failed(why) => {
                        let _ = tx.send(MediaEvent::State(format!("failed: {why}")));
                    }
                    PeerEvent::Closed => {
                        let _ = tx.send(MediaEvent::State("closed".into()));
                        break;
                    }
                    PeerEvent::Rtp(pkt) => {
                        if first {
                            first = false;
                            rec = record.as_deref().and_then(Recorder::open);
                            let _ = tx.send(MediaEvent::FirstPacket);
                        }
                        pi.fetch_add(1, Ordering::Relaxed);
                        bi.fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                        if let Some(r) = rec.as_mut() {
                            let h = &pkt.header;
                            let (seq, ts, ssrc) = (h.sequence_number, h.timestamp, h.ssrc);
                            r.write(&rtp_packet(h.payload_type(), h.marker(), seq, ts, ssrc, pkt.payload.clone()));
                        }
                    }
                    PeerEvent::Rtcp(_) => {}
                }
            }
            if let Some(mut r) = rec.take() {
                r.close();
            }
        });
    }

    /// Add a local audio source to a leg that was created receive-only (screening →
    /// user escalation, §14.4 step 3); the next [`ForgeLeg::create_offer`] re-offers
    /// `sendrecv`. No-op if a source exists.
    pub async fn add_source(&mut self, source: Source) -> Result<()> {
        if self.source != Source::None || source == Source::None {
            return Ok(());
        }
        self.pc.lock().await.set_direction(Direction::SendRecv);
        self.source = source;
        self.sending.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Create an SDP offer (also used for re-offers, §12.8).
    pub async fn create_offer(&self) -> Result<String> {
        let sdp = self.pc.lock().await.create_offer().await.context("forge create_offer")?;
        self.ensure_pump().await;
        Ok(sdp)
    }

    /// Apply a remote offer and produce the SDP answer.
    pub async fn accept_offer(&self, sdp: &str) -> Result<String> {
        let answer = {
            let mut pc = self.pc.lock().await;
            pc.set_remote_offer(sdp).await.context("forge set_remote_offer")?;
            pc.create_answer().await.context("forge create_answer")?
        };
        self.ensure_pump().await;
        Ok(answer)
    }

    /// Apply the remote answer.
    pub async fn set_answer(&self, sdp: &str) -> Result<()> {
        self.pc.lock().await.set_remote_answer(sdp).await.context("forge set_remote_answer")
    }

    /// Add a remote candidate (from a verified `info`).
    pub async fn add_remote_candidate(&self, c: &Candidate) -> Result<()> {
        self.pc.lock().await.add_ice_candidate_str(&c.candidate).await.context("forge add candidate")
    }

    /// Next leg event.
    pub async fn next_event(&mut self) -> Option<MediaEvent> {
        self.events.recv().await
    }

    /// Begin transmitting the configured source. Spec §14.1: the host calls this only once ACTIVE.
    pub fn start_sending(&self) {
        if self.sending.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.source == Source::None {
            return;
        }
        let (pc, src, sending, frames) = (self.pc.clone(), self.source.clone(), self.sending.clone(), self.frames_out.clone());
        tokio::spawn(async move {
            let sender = match pc.lock().await.sender() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("forge sender unavailable: {e}");
                    return;
                }
            };
            source::pump(src, sending, frames, move |data: Bytes| {
                let sender = sender.clone();
                // Frames offered before ICE/DTLS complete are dropped, not fatal
                // (the session is ACTIVE but the transport may still be connecting).
                Box::pin(async move {
                    if let Err(e) = sender.send_audio(data, FRAME_SAMPLES as u32).await {
                        tracing::trace!("frame dropped: {e}");
                    }
                    true
                })
            })
            .await;
        });
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        Stats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
        }
    }

    /// Stop sending and close the peer connection.
    pub async fn close(&self) {
        self.sending.store(false, Ordering::SeqCst);
        self.pc.lock().await.close();
    }
}
