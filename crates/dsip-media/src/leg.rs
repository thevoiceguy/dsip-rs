//! One media leg: a WebRTC peer connection with a single audio track.
//!
//! Spec: §14.1 (sending starts only when the host says the session is
//! ACTIVE), §12.12 (local candidates are surfaced as [`MediaEvent::Candidate`]
//! in the DSIP `info.data.candidates` shape), §14.2 (offer/answer), §12.8
//! (re-offers for renegotiation reuse the same leg).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::io::ogg_reader::OggReader;
use webrtc::media::io::ogg_writer::OggWriter;
use webrtc::media::io::Writer;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::source::{Source, ToneEncoder, FRAME_DURATION};

/// An ICE candidate in the DSIP `info.data.candidates[]` shape (§12.12 example).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    /// `candidate:` attribute value.
    pub candidate: String,
    /// SDP mid.
    #[serde(default)]
    pub sdp_mid: Option<String>,
    /// m-line index.
    #[serde(default)]
    pub sdp_m_line_index: Option<u16>,
}

/// Leg configuration.
#[derive(Debug, Clone)]
pub struct MediaConfig {
    /// What to transmit.
    pub source: Source,
    /// Record inbound audio to this Ogg/Opus file.
    pub record: Option<PathBuf>,
    /// STUN servers (empty for loopback demos).
    pub stun: Vec<String>,
}

/// Events from the leg to its host.
#[derive(Debug, Clone)]
pub enum MediaEvent {
    /// A local candidate (`None` = end of candidates).
    Candidate(Option<Candidate>),
    /// Peer connection state changed.
    State(String),
    /// First inbound RTP packet decoded/recorded.
    FirstPacket,
}

/// Counters.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    /// Inbound RTP packets.
    pub packets_in: u64,
    /// Inbound RTP payload bytes.
    pub bytes_in: u64,
    /// Outbound Opus frames.
    pub frames_out: u64,
}

/// A peer connection with one audio track.
pub struct MediaLeg {
    pc: Arc<RTCPeerConnection>,
    track: Option<Arc<TrackLocalStaticSample>>,
    source: Source,
    events: mpsc::UnboundedReceiver<MediaEvent>,
    packets_in: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    frames_out: Arc<AtomicU64>,
    sending: Arc<AtomicBool>,
}

impl MediaLeg {
    /// Build the peer connection and local track; nothing is sent until [`MediaLeg::start_sending`].
    pub async fn new(cfg: MediaConfig) -> Result<MediaLeg> {
        let mut me = MediaEngine::default();
        me.register_default_codecs().context("codecs")?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut me).context("interceptors")?;
        let api = APIBuilder::new().with_media_engine(me).with_interceptor_registry(registry).build();
        let config = RTCConfiguration {
            ice_servers: if cfg.stun.is_empty() { vec![] } else { vec![RTCIceServer { urls: cfg.stun.clone(), ..Default::default() }] },
            ..Default::default()
        };
        let pc = Arc::new(api.new_peer_connection(config).await.context("peer connection")?);
        let (tx, events) = mpsc::unbounded_channel();

        // Local track (or a recvonly transceiver for screening / receive-only legs)
        let track = if cfg.source == Source::None {
            pc.add_transceiver_from_kind(
                RTPCodecType::Audio,
                Some(RTCRtpTransceiverInit { direction: RTCRtpTransceiverDirection::Recvonly, send_encodings: vec![] }),
            )
            .await
            .context("recvonly transceiver")?;
            None
        } else {
            let t = Arc::new(TrackLocalStaticSample::new(
                RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.to_owned(), clock_rate: 48_000, channels: 1, ..Default::default() },
                "audio".to_owned(),
                "dsip".to_owned(),
            ));
            let sender = pc.add_track(Arc::clone(&t) as Arc<dyn TrackLocal + Send + Sync>).await.context("add track")?;
            // Drain RTCP for the sender so the interceptors keep working.
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1500];
                while sender.read(&mut buf).await.is_ok() {}
            });
            Some(t)
        };

        // Trickle-out: hand each candidate to the host (it sends them in signed `info` once ACTIVE).
        let ctx = tx.clone();
        pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let ctx = ctx.clone();
            Box::pin(async move {
                let ev = match c {
                    Some(c) => match c.to_json() {
                        Ok(j) => MediaEvent::Candidate(Some(Candidate { candidate: j.candidate, sdp_mid: j.sdp_mid, sdp_m_line_index: j.sdp_mline_index })),
                        Err(_) => return,
                    },
                    None => MediaEvent::Candidate(None),
                };
                let _ = ctx.send(ev);
            })
        }));
        let stx = tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            let _ = stx.send(MediaEvent::State(s.to_string()));
            Box::pin(async {})
        }));

        // Inbound: count packets and optionally record to Ogg.
        let packets_in = Arc::new(AtomicU64::new(0));
        let bytes_in = Arc::new(AtomicU64::new(0));
        let (pi, bi, record, ftx) = (packets_in.clone(), bytes_in.clone(), cfg.record.clone(), tx.clone());
        pc.on_track(Box::new(move |track, _receiver, _transceiver| {
            let (pi, bi, record, ftx) = (pi.clone(), bi.clone(), record.clone(), ftx.clone());
            Box::pin(async move {
                let mime = track.codec().capability.mime_type.to_lowercase();
                tracing::info!("inbound track {mime}");
                let mut writer: Option<OggWriter<std::fs::File>> = match &record {
                    Some(p) if mime.contains("opus") => std::fs::File::create(p).ok().and_then(|f| OggWriter::new(f, 48_000, 1).ok()),
                    _ => None,
                };
                let mut first = true;
                while let Ok((pkt, _)) = track.read_rtp().await {
                    if first {
                        first = false;
                        let _ = ftx.send(MediaEvent::FirstPacket);
                    }
                    pi.fetch_add(1, Ordering::Relaxed);
                    bi.fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                    if let Some(w) = writer.as_mut() {
                        let _ = w.write_rtp(&pkt);
                    }
                }
                if let Some(mut w) = writer.take() {
                    let _ = w.close();
                }
            })
        }));

        Ok(MediaLeg {
            pc,
            track,
            source: cfg.source,
            events,
            packets_in,
            bytes_in,
            frames_out: Arc::new(AtomicU64::new(0)),
            sending: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Add a local audio track to a leg that was created receive-only (screening → user escalation,
    /// §14.4 step 3); the next [`MediaLeg::create_offer`] re-offers `sendrecv`. No-op if a track exists.
    pub async fn add_source(&mut self, source: Source) -> Result<()> {
        if self.track.is_some() || source == Source::None {
            return Ok(());
        }
        let t = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.to_owned(), clock_rate: 48_000, channels: 1, ..Default::default() },
            "audio".to_owned(),
            "dsip".to_owned(),
        ));
        let sender = self.pc.add_track(Arc::clone(&t) as Arc<dyn TrackLocal + Send + Sync>).await.context("add track")?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while sender.read(&mut buf).await.is_ok() {}
        });
        self.track = Some(t);
        self.source = source;
        self.sending.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Create an SDP offer (also used for re-offers, §12.8).
    pub async fn create_offer(&self) -> Result<String> {
        let offer = self.pc.create_offer(None).await.context("create offer")?;
        let sdp = offer.sdp.clone();
        self.pc.set_local_description(offer).await.context("set local")?;
        Ok(sdp)
    }

    /// Apply a remote offer and produce the SDP answer.
    pub async fn accept_offer(&self, sdp: &str) -> Result<String> {
        self.pc.set_remote_description(RTCSessionDescription::offer(sdp.to_string())?).await.context("set remote offer")?;
        let answer = self.pc.create_answer(None).await.context("create answer")?;
        let out = answer.sdp.clone();
        self.pc.set_local_description(answer).await.context("set local answer")?;
        Ok(out)
    }

    /// Apply the remote answer.
    pub async fn set_answer(&self, sdp: &str) -> Result<()> {
        self.pc.set_remote_description(RTCSessionDescription::answer(sdp.to_string())?).await.context("set remote answer")
    }

    /// Add a remote candidate (from a verified `info`).
    pub async fn add_remote_candidate(&self, c: &Candidate) -> Result<()> {
        self.pc
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: c.candidate.clone(),
                sdp_mid: c.sdp_mid.clone(),
                sdp_mline_index: c.sdp_m_line_index,
                username_fragment: None,
            })
            .await
            .context("add candidate")
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
        let Some(track) = self.track.clone() else { return };
        let frames = self.frames_out.clone();
        let sending = self.sending.clone();
        match self.source.clone() {
            Source::None => {}
            Source::Tone { hz } => {
                tokio::spawn(async move {
                    let mut enc = match ToneEncoder::new(hz) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!("tone encoder: {e}");
                            return;
                        }
                    };
                    let mut tick = tokio::time::interval(FRAME_DURATION);
                    while sending.load(Ordering::SeqCst) {
                        tick.tick().await;
                        let Ok(data) = enc.next_frame() else { break };
                        if track.write_sample(&Sample { data, duration: FRAME_DURATION, ..Default::default() }).await.is_err() {
                            break;
                        }
                        frames.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            Source::File(path) => {
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(FRAME_DURATION);
                    while sending.load(Ordering::SeqCst) {
                        let Ok(f) = std::fs::File::open(&path) else {
                            tracing::warn!("cannot open {}", path.display());
                            return;
                        };
                        let Ok((mut reader, _header)) = OggReader::new(std::io::BufReader::new(f), true) else {
                            tracing::warn!("{} is not an Ogg/Opus file", path.display());
                            return;
                        };
                        while sending.load(Ordering::SeqCst) {
                            let Ok((page, _)) = reader.parse_next_page() else { break };
                            tick.tick().await;
                            if track.write_sample(&Sample { data: page.freeze(), duration: FRAME_DURATION, ..Default::default() }).await.is_err() {
                                return;
                            }
                            frames.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
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
        let _ = self.pc.close().await;
    }
}
