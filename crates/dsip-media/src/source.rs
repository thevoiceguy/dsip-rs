//! Audio sources: a generated Opus tone, or an Ogg/Opus file.
//!
//! Spec: none (infrastructure) — what goes *into* the media path is the
//! application's business; the protocol only cares that it happens after a
//! signed answer (§14.1).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::Bytes;

/// 20 ms Opus frames at 48 kHz mono.
pub const FRAME_SAMPLES: usize = 960;
/// Frame duration.
pub const FRAME_DURATION: Duration = Duration::from_millis(20);

/// What a leg transmits.
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    /// Send nothing (receive-only leg; screening, §14.4).
    None,
    /// A continuous sine tone, encoded live with Opus.
    Tone {
        /// Frequency in Hz.
        hz: f32,
    },
    /// An Ogg/Opus file, replayed packet by packet (looped).
    File(PathBuf),
    /// Opus frames from a channel, sent as they arrive (Recording Profile C§6: a recorder leg forwards a call's
    /// media unchanged — no transcoding).
    Feed(Feed),
}

/// The receiving end of a frame channel, shareable so a [`Source`] stays `Clone`.
#[derive(Clone)]
pub struct Feed(pub Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Bytes>>>);

impl Feed {
    /// A feed and the sender that fills it.
    pub fn channel() -> (tokio::sync::mpsc::UnboundedSender<Bytes>, Feed) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (tx, Feed(Arc::new(tokio::sync::Mutex::new(rx))))
    }
}

impl PartialEq for Feed {
    fn eq(&self, other: &Feed) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Feed")
    }
}

impl Source {
    /// Parse `none` | `tone` | `tone:440` | `file:/path.ogg`.
    pub fn parse(s: &str) -> Result<Source> {
        Ok(match s {
            "none" => Source::None,
            "tone" => Source::Tone { hz: 440.0 },
            t if t.starts_with("tone:") => Source::Tone { hz: t[5..].parse().context("tone frequency")? },
            f if f.starts_with("file:") => Source::File(PathBuf::from(&f[5..])),
            other => anyhow::bail!("unknown media source {other} (none | tone[:hz] | file:<path.ogg>)"),
        })
    }
}

/// Live Opus encoder for a sine tone.
pub struct ToneEncoder {
    enc: audiopus::coder::Encoder,
    phase: f32,
    step: f32,
    pcm: Vec<i16>,
    out: Vec<u8>,
}

impl ToneEncoder {
    /// A tone at `hz`, about −12 dBFS.
    pub fn new(hz: f32) -> Result<ToneEncoder> {
        let mut enc = audiopus::coder::Encoder::new(audiopus::SampleRate::Hz48000, audiopus::Channels::Mono, audiopus::Application::Voip)
            .context("opus encoder")?;
        enc.set_bitrate(audiopus::Bitrate::BitsPerSecond(32_000)).ok();
        Ok(ToneEncoder { enc, phase: 0.0, step: hz * 2.0 * std::f32::consts::PI / 48_000.0, pcm: vec![0; FRAME_SAMPLES], out: vec![0; 4000] })
    }

    /// Next 20 ms frame.
    pub fn next_frame(&mut self) -> Result<Bytes> {
        for s in self.pcm.iter_mut() {
            *s = (self.phase.sin() * 8_000.0) as i16;
            self.phase += self.step;
            if self.phase > 2.0 * std::f32::consts::PI {
                self.phase -= 2.0 * std::f32::consts::PI;
            }
        }
        let n = self.enc.encode(&self.pcm, &mut self.out).context("opus encode")?;
        Ok(Bytes::copy_from_slice(&self.out[..n]))
    }
}

/// A boxed future returned by a frame sink: `true` to keep going, `false` to stop.
pub type SinkFuture = Pin<Box<dyn Future<Output = bool> + Send>>;

/// Drive `source` into `sink` at 20 ms pacing while `sending` stays set,
/// counting frames in `frames`. Both backends spawn this; only the sink
/// differs (a webrtc-rs track, a forge `AudioSender`).
///
/// Spec: §14.1 — the caller sets `sending` only once the session is ACTIVE.
pub async fn pump(source: Source, sending: Arc<AtomicBool>, frames: Arc<AtomicU64>, tap: Option<tokio::sync::mpsc::UnboundedSender<Bytes>>,
                  mut sink: impl FnMut(Bytes) -> SinkFuture + Send) {
    // every frame sent is also handed to the tap (Recording Profile C§6: the recorder leg forwards it)
    let mut sink = move |data: Bytes| {
        if let Some(t) = &tap {
            let _ = t.send(data.clone());
        }
        sink(data)
    };
    let mut tick = tokio::time::interval(FRAME_DURATION);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    match source {
        Source::None => {}
        Source::Feed(feed) => {
            let mut rx = feed.0.lock().await;
            while sending.load(Ordering::SeqCst) {
                let Some(data) = rx.recv().await else { break };
                if !sending.load(Ordering::SeqCst) || !sink(data).await {
                    break;
                }
                frames.fetch_add(1, Ordering::Relaxed);
            }
        }
        Source::Tone { hz } => {
            let mut enc = match ToneEncoder::new(hz) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("tone encoder: {e}");
                    return;
                }
            };
            while sending.load(Ordering::SeqCst) {
                tick.tick().await;
                let Ok(data) = enc.next_frame() else { break };
                if !sink(data).await {
                    break;
                }
                frames.fetch_add(1, Ordering::Relaxed);
            }
        }
        Source::File(path) => {
            while sending.load(Ordering::SeqCst) {
                let mut file = match crate::ogg::FileSource::open(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!("{e}");
                        return;
                    }
                };
                while sending.load(Ordering::SeqCst) {
                    let Some(frame) = file.next_frame() else { break };
                    tick.tick().await;
                    if !sink(frame).await {
                        return;
                    }
                    frames.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}
