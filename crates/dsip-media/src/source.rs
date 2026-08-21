//! Audio sources: a generated Opus tone, or an Ogg/Opus file.
//!
//! Spec: none (infrastructure) — what goes *into* the media path is the
//! application's business; the protocol only cares that it happens after a
//! signed answer (§14.1).

use std::path::PathBuf;
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
