//! Ogg/Opus file I/O shared by both backends (inbound recording, file source).
//!
//! Spec: none (infrastructure).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context as _, Result};
use bytes::{Bytes, BytesMut};
use webrtc_media::io::ogg_reader::OggReader;
use webrtc_media::io::ogg_writer::OggWriter;
use webrtc_media::io::Writer;

/// Records inbound Opus RTP payloads to an Ogg file.
pub struct Recorder {
    writer: Option<OggWriter<File>>,
}

impl Recorder {
    /// Open `path` for a 48 kHz mono Opus stream. Returns `None` (logged) if the
    /// file cannot be created, so a failed recording never fails the call.
    pub fn open(path: &Path) -> Option<Recorder> {
        match File::create(path).and_then(|f| OggWriter::new(f, 48_000, 1).map_err(std::io::Error::other)) {
            Ok(w) => Some(Recorder { writer: Some(w) }),
            Err(e) => {
                tracing::warn!("cannot record to {}: {e}", path.display());
                None
            }
        }
    }

    /// Append one RTP packet's Opus payload.
    pub fn write(&mut self, pkt: &rtp::packet::Packet) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.write_rtp(pkt);
        }
    }

    /// Finish the file.
    pub fn close(&mut self) {
        if let Some(mut w) = self.writer.take() {
            let _ = w.close();
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.close();
    }
}

/// Build an `rtp` packet from header fields (for backends whose RTP type differs).
pub fn rtp_packet(payload_type: u8, marker: bool, sequence_number: u16, timestamp: u32, ssrc: u32, payload: Bytes) -> rtp::packet::Packet {
    rtp::packet::Packet {
        header: rtp::header::Header {
            version: 2,
            padding: false,
            extension: false,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc: vec![],
            extension_profile: 0,
            extensions: vec![],
            extensions_padding: 0,
        },
        payload,
    }
}

/// Replays an Ogg/Opus file page by page.
pub struct FileSource {
    reader: OggReader<BufReader<File>>,
}

impl FileSource {
    /// Open an Ogg/Opus file.
    pub fn open(path: &Path) -> Result<FileSource> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let (reader, _header) = OggReader::new(BufReader::new(f), true)
            .map_err(|e| anyhow::anyhow!("{} is not an Ogg/Opus file: {e}", path.display()))?;
        Ok(FileSource { reader })
    }

    /// Next page payload, `None` at end of file.
    pub fn next_page(&mut self) -> Option<BytesMut> {
        self.reader.parse_next_page().ok().map(|(page, _)| page)
    }
}
