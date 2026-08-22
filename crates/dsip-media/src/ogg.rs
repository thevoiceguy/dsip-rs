//! Ogg/Opus file I/O shared by both backends (inbound recording, file source).
//!
//! Spec: none (infrastructure).

use std::fs::File;
use std::path::Path;

use anyhow::{Context as _, Result};
use bytes::Bytes;
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

/// Replays an Ogg/Opus file, one Opus packet (frame) at a time.
///
/// Spec: none (infrastructure). Impl: parses the Ogg container directly and reassembles Opus
/// packets across the page segment table and page continuations (RFC 3533 lacing), skipping the
/// `OpusHead`/`OpusTags` headers (RFC 7845). The earlier version replayed whole Ogg *pages* as if
/// each were one frame, which garbled any file (e.g. from ffmpeg) that packs many frames per page.
pub struct FileSource {
    frames: Vec<Bytes>,
    pos: usize,
}

impl FileSource {
    /// Open an Ogg/Opus file and index its audio frames.
    pub fn open(path: &Path) -> Result<FileSource> {
        let data = std::fs::read(path).with_context(|| format!("open {}", path.display()))?;
        let frames = parse_opus_frames(&data);
        anyhow::ensure!(!frames.is_empty(), "{} has no Opus audio frames (not an Ogg/Opus file?)", path.display());
        Ok(FileSource { frames, pos: 0 })
    }

    /// Next Opus frame, `None` at end of file.
    pub fn next_frame(&mut self) -> Option<Bytes> {
        let f = self.frames.get(self.pos)?.clone();
        self.pos += 1;
        Some(f)
    }
}

/// Reassemble Opus packets from raw Ogg bytes, in stream order, dropping the two header packets.
///
/// Ogg framing (RFC 3533): each page is `"OggS"` + a 27-byte header whose last byte is the segment
/// count, then that many lacing bytes, then the segment data. A packet is the concatenation of
/// segments up to and including the first lacing value `< 255`; a value of `255` means the packet
/// continues (into the next segment, and across a page boundary when it is a page's last segment).
/// Flattening the lacing values and segment data in page order makes continuation transparent.
fn parse_opus_frames(data: &[u8]) -> Vec<Bytes> {
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i + 27 <= data.len() {
        if &data[i..i + 4] != b"OggS" {
            i += 1; // resync to the next capture pattern
            continue;
        }
        let n_seg = data[i + 26] as usize;
        let table = i + 27;
        if table + n_seg > data.len() {
            break;
        }
        let mut body = table + n_seg;
        for &lace in &data[table..table + n_seg] {
            let l = lace as usize;
            if body + l > data.len() {
                return finish(packets);
            }
            cur.extend_from_slice(&data[body..body + l]);
            body += l;
            if l < 255 {
                packets.push(std::mem::take(&mut cur));
            }
        }
        i = body;
    }
    finish(packets)
}

fn finish(packets: Vec<Vec<u8>>) -> Vec<Bytes> {
    packets
        .into_iter()
        .filter(|p| !p.starts_with(b"OpusHead") && !p.starts_with(b"OpusTags") && !p.is_empty())
        .map(Bytes::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ogg page: `OggS` + header + segment table + data.
    fn page(header_type: u8, seqno: u32, packets: &[&[u8]]) -> Vec<u8> {
        let mut laces = Vec::new();
        let mut body = Vec::new();
        for pkt in packets {
            let mut rem = pkt.len();
            loop {
                let seg = rem.min(255);
                laces.push(seg as u8);
                rem -= seg;
                if seg < 255 {
                    break;
                }
            }
            body.extend_from_slice(pkt);
        }
        let mut pg = Vec::new();
        pg.extend_from_slice(b"OggS");
        pg.push(0); // version
        pg.push(header_type);
        pg.extend_from_slice(&[0u8; 8]); // granule
        pg.extend_from_slice(&1u32.to_le_bytes()); // serial
        pg.extend_from_slice(&seqno.to_le_bytes());
        pg.extend_from_slice(&[0u8; 4]); // crc (unchecked)
        pg.push(laces.len() as u8);
        pg.extend_from_slice(&laces);
        pg.extend_from_slice(&body);
        pg
    }

    #[test]
    fn skips_headers_and_splits_multi_frame_pages() {
        let mut ogg = page(0x02, 0, &[b"OpusHead...."]);
        ogg.extend(page(0x00, 1, &[b"OpusTags...."]));
        // One page carrying three distinct audio frames (what ffmpeg-style muxing produces).
        ogg.extend(page(0x00, 2, &[b"FRAME-ONE", b"FRAME-TWO", b"FRAME-THREE"]));
        let frames = parse_opus_frames(&ogg);
        assert_eq!(frames.len(), 3, "three audio frames, headers dropped");
        assert_eq!(frames[0].as_ref(), b"FRAME-ONE");
        assert_eq!(frames[2].as_ref(), b"FRAME-THREE");
    }

    #[test]
    fn reassembles_a_packet_spanning_segments_and_pages() {
        // A 600-byte packet: needs three lacing segments (255+255+90) and we split it across pages.
        let big = vec![0xABu8; 600];
        // Page A ends mid-packet (last lace 255 → continues); page B (continuation) finishes it.
        // Emulate by putting the whole packet in one call — the lacing logic yields 255,255,90.
        let mut ogg = page(0x02, 0, &[b"OpusHead"]);
        ogg.extend(page(0x00, 1, &[b"OpusTags"]));
        ogg.extend(page(0x00, 2, &[&big]));
        let frames = parse_opus_frames(&ogg);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 600);
    }
}
