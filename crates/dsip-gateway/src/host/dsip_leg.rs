//! DSIP leg: a `dsip-transport::Agent` (one identity, one relay) plus, per call, a forge-webrtc
//! `PeerConnection` for media. SDP rides in `transports[].sdp` and candidates in signed `info`
//! (§12.12), exactly as `dsip-media` does — the gateway is another host of the same core.
//!
//! Spec: §16.3 (SDP as a transport binding object), §12.12 (ICE candidates in `info`, ACTIVE-only
//! buffering), §14.1 (media only after a signed answer). Impl: one peer connection per call keyed
//! by session id; decoded inbound Opus is forwarded to the media bridge, the bridge's Opus is
//! sent through the peer connection's `AudioSender`.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use forge_webrtc::{AudioSender, PeerConnection, PeerEvent};
use tokio::sync::mpsc;
use tracing::debug;

/// One call's WebRTC media on the DSIP side.
pub struct DsipMedia {
    pc: PeerConnection,
    /// Local ICE candidates gathered before ACTIVE (§12.12).
    pub pending_candidates: Vec<serde_json::Value>,
    /// Decoded inbound Opus payloads → the media bridge.
    pub inbound_tx: mpsc::UnboundedSender<Bytes>,
    inbound_rx: Option<mpsc::UnboundedReceiver<Bytes>>,
}

impl DsipMedia {
    /// New peer connection (answerer or offerer decided by which of `create_offer`/`accept_offer` runs).
    pub async fn new() -> Result<DsipMedia> {
        let pc = PeerConnection::new(vec![]).await.map_err(|e| anyhow!("peer connection: {e}"))?;
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Ok(DsipMedia { pc, pending_candidates: vec![], inbound_tx, inbound_rx: Some(inbound_rx) })
    }

    /// Take the inbound-Opus receiver (once) for the media bridge.
    pub fn take_inbound(&mut self) -> Option<mpsc::UnboundedReceiver<Bytes>> {
        self.inbound_rx.take()
    }

    /// An `AudioSender` for the bridge to push transcoded Opus into.
    pub fn sender(&self) -> Result<AudioSender> {
        self.pc.sender().map_err(|e| anyhow!("sender: {e}"))
    }

    /// Create our SDP offer (gateway places the DSIP call).
    pub async fn offer(&mut self) -> Result<String> {
        let sdp = self.pc.create_offer().await.map_err(|e| anyhow!("offer: {e}"))?;
        self.spawn_events();
        Ok(sdp)
    }

    /// Accept the caller's SDP offer and produce our answer (gateway answers a DSIP invite).
    pub async fn answer(&mut self, offer_sdp: &str) -> Result<String> {
        self.pc.set_remote_offer(offer_sdp).await.map_err(|e| anyhow!("set offer: {e}"))?;
        let sdp = self.pc.create_answer().await.map_err(|e| anyhow!("answer: {e}"))?;
        self.spawn_events();
        Ok(sdp)
    }

    /// Apply the remote SDP answer to our offer.
    pub async fn set_answer(&mut self, sdp: &str) -> Result<()> {
        self.pc.set_remote_answer(sdp).await.map_err(|e| anyhow!("set answer: {e}"))
    }

    /// Add a remote ICE candidate from a verified `info`.
    pub async fn add_candidate(&mut self, cand: &str) -> Result<()> {
        self.pc.add_ice_candidate_str(cand).await.map_err(|e| anyhow!("candidate: {e}"))
    }

    fn spawn_events(&mut self) {
        let Some(mut events) = self.pc.take_events() else { return };
        let inbound = self.inbound_tx.clone();
        // Local candidates and inbound RTP are pumped to the call loop via the shared channels;
        // candidates are collected here into a task that the call loop drains through `drain_candidates`.
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                match ev {
                    PeerEvent::Rtp(pkt) => {
                        let _ = inbound.send(pkt.payload.clone());
                    }
                    PeerEvent::Failed(w) => debug!("dsip media failed: {w}"),
                    PeerEvent::Closed => break,
                    _ => {}
                }
            }
        });
    }

    /// Local candidates gathered so far, in the §12.12 `info.data.candidates` shape.
    pub fn drain_candidates(&mut self) -> Vec<serde_json::Value> {
        let cands: Vec<serde_json::Value> = self
            .pc
            .local_candidates()
            .into_iter()
            .map(|c| serde_json::json!({"candidate": c.to_sdp_attribute(), "sdp_mid": "0", "sdp_m_line_index": 0}))
            .collect();
        cands
    }

    /// Close the peer connection.
    pub fn close(&mut self) {
        self.pc.close();
    }
}

/// Per-call media map keyed by DSIP session id.
#[derive(Default)]
pub struct DsipMediaMap(pub HashMap<String, DsipMedia>);
