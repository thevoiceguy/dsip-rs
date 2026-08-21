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
use forge_webrtc::{AudioSender, PeerConnection, PeerEvent};

use tokio::sync::mpsc;

/// One call's WebRTC media on the DSIP side.
pub struct DsipMedia {
    pc: PeerConnection,
    /// Local ICE candidates gathered before ACTIVE (§12.12).
    pub pending_candidates: Vec<serde_json::Value>,
}

impl DsipMedia {
    /// New peer connection (answerer or offerer decided by which of `create_offer`/`accept_offer` runs).
    pub async fn new() -> Result<DsipMedia> {
        let pc = PeerConnection::new(vec![]).await.map_err(|e| anyhow!("peer connection: {e}"))?;
        Ok(DsipMedia { pc, pending_candidates: vec![] })
    }

    /// An `AudioSender` for the bridge to push transcoded Opus into.
    pub fn sender(&self) -> Result<AudioSender> {
        self.pc.sender().map_err(|e| anyhow!("sender: {e}"))
    }

    /// Create our SDP offer (gateway places the DSIP call).
    pub async fn offer(&mut self) -> Result<String> {
        let sdp = self.pc.create_offer().await.map_err(|e| anyhow!("offer: {e}"))?;
        Ok(sdp)
    }

    /// Accept the caller's SDP offer and produce our answer (gateway answers a DSIP invite).
    pub async fn answer(&mut self, offer_sdp: &str) -> Result<String> {
        self.pc.set_remote_offer(offer_sdp).await.map_err(|e| anyhow!("set offer: {e}"))?;
        let sdp = self.pc.create_answer().await.map_err(|e| anyhow!("answer: {e}"))?;
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

    /// Whether media is established (DTLS-SRTP up).
    pub fn connected(&self) -> bool {
        matches!(self.pc.get_state(), forge_webrtc::ConnectionState::Connected)
    }

    /// Wait until connected or the timeout elapses.
    pub async fn wait_connected(&self, timeout: std::time::Duration) -> bool {
        self.pc.wait_connected(timeout).await.is_ok()
    }

    /// Take the peer connection's event receiver (candidates/connection state) for a driver that
    /// trickles them out; used by the round-trip harness and the daemon's candidate pump.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<PeerEvent>> {
        self.pc.take_events()
    }

    /// Close the peer connection.
    pub fn close(&mut self) {
        self.pc.close();
    }
}

/// Per-call media map keyed by DSIP session id.
#[derive(Default)]
pub struct DsipMediaMap(pub HashMap<String, DsipMedia>);
