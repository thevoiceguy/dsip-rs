# Follow-on: adopting forge-media as the DSIP media stack

**Status:** plan for later in the project. The PoC's `dsip-media` crate uses webrtc-rs so the
Phase 2 browser↔native demo can land now; this document records what was found when
evaluating `thevoiceguy/forge-media` (2026-08-21) and what it would take to switch.

## What forge-media already provides (verified: builds on the PoC machine)

| Need | Crate | Notes |
|---|---|---|
| ICE, both roles, host + srflx, STUN with MESSAGE-INTEGRITY | `forge-ice` | RFC 8445; own implementation |
| DTLS handshake, certificate, SRTP key export | `forge-rtp` (`dtls` feature) | vendored OpenSSL; `DtlsConnection::export_srtp_keys` |
| SRTP protect/unprotect (AES-GCM), RTP/RTCP | `forge-rtp` | `SrtpContext`, jitter buffer, port pool |
| SDP with ICE credentials and DTLS fingerprint | `forge-sdp` | `SdpProfile::webrtc_audio()`; depends on the `external/siphon-rs` submodule (cargo fetches submodules for git deps) |
| Opus | `forge-codecs` (`opus` feature) | `audiopus` → cmake |
| Offer-side peer connection | `forge-webrtc::PeerConnection` | `create_offer`, `set_remote_answer`, `add_ice_candidate` (trickle-in), DTLS after ICE |

## Gaps for a DSIP *endpoint* (as opposed to a media server)

1. **Answerer role.** `PeerConnection` has no `set_remote_offer` / `create_answer`. DSIP's native
   callee must answer a browser's offer (and a native caller's), and the DSIP answer message is a
   *selection* carrying the SDP answer (§14.2, spec-gap 16).
2. **Trickle-out.** `create_offer` gathers every candidate first and bakes them into the SDP.
   DSIP carries candidates in signed `info` envelopes after ACTIVE (§12.12); the endpoint needs
   an "on local candidate" stream, and the SDP should be producible before gathering completes.
3. **Single-leg media API.** Media in forge lives at the engine layer as a two-participant
   server (forwarding, mixing, injection, recording). An endpoint needs: push encoded Opus
   frames out on one leg; receive decoded (or raw Opus) frames in; DTLS role from the SDP
   `a=setup` line; SRTP installed from the exported keys without an engine session.
4. **Renegotiation.** DSIP `update` re-offers (add video, screening escalation); the peer
   connection needs `set_remote_offer`/`create_offer` after establishment with ICE restart
   semantics defined (or explicitly unsupported).

## Proposed shape (upstream to forge-webrtc)

```rust
pub struct PeerConnection { … }
impl PeerConnection {
    pub async fn create_offer(&mut self) -> Result<String>;            // SDP now; candidates may trickle
    pub async fn set_remote_offer(&mut self, sdp: &str) -> Result<()>;  // NEW
    pub async fn create_answer(&mut self) -> Result<String>;           // NEW (DTLS role from a=setup)
    pub async fn set_remote_answer(&mut self, sdp: &str) -> Result<()>;
    pub async fn add_ice_candidate(&mut self, c: IceCandidate) -> Result<()>;
    pub fn local_candidates(&self) -> mpsc::Receiver<Option<IceCandidate>>; // NEW trickle-out (None = end)
    pub fn media(&self) -> MediaLeg;                                   // NEW: send(OpusFrame) / recv() -> RtpPayload
}
```

`dsip-media` keeps the same trait surface (`MediaLeg`: `offer`, `answer`, `set_answer`,
`add_remote_candidate`, `next_local_candidate`, `send_frame`, `recv_frame`) so that swapping the
backend from webrtc-rs to forge is a one-crate change with the DSIP agent and CLI untouched.

## Migration steps

1. Land the four items above in forge-media (behind the existing `dtls` feature).
2. Add a `forge` feature to `dsip-media` with a second backend implementing the trait; depend on
   forge-media by git URL + rev.
3. Run the Phase 2 demos against both backends (browser ↔ native, native ↔ native); the DSIP
   vectors are unaffected (media is below the signaling contract).
4. Make `forge` the default; keep webrtc-rs as the fallback named in plan §7's risk row.
