//! The daemon half: real legs around the pure [`crate::controller::GatewayCall`].
//!
//! Spec: none (infrastructure) — the normative behaviour lives in the controller and the
//! tables it calls; these modules only move bytes: `sip_leg` (UDP + siphon-rs helpers),
//! `dsip_leg` (`dsip-transport::Agent` + forge-webrtc peer connection + §12.12 candidate
//! buffering), `media` (Opus ⇄ G.711 PCM bridge over forge-rtp), `call` (the host loop that
//! turns leg events into controller events and controller emissions into leg actions), `numbers` (the
//! Number Attestation Profile's gateway rules: PASSporT verification, routing by binding, assertion).

pub mod call;
pub mod dsip_leg;
pub mod media;
pub mod numbers;
pub mod sip_leg;
