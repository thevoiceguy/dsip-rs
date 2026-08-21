//! `dsip-media` — the native media endpoint (Phase 2): WebRTC DTLS-SRTP audio.
//!
//! Spec: sections owned by this crate — §14.1 (no media without a signed
//! answer: a leg only starts sending once the DSIP session is ACTIVE), §16.3
//! (SDP as a transport binding object — spec-gap 16), §12.12 (ICE candidates
//! ride in signed `info` after ACTIVE; gathered candidates are handed to the
//! host as they appear so it can buffer them), §14.4 (screening: a `recvonly`
//! leg exposes no local media), §17.1 (Opus audio).
//!
//! Impl: backend is webrtc-rs (plan §7 names it the least-proven dependency).
//! The [`leg::MediaLeg`] surface is deliberately small so that a forge-media
//! backend can replace it later without touching the agent or CLI —
//! see `impl/docs/forge-media-plan.md`. No sound card is used: the source is
//! a generated tone or an Ogg/Opus file, and inbound audio is recorded to
//! Ogg, which is enough to prove the DTLS-SRTP path end to end (and to test
//! native↔native headlessly).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod leg;
pub mod source;

pub use leg::{Candidate, MediaConfig, MediaEvent, MediaLeg, Stats};
pub use source::Source;
