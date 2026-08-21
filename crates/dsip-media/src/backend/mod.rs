//! Media backends. Each exposes a leg type with the surface `leg::MediaLeg`
//! dispatches to; nothing above this module names a backend type.
//!
//! Spec: none (infrastructure) — the binding is satisfied by both; see
//! `leg` for the normative behaviour both must honour.

#[cfg(feature = "forge")]
pub mod forge;
#[cfg(feature = "webrtc-rs")]
pub mod webrtc_rs;
