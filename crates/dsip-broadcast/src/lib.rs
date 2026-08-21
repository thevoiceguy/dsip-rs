//! `dsip-broadcast` — Verified Broadcast and the subscription protocol.
//!
//! Spec: sections owned by this crate — §9.3 (subscribe/notify: mandatory
//! `events` + `expires_in`, per-event lifetime caps, renewal replaces, `0`
//! terminates, seq-ordered notifies with a terminal state, authorization as
//! the target authority's policy, anti-enumeration), §22.1 (signed publication
//! records), §22.2 (integrity modes `metadata-only` / `derivative-bound`),
//! §22.3 (provenance statements from relays and transcoders that never
//! overwrite the publisher), §16.4 (policy is displayed and enforced by
//! receivers, not magic).
//!
//! Three pieces: [`authority::Authority`] (the target's relay/domain endpoint),
//! [`subscriber::Subscriber`], and the receiver-side stateless checks in
//! [`receiver`]. All are clockless and IO-free; the relay binary and the CLI
//! wrap them.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod authority;
pub mod receiver;
pub mod subscriber;

pub use authority::{Authority, AuthorityEvent};
pub use receiver::{evaluate_provenance, evaluate_publication, select_variant, stream_in_namespace, Receiver};
pub use subscriber::Subscriber;

/// Integrity modes defined by Core v1.0. Spec: §22.2.
pub const INTEGRITY_MODES: &[&str] = &["metadata-only", "derivative-bound"];
/// The broadcast profile identifier. Spec: §22.
pub const PROFILE: &str = "verified-broadcast/1.0";
