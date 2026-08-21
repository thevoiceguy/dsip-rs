//! `dsip-core` — identifiers, DIDs, keys, and the DSIP-JOSE envelope.
//!
//! Spec: sections owned by this crate — §7.2–§7.4 (DID usage, device
//! delegation), §8.1 (resolution authority), §10.2–§10.3 (signature semantics,
//! payload rules), §11 (version negotiation), §12.9 (replay window),
//! §15.1/§15.4 (reason registry), §20.6 (glare-backdating guard).
//!
//! This crate never depends on schema or session logic. A message leaving
//! [`envelope::verify`] has passed signature, binding, replay, and wire-format
//! checks and nothing else; shape (schema) and state come later, in that order.
//!
//! Verdict codes and stage order are defined by `impl/vectors/README.md` and
//! mirrored by [`verdict::RejectCode`].

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod b64;
pub mod delegation;
pub mod did;
pub mod envelope;
pub mod keys;
pub mod registry;
pub mod trust;
pub mod ulid;
pub mod verdict;
pub mod version;
pub mod wire;

pub use envelope::{Context, Envelope, Verified};
pub use verdict::{RejectCode, Verdict};

/// Replay window in seconds.
///
/// Spec: §12.9 — envelopes with `issued_at` older than the window MUST be
/// rejected; ids are tracked for deduplication within it.
pub const REPLAY_WINDOW_S: i64 = 300;

/// Tolerance between the ULID timestamp component and `issued_at`.
///
/// Spec: §20.6. Impl (spec-gap 6): the spec says "consistent … within the
/// replay window"; this PoC rejects beyond 300 s.
pub const ULID_TOLERANCE_S: i64 = 300;

/// Maximum encoded envelope size on `ws/1.0`, a fixed binding constant.
///
/// Spec: §13.2.
pub const WS_MAX_ENVELOPE_BYTES: usize = 65_536;

/// Maximum encoded size of an `introduction` envelope.
///
/// Spec: §19.4 — a core constant, deliberately far below the transport cap.
pub const INTRODUCTION_MAX_BYTES: usize = 4_096;
