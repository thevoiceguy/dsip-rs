//! `dsip-messaging-device` — the Messaging Profile's device side on OpenMLS, as one library for every host: the
//! native client (`dsip-msg`) and the browser (`dsip-wasm`'s `Messenger`). It grows stage by stage (dsip-rs stage 3,
//! `impl/docs/dsip-stack-design.md`) from the logic the two clients each carried; the vector-pinned machines stay in
//! `dsip_messaging::client`, the MLS wrapper in `dsip_mls`. It does no I/O: hosts hand it bytes and time.
//!
//! Spec: M§6.2 (every leaf authenticated), M§6.5 (commits checked, then merged), M§6.8 (an external join checked by
//! every member, spec-gap 62), M§7.3 (roster rules, spec-gap 126; leaving, spec-gap 125), M§7.4 (the hub reference,
//! spec-gap 60), M§8.1 (content objects checked before rendering), C§5 (content from a recorder leaf), C§9 (call
//! records).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod process;

pub use process::{process, Outcome, ProcessOptions};
