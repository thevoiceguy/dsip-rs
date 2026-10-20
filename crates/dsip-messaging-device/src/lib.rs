//! `dsip-messaging-device` — the Messaging Profile's device side on OpenMLS, as one library for every host: the
//! native client (`dsip-msg`) and the browser (`dsip-wasm`'s `Messenger`). It grows stage by stage (dsip-rs stage 3,
//! `impl/docs/dsip-stack-design.md`) from the logic the two clients each carried; the vector-pinned machines stay in
//! `dsip_messaging::client`, the MLS wrapper in `dsip_mls`. It does no I/O: hosts hand it bytes and time.
//!
//! Spec: M§5.3 (deposits awaiting their answer), M§5.4 (items routed and acknowledged; what a device keeps, written
//! together: spec-gap 44), M§5.5 (KeyPackages selected), M§6.2 (every leaf authenticated), M§6.5 (commits built,
//! checked, then merged, and retried), M§6.8 (an external join checked by every member, spec-gap 62), M§7.3 (roster
//! rules, spec-gap 126; leaving, spec-gap 125), M§7.4 (the hub reference, spec-gap 60), M§7.5 (successor groups,
//! spec-gap 61), M§8.1 (content objects checked before rendering), M§8.4 (blobs), M§9.2–M§9.4 (the outbox and hub
//! outages), M§10 (receipts), M§11.2 (activity), M§12 (history and archive records), M§13.3 (call events), M§14.1 (introductions and grants received), C§5
//! (content from a recorder leaf; recorded conversations), C§9 (call records).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod archive;
pub mod blob;
pub mod calls;
pub mod commits;
pub mod config;
pub mod deposits;
pub mod first_contact;
pub mod history;
pub mod inbound;
pub mod key_packages;
pub mod messenger;
pub mod outbox;
pub mod process;
pub mod receipts;
pub mod recording;
pub mod store;
pub mod successors;

pub use calls::CallLog;
pub use commits::Retry;
pub use config::Config;
pub use deposits::Deposits;
pub use history::History;
pub use inbound::{Inbound, Route};
pub use outbox::{Deposit, Outbox};
pub use process::{process, Outcome, ProcessOptions};
pub use receipts::Receipts;
pub use store::{MemoryStore, Store};
pub use successors::Successors;
