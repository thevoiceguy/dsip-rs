//! `dsip-mailbox` — the Messaging Profile over the wire: a mailbox/hub service and a device client.
//!
//! Spec: sections this crate hosts — M§4.2 (the service is found through the owner's DID document),
//! M§4.3 (`ws/1.0` with a verified `hello`, mailbox capabilities), M§5 (the profile message set on
//! the wire, forwarding to hubs — M§5.2), M§6.5–M§6.6 (hub ordering and fan-out, group registration),
//! M§7.3 (group membership over the wire), M§9.1 (deposit once, push to bound devices), M§14.2
//! (first-contact authorization, `origin` on hub-forwarded welcomes).
//!
//! Impl: every protocol decision is made by the vector-pinned state machines in `dsip-messaging`
//! (`Mailbox`, `Hub`) and the MLS binding in `dsip-mls`; this crate adds sockets, an item store, and
//! federation between two mailboxes. The core relay (`dsip-relay`) cannot carry this traffic: its
//! pipeline rejects every type outside the core message set, so the service runs its own
//! profile-aware verification ([`verify`]).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod http;
pub mod store;
pub mod verify;
pub mod wire;

/// Seconds a connection may take to send its `hello` (§13.2).
pub const HELLO_TIMEOUT_S: u64 = 10;
