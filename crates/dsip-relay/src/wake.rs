//! The relay as a waker (Wake Profile, draft `wake/0.1`): it keeps the registrations its devices send in
//! `wake-register`, and when it holds an invite for a registered device that is not bound it asks the device's push
//! gateway to wake it, and to end the call on the screen when the invite stops being held before the device binds.
//! The bookkeeping is shared with the mailbox ([`dsip_transport::waker`]).
//!
//! Spec: W§4.4 (the `wake` capability in the relay's `hello`), W§5.1 (`call`, `call-ended`).

pub use dsip_transport::waker::WakeConfig;
pub(crate) use dsip_transport::waker::{send, Outgoing, Wakes};

/// The kinds a relay sends. Spec: W§4.4, W§5.1
pub const KINDS: [&str; 2] = ["call", "call-ended"];
