//! `dsip-session` — the §12 session lifecycle.
//!
//! Spec: sections owned by this crate — §12.2 (session identification), §12.4
//! (state machine), §12.5 (cancel/answer race), §12.6 (glare), §12.7
//! (forking — initiator side in [`endpoint`], relay leg tracking in [`fork`]),
//! §12.8 (renegotiation), §12.9 (timers), §12.10–§12.12 (`progress`,
//! `cancel`, `info` semantics), §14.3–§14.4 (`answered_by`, screening).
//!
//! Messages reaching this crate have already passed signature, replay, and
//! shape checks (`dsip-core`, `dsip-schema`); [`message::Message`] is the
//! abbreviated, verified view the engine consumes. The engine is
//! deterministic and clockless: callers (the transport layer or the vector
//! runner) advance [`endpoint::Endpoint::advance`] and act on the emitted
//! [`event::Emission`]s.
//!
//! Impl: the plan (§6 WS-3) describes typestate. Sessions here are an
//! exhaustive `enum` state with every transition a `match` arm — the same
//! compile-time guarantee (no unhandled state/event pair) without forcing a
//! typestate onto a multi-session, timer-driven endpoint.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod endpoint;
pub mod event;
pub mod fork;
pub mod message;

pub use endpoint::{Endpoint, EndpointConfig, Session, SessionState, Role};
pub use event::{Emission, Event, LocalEvent};
pub use fork::{Attempt, LegState, Relay, RelayEvent};
pub use message::Message;
