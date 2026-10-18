//! `dsip-endpoint` — the IO-free endpoint core shared by every platform.
//!
//! Spec: sections owned by this crate — §10.2 (verify inbound bytes before
//! anything else), §12 (drive the engine), §14.2/§14.4 (an invite carries an
//! offer, an answer is a selection, screening selects `recvonly`), §16.2–§16.3
//! (structured media descriptors; SDP rides as a transport binding object),
//! §12.12 (`info` carries transport data), §19.4 (introductions and grants),
//! §10.4 (the clear resend of a refused sealed call) and C§4 (recording
//! consent) in [`calls`], the call glue every host shares.
//!
//! [`core::Core`] has no clock, no sockets, and no storage: callers pass `now`,
//! transmit the frames it hands back, and persist [`core::ContactFile`]. The
//! native agent (`dsip-transport`) wraps it in a wss connection; `dsip-wasm`
//! wraps it for the browser. One engine, one verifier, every platform.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod calls;
pub mod core;
pub mod error;
pub mod hello;
pub mod verify;

pub use calls::{AnswerPolicy, CallCommand, CallEvent, CallOut, Calls, CallsConfig, MediaRequest, MediaResult};
pub use error::{Error, Result};
pub use core::{Command, ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys, Invite, InvitePatch};
