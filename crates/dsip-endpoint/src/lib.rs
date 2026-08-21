//! `dsip-endpoint` — the IO-free endpoint core shared by every platform.
//!
//! Spec: sections owned by this crate — §10.2 (verify inbound bytes before
//! anything else), §12 (drive the engine), §14.2/§14.4 (an invite carries an
//! offer, an answer is a selection, screening selects `recvonly`), §16.2–§16.3
//! (structured media descriptors; SDP rides as a transport binding object),
//! §12.12 (`info` carries transport data), §19.4 (introductions and grants).
//!
//! [`core::Core`] has no clock, no sockets, and no storage: callers pass `now`,
//! transmit the frames it hands back, and persist [`core::ContactFile`]. The
//! native agent (`dsip-transport`) wraps it in a wss connection; `dsip-wasm`
//! wraps it for the browser. One engine, one verifier, every platform.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod core;
pub mod hello;
pub mod verify;

pub use core::{ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys};
