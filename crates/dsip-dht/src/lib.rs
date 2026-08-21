//! `dsip-dht` — reachability hints over a Kademlia DHT (experimental, Workstream D).
//!
//! Spec: sections owned by this crate — §8.5 (DHT discovery is experimental in
//! v1.0), §8.3 (conflict rules: signed beats unsigned, newer `seq` wins,
//! expired records are invalid, same-key live conflicts warn), §8.1 rule 6
//! (DHTs distribute records but are **not authoritative**), §7.4 (records are
//! signed by the subject or a delegated device).
//!
//! The authority order of §8.1 is untouchable: nothing in this crate returns
//! a hint as anything other than a hint. [`record::evaluate`] verifies a
//! record against the subject DID (or a delegation) before it is stored,
//! forwarded, or offered to a caller, and the caller labels it hint-sourced.
//!
//! Plan §10: `did:key` is the flagship path — a hint verifies against the key
//! embedded in the subject DID itself, so discovery needs no DNS, no Web PKI,
//! and no directory. Browsers do not join the DHT (they ask their relay);
//! bootstrap nodes are configuration and a centralization point. Both are
//! findings, documented in `impl/docs/dht-findings.md`, not hidden.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod control;
pub mod node;
pub mod record;

/// Kademlia protocol name for the DSIP hints overlay.
pub const PROTOCOL: &str = "/dsip/hints/0.6";
