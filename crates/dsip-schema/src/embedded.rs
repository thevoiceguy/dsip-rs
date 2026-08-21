//! Schema texts embedded from the canonical spec folder.
//!
//! Spec: §10.3 — "JSON Schema files for every message type accompany this
//! specification and are normative for payload shape." The files are read
//! from `v0.6/…/schemas/` at compile time; `build.rs` fails the build if they
//! drift from `generate_schemas.py`. When v0.7 lands, this path is the whole
//! migration for the schema layer.

macro_rules! schema {
    ($name:literal) => {
        ($name, include_str!(concat!("../../../../v0.6/dsip-schemas-v0.6-draft/dsip-schemas/schemas/", $name, ".schema.json")))
    };
}

/// `(name, json text)` for every schema in the v0.6 set.
pub const SCHEMAS: &[(&str, &str)] = &[
    schema!("invite"),
    schema!("progress"),
    schema!("answer"),
    schema!("reject"),
    schema!("cancel"),
    schema!("update"),
    schema!("info"),
    schema!("bye"),
    schema!("error"),
    schema!("hello"),
    schema!("introduction"),
    schema!("grant"),
    schema!("publish"),
    schema!("subscribe"),
    schema!("notify"),
    schema!("unpublish"),
    schema!("envelope"),
    schema!("message"),
];

/// Implementation-local schema for DHT reachability hints (plan §10; not part of the spec set).
pub const REACHABILITY_HINT: &str = include_str!("../../../schemas/reachability-hint.schema.json");

/// Implementation-local schema for broadcast provenance statements (§22.3 extension `broadcast-provenance/1.0`).
pub const BROADCAST_PROVENANCE: &str = include_str!("../../../schemas/broadcast-provenance.schema.json");
