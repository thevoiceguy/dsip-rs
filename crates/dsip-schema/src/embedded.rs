//! Schema texts embedded from the canonical spec folder.
//!
//! Spec: §10.3 — "JSON Schema files for every message type accompany this
//! specification and are normative for payload shape." The files are read
//! from `v0.7/…/schemas/` at compile time; `build.rs` fails the build if they
//! drift from `generate_schemas.py`. Switching the path *is* the schema-layer
//! migration between spec revisions (v0.6 → v0.7 on 2026-08-21).

macro_rules! schema {
    ($name:literal) => {
        ($name, include_str!(concat!("../../../../v0.7/dsip-schemas-v0.7-draft/dsip-schemas/schemas/", $name, ".schema.json")))
    };
}

/// `(name, json text)` for every schema in the v0.7 set (message types, the envelope and
/// dispatcher, and the WebRTC Media Binding's `info.data` schema).
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
    schema!("provenance"),
    schema!("key-rotation"),
    schema!("reachability-hint"),
    schema!("webrtc-info-data"),
    schema!("envelope"),
    schema!("message"),
];
