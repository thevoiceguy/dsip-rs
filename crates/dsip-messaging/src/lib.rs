//! `dsip-messaging` — the protocol rules of the DSIP Messaging Profile 1.0 (v0.8 draft,
//! `v0.8/dsip-messaging-profile-v0.8-draft.md`, cited `M§n`). Pure: no MLS library, no network.
//! MLS is abstracted to what a hub or mailbox can observe, as relay traces abstract signatures.
//!
//! Spec: sections owned by this crate — M§5 (profile messages: the two-layer model, lifetimes,
//! `MAX_MLS_BYTES`, the deposit class table — [`checks`]), M§8/M§10/M§11/M§12 (content objects,
//! receipts, activity, archive keys — [`checks`]), M§6.5–M§6.8 and M§7.3 (hub ordering,
//! sequencing, fan-out order, membership rules, external joins — [`hub`]), M§4.4, M§5.4–M§5.7,
//! M§6.6, M§12.2, M§14.2 (mailbox modes, sync and push, KeyPackage directory, group registration,
//! archive first-wins, first-contact authorization — [`mailbox`]), M§6.5 (client seq gaps), M§7.2/M§7.5
//! (conversation convergence), M§10 and M§11.2 (receipts, watermarks, activity) and M§13.2
//! (voicemail offer — [`client`]).
//!
//! Impl: every rule here is pinned by `impl/vectors/messaging/`; the Python reference is
//! `impl/tools/dsipvec/messaging.py`. The profile is a draft written before implementation, so
//! its open choices are spec-gaps 31–43 (`impl/docs/spec-gaps.md`).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod checks;
pub mod client;
pub mod hub;
pub mod mailbox;
pub mod schemas;

use serde_json::{json, Value};

/// Run one `messaging/` vector and return the value to compare with its `expect`.
///
/// Spec: none (infrastructure) — dispatches on `input.check`.
pub fn run_vector(v: &Value) -> Value {
    let inp = &v["input"];
    match inp["check"].as_str().unwrap_or("") {
        "payload" => {
            let name = inp["schema"].as_str().unwrap_or("");
            if schemas::schema_ok(name, &inp["payload"]) {
                checks::accept()
            } else {
                checks::reject("schema-invalid", None)
            }
        }
        "message" => checks::check_message(&inp["payload"]),
        "object" => checks::check_object(&inp["object"], &v["context"]),
        "conversation-ext" => checks::check_conversation_ext(&inp["extension"]),
        "voicemail-offer" => client::voicemail_offer(inp),
        "direct-select" => client::select_direct(inp["candidates"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "successor-check" => client::check_successor(inp),
        "successor-select" => client::select_successor(inp["candidates"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "client-trace" => {
            let mut c = client::Client::new(&v["context"]);
            trace(inp, |ev| (c.step(ev), c.snapshot()))
        }
        "gap-trace" => {
            let mut g = client::GapTracker::new(&v["context"]);
            trace(inp, |ev| (g.step(ev), g.snapshot()))
        }
        "hub-trace" => {
            let mut h = hub::Hub::new(&v["context"]);
            trace(inp, |ev| (h.step(ev), h.snapshot()))
        }
        "mailbox-trace" => {
            let mut m = mailbox::Mailbox::new(&v["context"]);
            trace(inp, |ev| (m.step(ev), m.snapshot()))
        }
        other => json!({"error": format!("unknown messaging check {other}")}),
    }
}

fn trace(inp: &Value, mut step: impl FnMut(&Value) -> (Vec<Value>, Value)) -> Value {
    let steps: Vec<Value> = inp["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|st| {
            let (emit, state) = step(&st["event"]);
            json!({"emit": emit, "state": state})
        })
        .collect();
    json!({"steps": steps})
}
