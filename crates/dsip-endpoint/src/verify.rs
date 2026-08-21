//! Inbound frame verification shared by endpoints and relays.
//!
//! Spec: §10.2 (verify over bytes, then decode), §12.9 (replay window and id
//! deduplication), §13.2 (size cap on receive). Runs the full stage 1–14
//! pipeline from `dsip-core` and `dsip-schema` and returns the verified
//! payload together with the registry effects.

use std::collections::HashMap;

use dsip_core::did::Resolver;
use dsip_core::envelope::{self, Context, Envelope, Verified};
use dsip_core::{Verdict, REPLAY_WINDOW_S};
use dsip_schema::{check_payload, SemanticContext};

/// Ids seen within the replay window, with expiry.
///
/// Spec: §12.9 — "Message id values MUST be tracked for deduplication within the window."
#[derive(Debug, Default)]
pub struct SeenIds {
    ids: HashMap<String, i64>,
}

impl SeenIds {
    /// Forget ids older than the replay window.
    pub fn sweep(&mut self, now: i64) {
        self.ids.retain(|_, t| *t + REPLAY_WINDOW_S >= now);
    }

    /// Record an id as seen at `now`.
    pub fn insert(&mut self, id: &str, now: i64) {
        self.ids.insert(id.to_string(), now);
    }

    /// The set view used by the verification context.
    pub fn set(&self) -> std::collections::HashSet<String> {
        self.ids.keys().cloned().collect()
    }
}

/// A verified inbound frame.
#[derive(Debug)]
pub struct Inbound {
    /// Envelope as received.
    pub envelope: Envelope,
    /// The exact frame text (forwarded unchanged by relays).
    pub frame: String,
    /// Verification output.
    pub verified: Verified,
    /// Stage 12–14 verdict (accept; carries `effective`/`warnings`).
    pub semantic: Verdict,
}

/// Verify one text frame end to end.
///
/// `sem` supplies `sent_hello_id` / `offer` / etc. On success the id is
/// recorded in `seen`.
pub fn verify_frame(
    frame: &str,
    now: i64,
    resolver: &dyn Resolver,
    delegations: &[Envelope],
    seen: &mut SeenIds,
    sem: &SemanticContext,
) -> Result<Inbound, Verdict> {
    let envelope = Envelope::from_frame(frame)?;
    seen.sweep(now);
    let mut ctx = Context::new(now, resolver);
    ctx.delegations = delegations.to_vec();
    ctx.seen_ids = seen.set();
    ctx.supported = sem.supported.clone();
    let verified = envelope::verify(&envelope, &ctx, Some(frame))?;
    let mut sem = sem.clone();
    sem.encoded_size = Some(frame.len());
    let semantic = check_payload(&verified.payload, &sem);
    if !semantic.ok() {
        return Err(semantic);
    }
    seen.insert(verified.payload["id"].as_str().unwrap_or(""), now);
    Ok(Inbound { envelope, frame: frame.to_string(), verified, semantic })
}
