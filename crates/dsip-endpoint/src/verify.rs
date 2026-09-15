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

/// Ids seen within the replay window, each with the time it may be forgotten.
///
/// Spec: §12.9 — "Message id values MUST be tracked for deduplication within the window."
/// Impl (spec-gap 31): an `introduction` is accepted until its `expires_at` (up to
/// 604,800 s), so its id is tracked until then instead of for the 300 s window.
#[derive(Debug, Default)]
pub struct SeenIds {
    ids: HashMap<String, i64>,
}

impl SeenIds {
    /// Forget ids whose tracking period has ended.
    pub fn sweep(&mut self, now: i64) {
        self.ids.retain(|_, forget_at| *forget_at >= now);
    }

    /// Record an id as seen at `now`, tracked for the replay window or until
    /// `track_until`, whichever is later.
    pub fn insert(&mut self, id: &str, now: i64, track_until: i64) {
        self.ids.insert(id.to_string(), track_until.max(now + REPLAY_WINDOW_S));
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
    let p = &verified.payload;
    // Impl (spec-gap 31): held introductions stay replay-tracked until they expire.
    let track_until = if verified.msg_type() == "introduction" { p["expires_at"].as_i64().unwrap_or(now) } else { now };
    seen.insert(p["id"].as_str().unwrap_or(""), now, track_until);
    Ok(Inbound { envelope, frame: frame.to_string(), verified, semantic })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introduction_ids_outlive_the_replay_window() {
        let mut seen = SeenIds::default();
        seen.insert("invite", 1_000, 1_000);
        seen.insert("intro", 1_000, 1_000 + 604_800);
        seen.sweep(1_000 + REPLAY_WINDOW_S + 1);
        assert!(!seen.set().contains("invite"));
        assert!(seen.set().contains("intro"));
        seen.sweep(1_000 + 604_800 + 1);
        assert!(seen.set().is_empty());
    }
}
