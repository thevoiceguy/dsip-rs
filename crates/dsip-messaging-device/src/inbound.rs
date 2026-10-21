//! Where one `items[]` element goes before any MLS processing, and what the delivery state records for it.
//!
//! Spec: M§5.4 (the cursor, acknowledged only once durably handled), M§6.5 rule 5 (a device's own deposits fanned
//! back to it, spec-gap 47), M§6.5 (seq gaps, spec-gap 69), M§8.5 (duplicates collapse), M§11.2 (`ephemeral` items
//! carry no cursor), M§12.3 step 5 (MLS items from before the device joined are history), M§5.4 (an item and its MLS
//! effect committed together, spec-gap 44; one that cannot be processed, spec-gap 138).
//!
//! Impl: the host passes the parts of its state the decision reads and writes ([`Inbound`]) and whether the item's
//! epoch is before this device joined the group; the decisions that need no further processing are committed to the
//! delivery state here, the rest ([`Route::FirstContact`], [`Route::Archive`], [`Route::Process`]) by the host after
//! it has handled them. Items released when a gap fills come back with [`Route::Process`] and are routed again.

use std::collections::{BTreeMap, HashSet};

use dsip_messaging::client::{GapTracker, Resume};
use dsip_mls::MlsError;
use serde_json::{json, Value};

use crate::{Outcome, Store};

/// The parts of a device's delivery state that routing reads and writes.
pub struct Inbound<'a> {
    /// The cursor and seq positions (M§5.4).
    pub resume: &'a mut Resume,
    /// Digests of this device's own deposits (spec-gap 47).
    pub own: &'a HashSet<String>,
    /// Seq gap trackers per group (spec-gap 69).
    pub gaps: &'a mut BTreeMap<String, GapTracker>,
    /// Items held behind a gap, per group, durable until released.
    pub held_items: &'a mut BTreeMap<String, Vec<Value>>,
    /// Seconds a gap may stay open (spec-gap 69).
    pub gap_timeout: i64,
}

/// What to do with one item.
#[derive(Debug, PartialEq)]
pub enum Route {
    /// `ephemeral` (M§11.2): never stored and without a cursor; nothing committed.
    Ephemeral,
    /// Already durably processed (M§8.5): committed as a duplicate.
    Duplicate,
    /// An `introduction` or `grant` (M§14.1): the host handles it, then commits.
    FirstContact,
    /// An `archive` item (M§12.2): the host opens or keeps it, then commits.
    Archive,
    /// A group's latest GroupInfo (M§6.8): committed; the host keeps it.
    GroupInfo {
        /// The group, base64url.
        group: String,
        /// The GroupInfo, base64url.
        mls: Value,
    },
    /// A class this device does not process: committed.
    Other,
    /// This device's own deposit fanned back (spec-gap 47): committed. Its seq counts for the gap tracker as its
    /// `accepted` would (spec-gap 69), so it may fill a gap: the held items it released, to route after it.
    Own {
        /// Held items released by this one.
        released: Vec<Value>,
    },
    /// From before this device joined the group, or a group it is not in (M§12.3): committed.
    PreJoin,
    /// Beyond a seq gap (spec-gap 69): committed as handled and stored in `held_items`.
    Held,
    /// Process it with MLS: its group and bytes, and the held items the gap filling released, in seq order, to route
    /// after it. The host commits it with its MLS effect.
    Process {
        /// The group, base64url (empty for a welcome).
        group: String,
        /// The MLS message.
        bytes: Vec<u8>,
        /// Held items released by this one.
        released: Vec<Value>,
    },
}

/// A group's gap tracker, starting from the seq position this device has committed, or, for a device that has just
/// joined and processed nothing, from the item at hand: what came before its welcome is not its gap (M§6.5, M§12.3
/// step 5; spec-gap 69). `now` starts the tracker's clock.
pub fn gap_tracker<'g>(gaps: &'g mut BTreeMap<String, GapTracker>, resume: &Resume, gap_timeout: i64, group: &str, first_seq: i64, now: i64)
    -> &'g mut GapTracker {
    let committed = resume.snapshot()["groups"][group]["contiguous"].as_i64().unwrap_or(0);
    let contiguous = if committed == 0 { (first_seq - 1).max(0) } else { committed };
    gaps.entry(group.to_string()).or_insert_with(|| GapTracker::new(&json!({"now": now, "contiguous": contiguous, "gap_timeout": gap_timeout})))
}

impl<'a> Inbound<'a> {
    /// [`gap_tracker`] over these parts.
    pub fn gap_of_from(self, group: &str, first_seq: i64, now: i64) -> &'a mut GapTracker {
        gap_tracker(self.gaps, self.resume, self.gap_timeout, group, first_seq, now)
    }

    /// Route `item`. `member` is whether this device is in the item's group; `prejoin(epoch)` whether an epoch is
    /// before it joined.
    pub fn route(&mut self, item: &Value, member: bool, prejoin: impl FnOnce(u64) -> bool, now: i64) -> Route {
        let class = item["class"].as_str().unwrap_or("");
        if class == "ephemeral" {
            return Route::Ephemeral;
        }
        if self.resume.is_duplicate(item) {
            self.resume.commit(item, true);
            return Route::Duplicate;
        }
        match class {
            "introduction" | "grant" => return Route::FirstContact,
            "archive" => return Route::Archive,
            "group-info" => {
                self.resume.commit(item, false);
                return Route::GroupInfo { group: item["group"].as_str().unwrap_or("").to_string(), mls: item["mls"].clone() };
            }
            "welcome" | "handshake" | "application" => {}
            _ => {
                self.resume.commit(item, false);
                return Route::Other;
            }
        }
        let group = item["group"].as_str().unwrap_or("").to_string();
        let bytes = item["mls"].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
        if class == "welcome" {
            return Route::Process { group, bytes, released: vec![] };
        }
        if self.own.contains(&dsip_mls::digest(&bytes)) {
            // spec-gap 69: the copy may arrive before its accepted, or instead of it (a binding lost on the way); either
            // way it is no gap
            let released = if member && item["held_release"] != json!(true) { self.gap_step(&group, item, now).1 } else { vec![] };
            self.resume.commit(item, false);
            return Route::Own { released };
        }
        let pre = match dsip_mls::message_header(&bytes) {
            Ok((_, epoch, _)) => !member || prejoin(epoch),
            Err(_) => false,
        };
        if pre {
            self.resume.commit(item, false);
            return Route::PreJoin;
        }
        let mut released = vec![];
        if item["held_release"] != json!(true) && member {
            let (hold, more) = self.gap_step(&group, item, now);
            if hold {
                let mut held = item.clone();
                held["held_release"] = json!(true);
                self.held_items.entry(group).or_default().push(held);
                self.resume.commit(item, true);
                return Route::Held;
            }
            released = more;
        }
        Route::Process { group, bytes, released }
    }

    /// Step `group`'s gap tracker with `item` (M§6.5, spec-gap 69): whether the item is held behind a gap, and the held
    /// items its seq releases, in seq order.
    fn gap_step(&mut self, group: &str, item: &Value, now: i64) -> (bool, Vec<Value>) {
        let seq = item["seq"].as_i64().unwrap_or(0);
        let class = item["class"].as_str().unwrap_or("");
        let decisions = gap_tracker(self.gaps, self.resume, self.gap_timeout, group, seq, now).step(&json!({"item": {"seq": seq, "class": class}}));
        if decisions.iter().any(|d| d["hold"] == json!(seq)) {
            return (true, vec![]);
        }
        let mut released = vec![];
        for d in &decisions {
            if let Some(s) = d["process"].as_i64().filter(|s| *s != seq) {
                if let Some(items) = self.held_items.get_mut(group) {
                    if let Some(i) = items.iter().position(|h| h["seq"] == json!(s)) {
                        released.push(items.remove(i));
                    }
                }
            }
        }
        (false, released)
    }

    /// Process the item [`Route::Process`] returned, with `process`, and commit it with its MLS effect (M§5.4, spec-gap
    /// 44); a sibling's welcome is committed without counting as a join (spec-gap 51).
    ///
    /// With `roll_back` ([`crate::Config::roll_back_unprocessable`]), `process` runs inside `store`'s transaction and
    /// the delivery state recording the item is written in the same one, under `resume`. If either fails, both roll
    /// back, the host must reload any group it holds in memory, and the item is committed as handled.
    ///
    /// Impl (spec-gap 138): an item that fails processing once fails it again on every redelivery, so committing it as
    /// handled lets the device acknowledge it instead of receiving it after every sync. The error is still returned
    /// for the host to report. Without `roll_back`, `process` runs outside any transaction and a failed item stays
    /// uncommitted.
    pub fn commit_processed<S: Store>(&mut self, store: &S, item: &Value, roll_back: bool,
                                      process: impl FnOnce() -> Result<Outcome, MlsError>) -> Result<Outcome, MlsError> {
        if !roll_back {
            let outcome = process()?;
            self.resume.commit(item, matches!(outcome, Outcome::NotForDevice));
            return Ok(outcome);
        }
        let before = self.resume.clone();
        let resume = &mut *self.resume;
        let result = store.atomically(|| {
            let outcome = process()?;
            resume.commit(item, matches!(outcome, Outcome::NotForDevice));
            store.put("resume", &resume.snapshot())?;
            Ok(outcome)
        });
        if result.is_err() {
            *self.resume = before;
            self.resume.commit(item, false);
        }
        result
    }

    /// Advance every gap tracker to `now`. A group whose gap has not filled in time (M§6.5, spec-gap 69) loses its
    /// held items and tracker, and its seq positions pass everything seen (the items behind the gap are for epochs
    /// this device can no longer reach); it is returned, with the seqs it held, for the host to re-join by external
    /// commit (M§6.8).
    pub fn gap_timeouts(&mut self, now: i64) -> Vec<(String, Value)> {
        let mut out = vec![];
        for (group, g) in self.gaps.iter_mut() {
            let delta = now - g.now();
            if delta <= 0 {
                continue;
            }
            for e in g.step(&json!({"advance": delta})) {
                if let Some(r) = e.get("rejoin") {
                    out.push((group.clone(), r["held"].clone(), g.snapshot()["contiguous"].as_i64().unwrap_or(0)));
                }
            }
        }
        out.into_iter()
            .map(|(group, held, through)| {
                self.held_items.remove(&group);
                self.resume.rejoined(&group, through);
                self.gaps.remove(&group);
                (group, held)
            })
            .collect()
    }

    /// This device was removed from `group` (spec-gap 127): a welcome adding it back is a join again, and its gap
    /// tracker and held items there go, so a welcome back starts counting afresh (spec-gap 83). The seq positions
    /// stay: what was processed remains a duplicate.
    pub fn removed(&mut self, group: &str) {
        self.resume.removed(group);
        self.gaps.remove(group);
        self.held_items.remove(group);
    }
}
