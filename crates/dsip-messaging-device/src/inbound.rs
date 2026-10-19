//! Where one `items[]` element goes before any MLS processing, and what the delivery state records for it.
//!
//! Spec: M§5.4 (the cursor, acknowledged only once durably handled), M§6.5 rule 5 (a device's own deposits fanned
//! back to it, spec-gap 47), M§6.5 (seq gaps, spec-gap 69), M§8.5 (duplicates collapse), M§11.2 (`ephemeral` items
//! carry no cursor), M§12.3 step 5 (MLS items from before the device joined are history).
//!
//! Impl: the host passes the parts of its state the decision reads and writes ([`Inbound`]) and whether the item's
//! epoch is before this device joined the group; the decisions that need no further processing are committed to the
//! delivery state here, the rest ([`Route::FirstContact`], [`Route::Archive`], [`Route::Process`]) by the host after
//! it has handled them. Items released when a gap fills come back with [`Route::Process`] and are routed again.

use std::collections::{BTreeMap, HashSet};

use dsip_messaging::client::{GapTracker, Resume};
use serde_json::{json, Value};

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
    /// This device's own deposit fanned back (spec-gap 47): committed.
    Own,
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
            self.resume.commit(item, false);
            return Route::Own;
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
            let seq = item["seq"].as_i64().unwrap_or(0);
            let decisions = gap_tracker(self.gaps, self.resume, self.gap_timeout, &group, seq, now).step(&json!({"item": {"seq": seq, "class": class}}));
            if decisions.iter().any(|d| d["hold"] == json!(seq)) {
                let mut held = item.clone();
                held["held_release"] = json!(true);
                self.held_items.entry(group).or_default().push(held);
                self.resume.commit(item, true);
                return Route::Held;
            }
            for d in &decisions {
                if let Some(s) = d["process"].as_i64().filter(|s| *s != seq) {
                    if let Some(items) = self.held_items.get_mut(&group) {
                        if let Some(i) = items.iter().position(|h| h["seq"] == json!(s)) {
                            released.push(items.remove(i));
                        }
                    }
                }
            }
        }
        Route::Process { group, bytes, released }
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
