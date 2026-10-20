//! Successor groups: the vector-pinned tracker's decisions read as types, the checks a welcome to a successor needs
//! from the group itself, and where a conversation lives now.
//!
//! Spec: M§7.5 (a group whose hub is gone is succeeded by a group for the same conversation, created by a member at
//! its own mailbox, re-adding the last known roster; a successor is accepted only from a predecessor member re-adding
//! predecessor members, otherwise it is first contact; concurrent successors converge on the lowest `group_id`),
//! M§9.4 (the successor trigger).
//!
//! Impl (spec-gap 61): the decisions are `dsip_messaging::client::SuccessorTracker`'s. What a host does with the dead
//! group's pending items, and which roster it records for a group, stay the host's.

use std::collections::BTreeSet;

use dsip_core::envelope::Context;
use dsip_messaging::client::SuccessorTracker;
use dsip_mls::member_identity;
use openmls::prelude::{LeafNodeIndex, MlsGroup};
use serde_json::json;

/// What to do when asked to create a successor for a dead group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Create {
    /// This device already converged on a successor: use it.
    Use(String),
    /// Create one, re-adding these identities of the dead group's last known roster (this one excluded).
    Create {
        /// The identities to re-add.
        peers: Vec<String>,
    },
    /// Not created, for this reason (`not-a-member`).
    Refuse(String),
}

/// What converging on one successor per dead group asks of the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Converge {
    /// Join this successor: the conversation continues in it.
    Join(String),
    /// Leave this group: a lower successor exists (one this device kept or created).
    Leave(String),
    /// Decline this successor's welcome: a lower one exists.
    Decline(String),
    /// Not a valid successor: a new conversation under first contact, not kept as a successor.
    FirstContact(String),
}

fn converge(raw: Vec<serde_json::Value>) -> Vec<Converge> {
    raw.into_iter()
        .filter_map(|e| {
            let (name, g) = e.as_object()?.iter().next()?;
            let g = g.as_str()?.to_string();
            Some(match name.as_str() {
                "join" => Converge::Join(g),
                "leave" => Converge::Leave(g),
                "decline" => Converge::Decline(g),
                "first_contact" => Converge::FirstContact(g),
                _ => return None,
            })
        })
        .collect()
}

/// A device's successor tracker; persisted as the tracker itself.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Successors(SuccessorTracker);

impl Successors {
    /// Record (or refresh) a group this device is a member of, with its roster by identity (M§7.5: the last roster
    /// this device processed).
    pub fn member_of(&mut self, group: &str, roster: &[String]) {
        self.0.member_of(group, roster);
    }

    /// The successor this device converged on for `predecessor`.
    pub fn successor(&self, predecessor: &str) -> Option<&str> {
        self.0.successor(predecessor)
    }

    /// Asked to create a successor for `predecessor`, as `me`.
    pub fn create(&mut self, predecessor: &str, me: &str) -> Create {
        let d = self.0.step(&json!({"create": {"predecessor": predecessor}})).into_iter().next().unwrap_or_default();
        if let Some(w) = d["use"].as_str() {
            return Create::Use(w.to_string());
        }
        match d.get("create") {
            Some(c) => Create::Create {
                peers: c["roster"].as_array().into_iter().flatten().filter_map(|i| i.as_str()).filter(|i| *i != me).map(String::from).collect(),
            },
            None => Create::Refuse(d["refuse"].as_str().unwrap_or("").to_string()),
        }
    }

    /// This device created `group` as the successor of `predecessor`.
    pub fn created(&mut self, group: &str, predecessor: &str) -> Vec<Converge> {
        converge(self.0.step(&json!({"created": {"group": group, "successor_of": predecessor}})))
    }

    /// A welcome to `group`, a successor of `predecessor` created by `creator` with `roster` by identity.
    pub fn welcome(&mut self, group: &str, predecessor: &str, creator: &str, roster: &[String]) -> Vec<Converge> {
        converge(self.0.step(&json!({"welcome": {"group": group, "successor_of": predecessor, "creator": creator, "roster": roster}})))
    }

    /// The group the conversation of `group` lives in now: `group`, or the successors converged on from it, as far as
    /// this device is in them (`member`).
    pub fn live(&self, group: &str, member: impl Fn(&str) -> bool) -> String {
        let mut g = group.to_string();
        for _ in 0..8 {
            match self.0.successor(&g) {
                Some(w) if member(w) && w != g => g = w.to_string(),
                _ => break,
            }
        }
        g
    }

    /// The groups whose content makes up `group`'s thread, among `groups`: it and the predecessors it succeeds (M§7.5:
    /// the dead group stays readable and the conversation continues in the successor).
    pub fn lineage<'a>(&self, group: &str, groups: impl Iterator<Item = &'a str> + Clone) -> BTreeSet<String> {
        let mut set: BTreeSet<String> = [group.to_string()].into();
        loop {
            let more: Vec<String> = groups
                .clone()
                .filter(|g| !set.contains(*g) && self.0.successor(g).is_some_and(|w| set.contains(w)))
                .map(String::from)
                .collect();
            if more.is_empty() {
                return set;
            }
            set.extend(more);
        }
    }

    /// The tracker's state, as the vectors compare it.
    pub fn snapshot(&self) -> serde_json::Value {
        self.0.snapshot()
    }
}

/// The identity of a successor's creator: its leaf 0, the leaf that created the group (M§7.5); empty when that leaf
/// does not authenticate.
pub fn creator(group: &MlsGroup, ctx: &Context) -> String {
    member_identity(group, LeafNodeIndex::new(0), ctx).map(|w| w.identity).unwrap_or_default()
}
