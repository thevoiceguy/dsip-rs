//! A device's history: what the vector-pinned history machine decides about each object it shows, sends, or opens
//! from the archive, read as types; the archive records those decisions ask for; and what was opened from the archive
//! waiting for the conversation it belongs to.
//!
//! Spec: M§12.1 (the current archive key), M§12.2 (what a device shows from MLS, its own sent content included, is
//! archived; spec-gap 51), M§12.3 (a new device reads history from the archive, and MLS items from its join epoch on),
//! M§8.5 (archive and MLS copies are duplicates), M§10.3 / M§10.5 (a sent read watermark is archived, spec-gap 68),
//! M§13.3 (a call event is archived as state, spec-gap 63).
//!
//! Impl (spec-gap 64): restored content and receipts are applied to their conversation's receipts once the device is
//! in it, to the conversation's group rather than the personal group when both carry it.

use std::collections::BTreeMap;

use dsip_messaging::client;
use serde_json::{json, Value};

use crate::archive::{self, Opened, Received};

/// The key an object is shown and deduplicated by: `conversation|sender|id` (M§8.5), and for a call event
/// `call|session`, one per session whichever device reported it (M§13.3, spec-gap 63).
pub fn object_key(obj: &Value) -> String {
    let s = |k: &str| obj[k].as_str().unwrap_or("");
    if obj["object"] == "call-event" {
        return format!("call|{}", s("session"));
    }
    format!("{}|{}|{}", s("conversation"), s("sender"), s("id"))
}

/// What the history machine decided.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Show this object (by its key): new to the timeline.
    Show(String),
    /// Already shown or applied (M§8.5).
    Duplicate(String),
    /// An archived receipt or call event (by its cursor): apply it as state, not as a timeline entry.
    Apply(Value),
    /// An archive item (by its cursor) under a key this device does not hold yet: kept until it arrives.
    Hold(Value),
    /// An MLS item (by its seq) from before this device joined: not for it (M§12.3).
    Prejoin(Value),
    /// Archive the object at `(group, seq)` under the key `akid` (M§12.2).
    Archive {
        /// The group, base64url.
        group: String,
        /// The hub's seq of the item.
        seq: i64,
        /// The current archive key.
        akid: String,
    },
}

impl Decision {
    /// Whether this is [`Decision::Show`].
    pub fn is_show(&self) -> bool {
        matches!(self, Decision::Show(_))
    }

    /// Whether this is [`Decision::Apply`].
    pub fn is_apply(&self) -> bool {
        matches!(self, Decision::Apply(_))
    }
}

fn decisions(raw: Vec<Value>) -> Vec<Decision> {
    raw.into_iter()
        .filter_map(|d| {
            let (name, v) = d.as_object()?.iter().next()?;
            let s = |v: &Value| v.as_str().unwrap_or("").to_string();
            Some(match name.as_str() {
                "show" => Decision::Show(s(v)),
                "duplicate" => Decision::Duplicate(s(v)),
                "apply" => Decision::Apply(v.clone()),
                "hold" => Decision::Hold(v.clone()),
                "prejoin" => Decision::Prejoin(v.clone()),
                "archive" => Decision::Archive { group: s(&v["group"]), seq: v["seq"].as_i64().unwrap_or(0), akid: s(&v["akid"]) },
                _ => return None,
            })
        })
        .collect()
}

/// One device's history machine.
#[derive(Debug, Clone, Default)]
pub struct History(client::History);

impl History {
    /// A history from what a device holds: its archive keys `(akid, created_at)` and the epoch it joined each group at.
    pub fn new<'a>(keys: impl IntoIterator<Item = (&'a str, i64)>, joined: impl IntoIterator<Item = (&'a str, u64)>) -> History {
        let keys: Vec<Value> = keys.into_iter().map(|(a, c)| json!({"akid": a, "created_at": c})).collect();
        let joined: serde_json::Map<String, Value> = joined.into_iter().map(|(g, e)| (g.to_string(), json!(e))).collect();
        History(client::History::new(&json!({"keys": keys, "joined": joined})))
    }

    /// This device joined `group` at `epoch`: MLS items from earlier epochs are history, not its (M§12.3).
    pub fn joined(&mut self, group: &str, epoch: u64) {
        self.0.step(&json!({"joined": {"group": group, "epoch": epoch}}));
    }

    /// The archive key `akid`, created at `created_at`, is held (M§12.1): what was held for it opens now.
    pub fn archive_key(&mut self, akid: &str, created_at: i64) -> Vec<Decision> {
        decisions(self.0.step(&json!({"archive_key": {"akid": akid, "created_at": created_at}})))
    }

    /// An archive item whose key this device does not hold.
    pub fn held(&mut self, item: &Value) -> Vec<Decision> {
        decisions(self.0.step(&json!({"archive": {"cursor": item["cursor"], "akid": item["akid"], "group": item["group"], "seq": item["seq"]}})))
    }

    /// An archive item opened (M§12.3 step 5); its payload's key is `id`.
    pub fn opened(&mut self, item: &Value, opened: &Opened, id: &str) -> Vec<Decision> {
        decisions(self.0.step(&archive::history_event(item, opened, id)))
    }

    /// An object received from MLS: `group`'s item `seq` at `epoch`, keyed `id`. Content is shown and archived; a call
    /// event is state, archived once (spec-gap 63).
    pub fn mls(&mut self, group: &str, seq: i64, epoch: u64, id: &str, object: &Value) -> Vec<Decision> {
        let mut e = json!({"group": group, "seq": seq, "epoch": epoch, "id": id});
        if object["object"] == "call-event" {
            e["object"] = json!("call-event");
        }
        decisions(self.0.step(&json!({"mls": e})))
    }

    /// This device's own `object`, keyed `id`, accepted at `group`'s `seq`: content is shown and archived (spec-gap
    /// 51); a read watermark or call event is archived as state (spec-gaps 68, 63). Nothing else it sends is history.
    pub fn sent(&mut self, group: &str, seq: i64, id: &str, object: &Value) -> Vec<Decision> {
        let history = match object["object"].as_str() {
            Some("content" | "call-event") => true,
            Some("receipt") => object["kind"] == "read",
            _ => false,
        };
        if !history {
            return vec![];
        }
        decisions(self.0.step(&json!({"sent": {"group": group, "seq": seq, "id": id, "object": object["object"]}})))
    }

    /// The current archive key: the greatest `created_at`, ties by `akid`.
    pub fn current_akid(&self) -> Option<String> {
        self.0.current_akid()
    }

    /// The machine's state: `timeline`, `held`, `current_akid`.
    pub fn snapshot(&self) -> Value {
        self.0.snapshot()
    }
}

/// The archive records `decisions` ask for, `(akid, record)`, for `object` received as `at` (M§12.2).
pub fn archive_records(decisions: &[Decision], at: &Received, object: &Value) -> Vec<(String, Value)> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Archive { akid, .. } => Some((akid.clone(), archive::record(at, object))),
            _ => None,
        })
        .collect()
}

/// Content and receipts opened from the archive, waiting for this device to be in their conversation (spec-gap 64).
#[derive(Debug, Clone, Default)]
pub struct Restored(Vec<Value>);

impl Restored {
    /// What a device persisted, `[{seq, object, conversation}]`.
    pub fn from_items(items: Vec<Value>) -> Restored {
        Restored(items)
    }

    /// What to persist.
    pub fn items(&self) -> &[Value] {
        &self.0
    }

    /// `object`, at seq `seq` of the archive, is to be applied to its conversation.
    pub fn push(&mut self, seq: i64, object: &Value) {
        self.0.push(json!({"seq": seq, "object": object, "conversation": object["conversation"]}));
    }

    /// Take what this device can apply now, by group, given its groups `(group, conversation, is personal)`: each
    /// item goes to its conversation's group, the conversation's own group before the personal group. The rest wait.
    pub fn ready<'a>(&mut self, groups: impl Iterator<Item = (&'a str, &'a str, bool)> + Clone) -> BTreeMap<String, Vec<Value>> {
        let mut by_group: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        let mut waiting = vec![];
        for r in std::mem::take(&mut self.0) {
            let target = groups.clone().filter(|(_, c, _)| r["conversation"] == *c).min_by_key(|(_, _, personal)| *personal).map(|(g, _, _)| g);
            match target {
                Some(g) => by_group.entry(g.to_string()).or_default().push(r),
                None => waiting.push(r),
            }
        }
        self.0 = waiting;
        by_group
    }
}
