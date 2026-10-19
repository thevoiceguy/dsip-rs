//! A device's outbox: the application items pending per group until the hub accepts them, and the outage machine of
//! each group whose hub has been unreachable.
//!
//! Spec: M§9.2 (an item is pending until the hub's `accepted`), M§9.3 (a retry re-deposits the same bytes), M§9.4 (an
//! unreachable hub: items kept, retried with the §13.2 backoff, handed to the successor past the threshold).
//!
//! Impl (spec-gap 72): the decisions are `dsip_messaging::client::HubOutage`'s; this keeps the items it names and the
//! machine per group, and advances every machine on the host's clock ([`Outbox::due`]), so that an outage starts at
//! the time the hub stopped answering, never at the time the machine was made. Items are host-shaped JSON with an
//! `id`; the host deposits them and persists the outbox.

use std::collections::BTreeMap;

use dsip_messaging::client::HubOutage;
use serde_json::{json, Value};

/// What became of a new item.
#[derive(Debug, PartialEq, Eq)]
pub enum Deposit {
    /// Deposit it now.
    Send,
    /// The hub is down: it waits behind the pending ones and goes out with them.
    Queued,
    /// The group was abandoned after its outage: the item is not kept; it belongs in the successor.
    Abandoned,
}

/// Pending items and outages, per group.
#[derive(Debug, Default)]
pub struct Outbox {
    /// Pending items per group, oldest first: host JSON with an `id`.
    pub items: BTreeMap<String, Vec<Value>>,
    /// The outage machine per group, once there is one.
    pub outages: BTreeMap<String, HubOutage>,
    /// Seconds an outage lasts before the successor trigger (M§9.4: the client's own; 24 h RECOMMENDED).
    pub hub_timeout: i64,
}

impl Outbox {
    /// An empty outbox.
    pub fn new(hub_timeout: i64) -> Outbox {
        Outbox { hub_timeout, ..Outbox::default() }
    }

    /// The pending item `id` of `group`.
    pub fn item(&self, group: &str, id: &str) -> Option<&Value> {
        self.items.get(group)?.iter().find(|i| i["id"] == id)
    }

    /// The pending item `id` of `group`, to change in place.
    pub fn item_mut(&mut self, group: &str, id: &str) -> Option<&mut Value> {
        self.items.get_mut(group)?.iter_mut().find(|i| i["id"] == id)
    }

    /// Drop the pending item `id` of `group`, which the hub accepted or refused for good.
    pub fn remove(&mut self, group: &str, id: &str) {
        if let Some(items) = self.items.get_mut(group) {
            items.retain(|i| i["id"] != id);
        }
    }

    /// How many items `group` has pending.
    pub fn pending(&self, group: &str) -> usize {
        self.items.get(group).map_or(0, Vec::len)
    }

    /// Whether `group`'s hub is down.
    pub fn is_down(&self, group: &str) -> bool {
        self.outages.get(group).is_some_and(HubOutage::is_down)
    }

    /// Whether `group` was abandoned after its outage.
    pub fn is_abandoned(&self, group: &str) -> bool {
        self.outages.get(group).is_some_and(HubOutage::is_abandoned)
    }

    /// `group`'s outage machine, made now if it has none.
    pub fn outage_mut(&mut self, group: &str, now: i64) -> &mut HubOutage {
        let timeout = self.hub_timeout;
        self.outages.entry(group.to_string()).or_insert_with(|| HubOutage::new(&json!({"now": now, "hub_timeout": timeout})))
    }

    /// A new item for `group`. With `track`, the group's outage machine follows every deposit from now on; without, it
    /// is made when the hub first proves unreachable ([`Outbox::unreachable`]).
    pub fn deposit(&mut self, group: &str, item: Value, now: i64, track: bool) -> Deposit {
        if track {
            self.outage_mut(group, now);
        }
        if self.is_abandoned(group) {
            return Deposit::Abandoned;
        }
        let id = item["id"].as_str().unwrap_or("").to_string();
        self.items.entry(group.to_string()).or_default().push(item);
        let queued = self.outages.get_mut(group).is_some_and(|o| o.deposit(&id).iter().any(|e| e.get("queued").is_some()));
        if queued { Deposit::Queued } else { Deposit::Send }
    }

    /// The hub answered item `id` of `group` (`reason` `None` for `accepted`): the outage machine's emissions, if the
    /// group has one. An answer that is an outage (M§9.4) keeps the item pending.
    pub fn answered(&mut self, group: &str, id: &str, reason: Option<&str>) -> Vec<Value> {
        self.outages.get_mut(group).map(|o| o.answer(id, reason)).unwrap_or_default()
    }

    /// Item `id` of `group` met an unreachable hub, or (`silent`) no answer at all: the outage starts now if it had not.
    /// Whether it started, and the machine's emissions.
    pub fn unreachable(&mut self, group: &str, id: &str, silent: bool, now: i64) -> (bool, Vec<Value>) {
        let timeout = self.hub_timeout;
        let pending: Vec<Value> = self.items.get(group).into_iter().flatten().map(|i| i["id"].clone()).collect();
        let o = self.outages.entry(group.to_string())
            .or_insert_with(|| HubOutage::new(&json!({"now": now, "hub_timeout": timeout, "pending": pending})));
        let started = !o.is_down();
        let ems = if silent { o.no_answer(id) } else { o.answer(id, Some("mailbox.hub-unreachable")) };
        (started && o.is_down(), ems)
    }

    /// Advance every outage machine to `now`: the groups with something to do and what (a retry due, the successor
    /// trigger, a hand-over retry).
    pub fn due(&mut self, now: i64) -> Vec<(String, Vec<Value>)> {
        let mut out = vec![];
        for (g, o) in &mut self.outages {
            // advanced even by 0: a retry due now (a restored outage's first) goes out on this tick
            let ems = o.advance((now - o.now()).max(0));
            if !ems.is_empty() {
                out.push((g.clone(), ems));
            }
        }
        out
    }

    /// Restore `group`'s outage after a restart (its items restored first): down since `down_since`, the first retry due
    /// now, or, without it, a machine for a hub that was up.
    pub fn restore_outage(&mut self, group: &str, down_since: Option<i64>, now: i64) {
        let o = match down_since {
            Some(since) => {
                let ids: Vec<Value> = self.items.get(group).into_iter().flatten().map(|i| i["id"].clone()).collect();
                HubOutage::new(&json!({"now": now, "hub_timeout": self.hub_timeout, "pending": ids, "down_since": since}))
            }
            None => HubOutage::new(&json!({"now": now, "hub_timeout": self.hub_timeout})),
        };
        self.outages.insert(group.to_string(), o);
    }

    /// Take `group`'s pending items, for its successor (M§9.4).
    pub fn take(&mut self, group: &str) -> Vec<Value> {
        self.items.remove(group).unwrap_or_default()
    }

    /// Forget `group`: no items, no outage.
    pub fn forget(&mut self, group: &str) {
        self.items.remove(group);
        self.outages.remove(group);
    }
}
