//! A conversation's receipts and activity: what the vector-pinned receipts machine decides, read as types, with its
//! clock moved to the host's time before every event so that nothing the clock decides is lost.
//!
//! Spec: M§10.1 (the `receipt` object), M§10.2 (delivered receipts decided once per sync batch), M§10.3 (read
//! watermarks, at most one per 5 s), M§10.4 (played), M§10.5 (an undisclosed watermark goes to the personal group,
//! spec-gap 52), M§11.2 (activity shown until it expires), M§12.2 (a receipt that changed rendering is archived,
//! spec-gap 64).
//!
//! Impl: the decisions are `dsip_messaging::client::Client`'s. Each event first advances the machine to `now`, and
//! what that advance emits (a read watermark held back by the 5 s interval) comes back with the event's own
//! decisions; a host that advanced and discarded it lost the watermark.

use dsip_messaging::client::Client;
use serde_json::{json, Value};

/// A receipt the machine decided to send (M§10.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    /// `delivered`, `read` or `played`.
    pub kind: String,
    /// An undisclosed read watermark: sent to this identity's personal group, not the conversation (M§10.5).
    pub personal: bool,
    /// The content ids a `delivered` or `played` receipt names.
    pub targets: Option<Value>,
    /// The content id a `read` receipt names.
    pub through: Option<Value>,
}

impl Receipt {
    /// The `receipt` object for the conversation `conversation`, sent by `sender` as object `id` at `now` (M§10.1).
    pub fn object(&self, conversation: &str, sender: &str, id: &str, now: i64) -> Value {
        let mut obj = json!({"object": "receipt", "id": id, "conversation": conversation, "sender": sender, "sent_at": now,
            "kind": self.kind});
        if let Some(t) = &self.targets {
            obj["targets"] = t.clone();
        }
        if let Some(t) = &self.through {
            obj["through"] = t.clone();
        }
        obj
    }
}

/// What the receipts machine decided.
#[derive(Debug, Clone, PartialEq)]
pub enum Emission {
    /// Send this receipt.
    Receipt(Receipt),
    /// Send this activity indicator, sealed (M§11.1).
    Activity {
        /// The activity, e.g. `typing`.
        activity: String,
        /// `active` or `stopped`.
        state: String,
    },
    /// The receipts at this seq of the batch changed rendering: archive them (M§12.2, spec-gap 64).
    Archive(i64),
}

fn emissions(raw: Vec<Value>) -> Vec<Emission> {
    raw.into_iter()
        .filter_map(|e| {
            if let Some(seq) = e["archive"]["seq"].as_i64() {
                return Some(Emission::Archive(seq));
            }
            let send = e.get("send")?;
            if let Some(a) = send["activity"].as_str() {
                return Some(Emission::Activity { activity: a.to_string(), state: send["state"].as_str().unwrap_or("active").to_string() });
            }
            Some(Emission::Receipt(Receipt {
                kind: send["receipt"].as_str()?.to_string(),
                personal: send["to"] == "personal",
                targets: send.get("targets").cloned(),
                through: send.get("through").cloned(),
            }))
        })
        .collect()
}

/// One conversation's receipts machine.
pub struct Receipts(Client);

impl Receipts {
    /// A machine for the identity `me` with the disclosure `policy` (`{delivered, read, played, activity}`), at `now`.
    pub fn new(me: &str, policy: &Value, now: i64) -> Receipts {
        Receipts(Client::new(&json!({"now": now, "me": me, "member_identities": 2, "policy": policy})))
    }

    /// The machine's clock.
    pub fn now(&self) -> i64 {
        self.0.now()
    }

    /// Move the clock to `now` (never back): a read watermark held back by the interval may go out (M§10.3), and
    /// expired activity stops being shown (M§11.2).
    pub fn at(&mut self, now: i64) -> Vec<Emission> {
        let delta = now - self.0.now();
        if delta <= 0 {
            return vec![];
        }
        emissions(self.0.step(&json!({"advance": delta})))
    }

    fn event(&mut self, now: i64, ev: Value) -> Vec<Emission> {
        let mut out = self.at(now);
        out.extend(emissions(self.0.step(&ev)));
        out
    }

    /// A sync batch of this conversation, `[{seq, object, …}]` (M§10.2): delivered receipts for its fresh content, and
    /// the receipts in it that changed rendering, to archive.
    pub fn sync(&mut self, now: i64, items: Vec<Value>) -> Vec<Emission> {
        self.event(now, json!({"sync": {"items": items}}))
    }

    /// This device's own `object`, accepted at `seq` (M§10.2): content is known to the machine, so that receipts for
    /// it are booked; nothing else it sends is.
    pub fn own(&mut self, now: i64, seq: i64, object: &Value) -> Vec<Emission> {
        if object["object"] != "content" {
            return self.at(now);
        }
        self.sync(now, vec![json!({"seq": seq, "object": object})])
    }

    /// Content and receipts opened from archive (spec-gap 64): rendering state only; nothing is sent or archived for
    /// them, so what comes back is the clock's.
    pub fn restore(&mut self, now: i64, items: Vec<Value>) -> Vec<Emission> {
        self.event(now, json!({"restore": {"items": items}}))
    }

    /// The user read through content `through` (M§10.3).
    pub fn read(&mut self, now: i64, through: &Value) -> Vec<Emission> {
        self.event(now, json!({"read": {"through": through}}))
    }

    /// The user played media content `id` (M§10.4).
    pub fn play(&mut self, now: i64, id: &str) -> Vec<Emission> {
        self.event(now, json!({"play": {"id": id}}))
    }

    /// The user's own activity `activity` is `state` (M§11.1).
    pub fn activity(&mut self, now: i64, activity: &str, state: &str) -> Vec<Emission> {
        self.event(now, json!({"activity": {"activity": activity, "state": state}}))
    }

    /// A member's activity arrived, shown until `expires_at`, the deposit's (M§11.2, spec-gap 49).
    pub fn activity_in(&mut self, now: i64, sender: &Value, activity: &Value, state: &Value, expires_at: &Value) -> Vec<Emission> {
        self.event(now, json!({"activity_in": {"sender": sender, "activity": activity, "state": state, "expires_at": expires_at}}))
    }

    /// The machine's state: `timeline`, `delivered`, `played`, `read_through`, `activity`.
    pub fn snapshot(&self) -> Value {
        self.0.snapshot()
    }
}

/// The receipt items at `seq` of a batch: what an [`Emission::Archive`] archives, each under the group it arrived in
/// (its `src`).
pub fn archived(items: &[Value], seq: i64) -> impl Iterator<Item = &Value> {
    items.iter().filter(move |it| it["seq"] == json!(seq) && it["object"]["object"] == "receipt")
}
