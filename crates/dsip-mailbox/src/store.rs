//! The bytes behind the cursors.
//!
//! Spec: M§5.4 — `items` carries what was stored; the state machine owns cursors, retention and
//! ordering, so this is only the payload side of the same records. Impl: in memory, as the
//! reference relay's frame store is.

use std::collections::HashMap;

use serde_json::{json, Value};

/// One stored item, as `items` will carry it (M§5.4).
#[derive(Debug, Clone)]
pub struct Item {
    /// Deposit class.
    pub class: String,
    /// Group id (base64url).
    pub group: String,
    /// The service that deposited it.
    pub source: String,
    /// Hub sequence, for `handshake` and `application`.
    pub seq: Option<i64>,
    /// MLS bytes (base64url), when the class carries them.
    pub mls: Option<String>,
    /// Hub reference, on a `welcome`.
    pub hub: Option<Value>,
    /// Archive bytes (base64url), on an `archive`.
    pub archive: Option<String>,
    /// Archive key id.
    pub akid: Option<String>,
    /// When it was stored.
    pub stored_at: i64,
    /// On an `ephemeral` deposit: the sealed activity (M§11.1).
    pub sealed: Option<String>,
    /// On an `ephemeral` deposit: the originating `expires_at`, carried unchanged (M§11.2, spec-gap 49).
    pub expires_at: Option<i64>,
    /// The ciphertext manifest of blobs the content references (M§5.2, M§8.4): no keys.
    pub blobs: Option<Value>,
    /// On a commit deposit to a hub: the Welcome for the identities it adds (M§5.2).
    pub welcome: Option<String>,
    /// On a commit deposit to a hub: the grants authorizing each add (M§14.2).
    pub grants: Option<Value>,
    /// On a commit deposit to a hub: the depositing device's envelope, compact, as `origin` (M§14.2).
    pub origin: Option<String>,
}

impl Item {
    /// The `items[]` element for this record.
    pub fn to_value(&self, cursor: &str) -> Value {
        let mut v = json!({"cursor": cursor, "stored_at": self.stored_at, "class": self.class, "group": self.group,
                           "source": self.source});
        for (k, opt) in [("mls", &self.mls), ("archive", &self.archive), ("akid", &self.akid)] {
            if let Some(s) = opt {
                v[k] = json!(s);
            }
        }
        if let Some(seq) = self.seq {
            v["seq"] = json!(seq);
        }
        if let Some(b) = &self.blobs {
            v["blobs"] = b.clone();
        }
        if let Some(h) = &self.hub {
            v["hub"] = h.clone();
        }
        v
    }

    /// Build a record from a deposit payload.
    pub fn from_deposit(p: &Value, source: &str, now: i64) -> Item {
        let s = |k: &str| p.get(k).and_then(Value::as_str).map(String::from);
        Item {
            class: s("class").unwrap_or_default(),
            group: s("group").unwrap_or_default(),
            source: source.to_string(),
            seq: p.get("seq").and_then(Value::as_i64),
            mls: s("mls"),
            hub: p.get("hub").cloned(),
            archive: s("archive"),
            akid: s("akid"),
            stored_at: now,
            blobs: p.get("blobs").cloned(),
            sealed: s("sealed"),
            expires_at: p["expires_at"].as_i64(),
            welcome: s("welcome"),
            grants: p.get("grants").cloned(),
            origin: None,
        }
    }
}

/// Cursor → item, plus the KeyPackage bytes the directory serves (M§5.5).
#[derive(Debug, Default)]
pub struct Store {
    items: HashMap<String, Item>,
    key_packages: HashMap<String, Vec<String>>,
    last_resort: HashMap<String, String>,
}

impl Store {
    /// Record an item under the cursor the state machine assigned.
    pub fn put(&mut self, cursor: &str, item: Item) {
        self.items.insert(cursor.to_string(), item);
    }

    /// The item at a cursor.
    pub fn get(&self, cursor: &str) -> Option<&Item> {
        self.items.get(cursor)
    }

    /// Forget cursors the state machine no longer lists (queue-mode deletion, pending-group expiry).
    pub fn retain(&mut self, live: &[String]) {
        self.items.retain(|c, _| live.iter().any(|l| l == c));
    }

    /// Add uploaded KeyPackages for a device.
    pub fn add_key_packages(&mut self, device: &str, packages: Vec<String>, last_resort: Option<String>) {
        self.key_packages.entry(device.to_string()).or_default().extend(packages);
        if let Some(lr) = last_resort {
            self.last_resort.insert(device.to_string(), lr);
        }
    }

    /// Take the bytes for a serving decision the state machine made: `one-time` consumes, `last-resort` does not.
    pub fn take_key_package(&mut self, device: &str, kind: &str) -> Option<String> {
        if kind == "one-time" {
            self.key_packages.get_mut(device).and_then(|v| if v.is_empty() { None } else { Some(v.remove(0)) })
        } else {
            self.last_resort.get(device).cloned()
        }
    }
}
