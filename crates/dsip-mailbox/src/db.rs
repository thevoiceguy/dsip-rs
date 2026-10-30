//! The mailbox service's state on disk: one SQLite database, written per change (service-nodes plan S4).
//!
//! Spec: none (infrastructure).
//! Impl (spec-gap 59): `<state>/mailbox.sqlite` holds two tables. `items` has one row per stored item (owner, cursor):
//! the mailbox machine's record of it and the payload (M§5.4), the bulk of the bytes, written when the item is stored
//! and deleted when the machine drops it, and not otherwise rewritten. `parts` holds the rest of the service state
//! as JSON documents, split by owner (the mailbox machine without its items, and the KeyPackages), by hubbed group
//! (the hub machine, the hub's public MLS view) and by kind for the remainder (the enrolment, fan-out, hub
//! references, revocations, the seen-id window…): a save compares each part with what it last wrote (SHA-256) and
//! writes only those that changed, in one transaction with the item rows. The database runs in WAL mode with
//! `synchronous = FULL`, so a deposit is acknowledged only once it is durable (M§9; spec-gap 99). It replaces
//! `mailbox-state.json`, the whole state rewritten after every change, which a mailbox upgraded from it imports once.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

/// The service's database.
pub(crate) struct Db {
    conn: Connection,
    /// Each part's digest as last written.
    written: HashMap<String, [u8; 32]>,
}

/// One item row change in a save.
pub(crate) enum Row {
    /// An item stored: its owner, cursor, order `n`, the machine's record and the payload.
    Put { owner: String, cursor: String, n: i64, record: String, item: Option<String> },
    /// An item the machine dropped.
    Delete { owner: String, cursor: String },
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

impl Db {
    /// Open (or create) the database at `path`.
    pub(crate) fn open(path: &Path) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS parts (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS items (owner TEXT NOT NULL, cursor TEXT NOT NULL, n INTEGER NOT NULL,
                                               record TEXT NOT NULL, item TEXT, PRIMARY KEY (owner, cursor));",
        )?;
        Ok(Db { conn, written: HashMap::new() })
    }

    /// Whether the database holds no state yet.
    pub(crate) fn is_empty(&self) -> rusqlite::Result<bool> {
        Ok(self.conn.query_row("SELECT key FROM parts LIMIT 1", [], |r| r.get::<_, String>(0)).optional()?.is_none())
    }

    /// The saved state, assembled in the shape `mailbox-state.json` had (format 2), so one restore reads both.
    pub(crate) fn load(&mut self) -> Result<Value, String> {
        let mut v = Map::new();
        let (mut owners, mut hubs, mut views) = (Map::new(), Map::new(), Map::new());
        {
            let mut q = self.conn.prepare("SELECT key, value FROM parts").map_err(|e| e.to_string())?;
            let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
            for row in rows {
                let (key, text) = row.map_err(|e| e.to_string())?;
                let value: Value = serde_json::from_str(&text).map_err(|e| format!("part {key}: {e}"))?;
                self.written.insert(key.clone(), digest(&text));
                match key.split_once('/') {
                    Some(("owner", id)) => {
                        let store = json!({"items": {}, "key_packages": value["key_packages"], "last_resort": value["last_resort"]});
                        let mut mailbox = value["mailbox"].clone();
                        mailbox["items"] = json!([]);
                        owners.insert(id.to_string(), json!({"mailbox": mailbox, "store": store}));
                    }
                    Some(("hub", g)) => {
                        hubs.insert(g.to_string(), value);
                    }
                    Some(("view", g)) => {
                        views.insert(g.to_string(), value);
                    }
                    _ => {
                        v.insert(key, value);
                    }
                }
            }
        }
        // the machine lists its items in the order it stored them (`n`)
        let mut q = self.conn.prepare("SELECT owner, cursor, record, item FROM items ORDER BY owner, n").map_err(|e| e.to_string())?;
        let rows = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (owner, cursor, record, item) = row.map_err(|e| e.to_string())?;
            let Some(o) = owners.get_mut(&owner) else {
                tracing::warn!("database: item {cursor} of {owner}, who has no mailbox here: skipped");
                continue;
            };
            let record: Value = serde_json::from_str(&record).map_err(|e| format!("item {owner} {cursor}: {e}"))?;
            if let Some(a) = o["mailbox"]["items"].as_array_mut() {
                a.push(record);
            }
            if let Some(text) = item {
                o["store"]["items"][&cursor] = serde_json::from_str(&text).map_err(|e| format!("item {owner} {cursor}: {e}"))?;
            }
        }
        v.insert("format".into(), json!(2));
        v.insert("owners".into(), Value::Object(owners));
        v.insert("hubs".into(), Value::Object(hubs));
        v.insert("views".into(), Value::Object(views));
        Ok(Value::Object(v))
    }

    /// Write a save: every part of the state as it now is (`key → value`; only those that changed since they were
    /// last written are written, and a part written before and absent now is deleted, an owner's with its items) and
    /// the item rows that changed. One transaction: all of it, or nothing.
    pub(crate) fn write(&mut self, parts: Vec<(String, Value)>, rows: &[Row]) -> rusqlite::Result<()> {
        let mut written = HashMap::with_capacity(parts.len());
        let tx = self.conn.transaction()?;
        for (key, value) in &parts {
            let text = value.to_string();
            let d = digest(&text);
            if self.written.get(key) != Some(&d) {
                tx.execute("INSERT OR REPLACE INTO parts (key, value) VALUES (?1, ?2)", params![key, text])?;
            }
            written.insert(key.clone(), d);
        }
        for key in self.written.keys().filter(|k| !written.contains_key(*k)) {
            tx.execute("DELETE FROM parts WHERE key = ?1", params![key])?;
            if let Some(("owner", id)) = key.split_once('/') {
                tx.execute("DELETE FROM items WHERE owner = ?1", params![id])?;
            }
        }
        for row in rows {
            match row {
                Row::Put { owner, cursor, n, record, item } => {
                    tx.execute("INSERT OR REPLACE INTO items (owner, cursor, n, record, item) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![owner, cursor, n, record, item])?;
                }
                Row::Delete { owner, cursor } => {
                    tx.execute("DELETE FROM items WHERE owner = ?1 AND cursor = ?2", params![owner, cursor])?;
                }
            }
        }
        tx.commit()?;
        self.written = written;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsip_messaging::mailbox::cursor;

    fn temp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dsip-mailbox-db-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(n: i64) -> Row {
        let record = json!({"cursor": cursor(n), "n": n, "class": "application", "group": "R1JPVVA", "seq": n, "size": 1024});
        let item = json!({"class": "application", "group": "R1JPVVA", "seq": n, "mls": "A".repeat(1024)});
        Row::Put { owner: "did:key:o".into(), cursor: cursor(n), n, record: record.to_string(), item: Some(item.to_string()) }
    }

    fn part(counter: i64) -> Vec<(String, Value)> {
        vec![("owner/did:key:o".into(), json!({"mailbox": {"counter": counter, "items": []}, "key_packages": {}, "last_resort": {}})),
             ("seen".into(), json!([counter]))]
    }

    #[test]
    fn a_save_writes_rows_and_load_gives_them_back_in_order() {
        let dir = temp("roundtrip");
        let path = dir.join("mailbox.sqlite");
        {
            let mut db = Db::open(&path).unwrap();
            assert!(db.is_empty().unwrap());
            db.write(part(3), &[put(3), put(1), put(2)]).unwrap();
            db.write(part(3), &[Row::Delete { owner: "did:key:o".into(), cursor: cursor(1) }]).unwrap();
        }
        let v = Db::open(&path).unwrap().load().unwrap();
        let o = &v["owners"]["did:key:o"];
        let cursors: Vec<&str> = o["mailbox"]["items"].as_array().unwrap().iter().map(|r| r["cursor"].as_str().unwrap()).collect();
        assert_eq!(cursors, [cursor(2), cursor(3)], "in the machine's order, without the dropped one");
        assert_eq!(o["store"]["items"].as_object().unwrap().len(), 2);
        assert_eq!(o["mailbox"]["counter"], 3);
        assert_eq!(v["seen"], json!([3]));
        // an owner whose part goes takes its items with it
        let mut db = Db::open(&path).unwrap();
        db.load().unwrap();
        db.write(vec![("seen".into(), json!([]))], &[]).unwrap();
        let v = Db::open(&path).unwrap().load().unwrap();
        assert!(v["owners"].as_object().unwrap().is_empty());
        let rows: i64 = db.conn.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The load measurement (service-nodes plan S4): one deposit per save, as the service saves, with a 1 KB payload,
    /// at growing numbers of items held: the cost of a save does not grow with them.
    /// `cargo test -p dsip-mailbox --release --lib store_stress -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn store_stress() {
        let dir = temp("stress");
        let mut db = Db::open(&dir.join("mailbox.sqlite")).unwrap();
        let mut n = 0;
        for target in [1_000, 10_000, 100_000] {
            let (start, from) = (std::time::Instant::now(), n);
            while n < target {
                n += 1;
                db.write(part(n), &[put(n)]).unwrap();
            }
            let secs = start.elapsed().as_secs_f64();
            let bytes: u64 = ["mailbox.sqlite", "mailbox.sqlite-wal"].iter().filter_map(|f| std::fs::metadata(dir.join(f)).ok()).map(|m| m.len()).sum();
            println!("{target:>7} items held: {:>6.0} deposits/s over the last {:>6}, {:>5} bytes on disk per item",
                (n - from) as f64 / secs, n - from, bytes / n as u64);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
