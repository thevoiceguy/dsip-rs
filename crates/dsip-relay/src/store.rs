//! The relay's store-and-forward queue on disk, so a restarted relay delivers what it held (service-nodes plan S3).
//!
//! Spec: §13.3 (envelopes for a known, offline recipient are held until `min(expires_at, offline_retention_s)`; the
//! relay advertises `offline_retention_s`, and a queue lost on a restart would break that for every envelope in it).
//! Impl: a redb file. Two tables: `queue`, keyed by (recipient, arrival), holding the tracker's [`Queued`] entry and
//! the exact frame received (§10.2: forwarded as received, never re-serialized); and `known`, the recipients the
//! relay knows ([`Known`]), so a restart does not turn a known, offline recipient into an unknown one (§13.2
//! `transport.unknown-recipient`). After each step only the queues it touched are rewritten, and the known table by
//! difference; every write commits durably, since an envelope the relay accepted is one it promised to hold.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Mutex;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use dsip_session::fork::{Known, Queued};

const QUEUE: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("queue");
const KNOWN: TableDefinition<&str, &[u8]> = TableDefinition::new("known");

/// Why the queue store failed. redb's errors are flattened to text: they are logged, never matched.
#[derive(Debug, thiserror::Error)]
#[error("relay queue store: {0}")]
pub struct StoreError(String);

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

#[derive(Serialize, Deserialize)]
struct Entry {
    queued: Queued,
    frame: String,
}

/// What the store held when it was opened: the queues, the frames they deliver (by envelope id, with their
/// deadlines) and the known recipients.
#[derive(Debug, Default)]
pub struct Loaded {
    /// Queued envelopes by recipient.
    pub inbox: BTreeMap<String, Vec<Queued>>,
    /// The frame of each queued envelope, by envelope id, with its deadline.
    pub frames: HashMap<String, (String, i64)>,
    /// The recipients the relay knew.
    pub known: Vec<Known>,
}

/// The relay's queue on disk ([`crate::RelayConfig::queue_store`]).
pub struct QueueStore {
    db: Database,
    /// The known table as last written, to write only what changed.
    known: Mutex<BTreeMap<String, Known>>,
}

impl std::fmt::Debug for QueueStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueStore").finish_non_exhaustive()
    }
}

impl QueueStore {
    /// Open (or create) the store at `path`.
    pub fn open(path: &Path) -> Result<QueueStore, StoreError> {
        let db = Database::create(path).map_err(err)?;
        let w = db.begin_write().map_err(err)?;
        w.open_table(QUEUE).map_err(err)?;
        w.open_table(KNOWN).map_err(err)?;
        w.commit().map_err(err)?;
        Ok(QueueStore { db, known: Mutex::new(BTreeMap::new()) })
    }

    /// Everything the store holds. An entry that does not parse is skipped and logged.
    pub fn load(&self) -> Result<Loaded, StoreError> {
        let mut out = Loaded::default();
        let r = self.db.begin_read().map_err(err)?;
        for row in r.open_table(QUEUE).map_err(err)?.iter().map_err(err)? {
            let (k, v) = row.map_err(err)?;
            let (to, _) = k.value();
            match serde_json::from_slice::<Entry>(v.value()) {
                Ok(e) => {
                    out.frames.insert(e.queued.message.id.clone(), (e.frame, e.queued.deadline));
                    out.inbox.entry(to.to_string()).or_default().push(e.queued);
                }
                Err(e) => tracing::warn!("queue store: skipping an entry for {to}: {e}"),
            }
        }
        let mut mirror = BTreeMap::new();
        for row in r.open_table(KNOWN).map_err(err)?.iter().map_err(err)? {
            let (k, v) = row.map_err(err)?;
            match serde_json::from_slice::<Known>(v.value()) {
                Ok(known) => {
                    mirror.insert(known.who.clone(), known.clone());
                    out.known.push(known);
                }
                Err(e) => tracing::warn!("queue store: skipping known {}: {e}", k.value()),
            }
        }
        if let Ok(mut m) = self.known.lock() {
            *m = mirror;
        }
        Ok(out)
    }

    /// Write `queues` (each recipient's whole queue, as the tracker now holds it; an absent or empty one is
    /// deleted) and the known recipients that changed since the last write, in one durable commit. `frame` gives
    /// each queued envelope's frame by its id; an entry whose frame is not held is not written (it could not be
    /// delivered).
    pub fn write<'a>(
        &self,
        queues: impl IntoIterator<Item = (&'a str, Option<&'a Vec<Queued>>)>,
        known: Option<&BTreeMap<String, Known>>,
        frame: impl Fn(&str) -> Option<&'a str>,
    ) -> Result<(), StoreError> {
        let mut mirror = self.known.lock().map_err(err)?;
        let w = self.db.begin_write().map_err(err)?;
        {
            let mut t = w.open_table(QUEUE).map_err(err)?;
            for (to, q) in queues {
                let old: Vec<u64> = t.range((to, 0)..=(to, u64::MAX)).map_err(err)?.filter_map(|r| r.ok()).map(|(k, _)| k.value().1).collect();
                for a in old {
                    t.remove((to, a)).map_err(err)?;
                }
                for e in q.into_iter().flatten() {
                    let Some(f) = frame(&e.message.id) else { continue };
                    let bytes = serde_json::to_vec(&Entry { queued: e.clone(), frame: f.to_string() }).map_err(err)?;
                    t.insert((to, e.arrival), bytes.as_slice()).map_err(err)?;
                }
            }
        }
        if let Some(now) = known {
            let mut t = w.open_table(KNOWN).map_err(err)?;
            for who in mirror.keys().filter(|w| !now.contains_key(*w)) {
                t.remove(who.as_str()).map_err(err)?;
            }
            for (who, k) in now.iter().filter(|(w, k)| mirror.get(*w) != Some(*k)) {
                t.insert(who.as_str(), serde_json::to_vec(k).map_err(err)?.as_slice()).map_err(err)?;
            }
        }
        w.commit().map_err(err)?;
        if let Some(now) = known {
            *mirror = now.clone();
        }
        Ok(())
    }

    /// Whether `known` differs from what was last written.
    pub fn known_changed(&self, known: &BTreeMap<String, Known>) -> bool {
        self.known.lock().map_or(true, |m| *m != *known)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsip_session::Message;

    fn queued(id: &str, to: &str, arrival: u64) -> Queued {
        let message = Message { msg_type: "invite".into(), id: id.into(), from: "did:key:a".into(), to: Some(to.into()), ..Default::default() };
        Queued { message, deadline: 2_000_000_000, arrival }
    }

    #[test]
    fn queues_and_known_recipients_survive_reopening() {
        let dir = std::env::temp_dir().join(format!("dsip-relay-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("queue.redb");
        let _ = std::fs::remove_file(&path);
        let frames: HashMap<&str, &str> = [("i1", "frame-1"), ("i2", "frame-2"), ("i3", "frame-3")].into();
        let bob = vec![queued("i1", "did:key:bob", 1), queued("i3", "did:key:bob", 3)];
        let carol = vec![queued("i2", "did:key:carol", 2)];
        let known = |who: &str, last: Option<i64>| (who.to_string(), Known { who: who.into(), identity: None, last_bound: last });
        let mut k: BTreeMap<String, Known> = [known("did:key:bob", Some(10)), known("did:key:carol", None)].into();
        {
            let store = QueueStore::open(&path).unwrap();
            assert!(store.known_changed(&k));
            store.write([("did:key:bob", Some(&bob)), ("did:key:carol", Some(&carol))], Some(&k), |id| frames.get(id).copied()).unwrap();
            assert!(!store.known_changed(&k));
            // Carol's queue is flushed and Bob forgotten: only what changed is rewritten
            k.remove("did:key:bob");
            store.write([("did:key:carol", None)], Some(&k), |id| frames.get(id).copied()).unwrap();
        }
        let held = QueueStore::open(&path).unwrap().load().unwrap();
        assert_eq!(held.inbox.len(), 1);
        assert_eq!(held.inbox["did:key:bob"], bob);
        assert_eq!(held.frames["i3"], ("frame-3".to_string(), 2_000_000_000));
        assert!(!held.frames.contains_key("i2"));
        assert_eq!(held.known, vec![k["did:key:carol"].clone()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
