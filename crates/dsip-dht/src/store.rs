//! The overlay's record store on disk: a [`RecordStore`] for libp2p Kademlia backed by redb, so a node can hold far
//! more hints than fit in memory, and keeps them across restarts.
//!
//! Spec: DHT Reachability Hints Profile §4 — a node verifies a record before it stores, forwards or returns it. Every
//! record is verified on its way in (by the node, before [`RecordStore::put`]) and again on its way out
//! ([`RecordStore::get`]): one that no longer verifies — expired, or changed on disk — is not returned, and the node's
//! paced pass deletes it. A restart therefore needs no pass over everything held before the node serves.
//!
//! Impl: every write commits without durability ([`Durability::None`]: in the page cache, not yet on disk) and
//! [`DiskStore::flush`] makes them durable, once per maintenance tick: a crash loses at most that tick's stores, which
//! republishing restores. Measured on a disk: about 580 stores a second with a sync per store, far below what a node
//! holding a million records re-announces (about 830 a second over 20 minutes).
//!
//! Values are the hint's frame and nothing else, stored deflated behind a one-byte format tag: a
//! browser's device-signed hint is about 2.2 KB, which redb's 4 KB pages hold one to a page; deflated (about 1.4 KB)
//! two fit, and the store takes half the disk (measured: `examples/store_stress.rs`). libp2p's `publisher` and `expires` are not kept: a hint carries
//! its own `expires_at`, which is what decides. Provider records are not used by DSIP and stay in memory. A store opened without a path lives
//! in memory (short-lived clients). The records iterator ([`RecordStore::records`]) reads in batches, so walking a
//! large store holds one batch at a time; nothing in this node uses it — libp2p's own replication job, which would
//! copy every record into memory each run, is turned off and the node replicates with [`DiskStore::batch_after`].

// redb's error is large; it never leaves this module (each operation logs it and degrades), so it is not boxed
#![allow(clippy::result_large_err)]

use std::borrow::Cow;
use std::collections::VecDeque;
use std::path::Path;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::Context;
use libp2p::kad::store::{Error, MemoryStore, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;
use redb::{Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::record::evaluate;

/// (key, frame) pairs read from the store.
type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

/// key (the subject's multihash) → the hint's frame.
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
/// keys of the records this node publishes itself (posted to it, re-announced on its republish interval).
const HELD: TableDefinition<&[u8], ()> = TableDefinition::new("held");

/// Records read per batch when walking the store.
const BATCH: usize = 512;

/// Default bound on the records a node holds (`[overlay] max_records`).
pub const DEFAULT_MAX_RECORDS: usize = 1_000_000;

/// Default memory for the store's page cache (`[overlay] store_cache_mb`): what bounds a node's memory, whatever it holds.
pub const DEFAULT_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// Largest value accepted, as libp2p's own store: a hint frame is a few kilobytes.
pub const MAX_VALUE_BYTES: usize = 65 * 1024;

/// Stored value format: a tag byte, then the frame (0: as is; 1: deflated).
const RAW: u8 = 0;
const DEFLATED: u8 = 1;

/// A frame as stored: deflated when that is smaller, behind its tag.
fn encode(frame: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut z = flate2::write::DeflateEncoder::new(vec![DEFLATED], flate2::Compression::default());
    if z.write_all(frame).is_ok() {
        if let Ok(out) = z.finish() {
            if out.len() < frame.len() + 1 {
                return out;
            }
        }
    }
    let mut out = Vec::with_capacity(frame.len() + 1);
    out.push(RAW);
    out.extend_from_slice(frame);
    out
}

/// The frame back from a stored value; `None` for a value this version cannot read.
fn decode(stored: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    match stored.split_first()? {
        (&RAW, rest) => Some(rest.to_vec()),
        (&DEFLATED, rest) => {
            let mut out = Vec::with_capacity(rest.len() * 2);
            flate2::read::DeflateDecoder::new(rest).take(MAX_VALUE_BYTES as u64).read_to_end(&mut out).ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// A Kademlia record store on disk (or in memory), verifying what it returns.
pub struct DiskStore {
    db: Database,
    resolver: StaticResolver,
    max_records: usize,
    count: usize,
    providers: MemoryStore,
}

fn db_err<E: std::fmt::Display>(e: E) -> anyhow::Error {
    anyhow::anyhow!("record store: {e}")
}

impl DiskStore {
    /// Open (or create) the store at `path`, or in memory without one. `max_records` bounds what it holds: a store
    /// at the bound refuses new keys (libp2p's `MaxRecords`), and replacing a held key is always allowed.
    /// `cache_bytes` is the page cache's size: the store's memory, however much it holds.
    pub fn open(path: Option<&Path>, local: PeerId, resolver: StaticResolver, max_records: usize, cache_bytes: usize) -> anyhow::Result<DiskStore> {
        let mut b = Database::builder();
        b.set_cache_size(cache_bytes);
        let db = match path {
            Some(p) => b.create(p).map_err(db_err)?,
            None => b.create_with_backend(redb::backends::InMemoryBackend::new()).map_err(db_err)?,
        };
        let w = db.begin_write().map_err(db_err)?;
        let count = {
            let t = w.open_table(RECORDS).map_err(db_err)?;
            w.open_table(HELD).map_err(db_err)?;
            t.len().map_err(db_err)? as usize
        };
        w.commit().map_err(db_err)?;
        Ok(DiskStore { db, resolver, max_records, count, providers: MemoryStore::new(local) })
    }

    /// Records held.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The bound on records held.
    pub fn max_records(&self) -> usize {
        self.max_records
    }

    /// Up to `n` records after `cursor` in key order (from the start without one), unverified: the node's paced pass
    /// verifies each before re-announcing it, and deletes those that fail.
    pub fn batch_after(&self, cursor: Option<&[u8]>, n: usize) -> Pairs {
        let read = || -> std::result::Result<Pairs, redb::Error> {
            let r = self.db.begin_read()?;
            let t = r.open_table(RECORDS)?;
            let mut out = Vec::with_capacity(n.min(BATCH * 8));
            let iter = match cursor {
                Some(c) => t.range::<&[u8]>((std::ops::Bound::Excluded(c), std::ops::Bound::Unbounded))?,
                None => t.range::<&[u8]>(..)?,
            };
            for item in iter.take(n) {
                let (k, v) = item?;
                // a value this version cannot read is returned empty: it fails verification and the pass deletes it
                out.push((k.value().to_vec(), decode(v.value()).unwrap_or_default()));
            }
            Ok(out)
        };
        read().unwrap_or_else(|e| {
            tracing::warn!("record store: reading a batch failed: {e}");
            vec![]
        })
    }

    /// The frame held for `key`, unverified.
    pub fn raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(RECORDS).ok()?;
        t.get(key).ok().flatten().and_then(|v| decode(v.value()))
    }

    /// Mark (or unmark) `key` as one this node publishes itself.
    pub fn set_held(&mut self, key: &[u8], held: bool) {
        let write = || -> std::result::Result<(), redb::Error> {
            let mut w = self.db.begin_write()?;
            w.set_durability(Durability::None);
            {
                let mut t = w.open_table(HELD)?;
                if held {
                    t.insert(key, ())?;
                } else {
                    t.remove(key)?;
                }
            }
            w.commit()?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::warn!("record store: marking a held record failed: {e}");
        }
    }

    /// The keys this node publishes itself.
    pub fn held_keys(&self) -> Vec<Vec<u8>> {
        let read = || -> std::result::Result<Vec<Vec<u8>>, redb::Error> {
            let r = self.db.begin_read()?;
            let t = r.open_table(HELD)?;
            let mut out = vec![];
            for item in t.range::<&[u8]>(..)? {
                out.push(item?.0.value().to_vec());
            }
            Ok(out)
        };
        read().unwrap_or_default()
    }

    /// Make every write since the last flush durable (an empty commit at full durability), and free the pages they
    /// replaced: redb frees pages only on a durable commit.
    pub fn flush(&mut self) {
        let write = || -> std::result::Result<(), redb::Error> {
            let mut w = self.db.begin_write()?;
            w.set_durability(Durability::Immediate);
            w.commit()?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::warn!("record store: flushing failed: {e}");
        }
    }

    /// Bytes the store's file occupies on disk (blocks allocated: the file is sparse, its length is larger).
    pub fn file_bytes(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).map(|m| m.blocks() * 512).unwrap_or(0)
    }
}

impl RecordStore for DiskStore {
    type RecordsIter<'a> = Records<'a>;
    type ProvidedIter<'a> = <MemoryStore as RecordStore>::ProvidedIter<'a>;

    /// Spec: DHT Hints Profile §4 — verified on the way out; one that no longer verifies is not returned.
    fn get(&self, k: &RecordKey) -> Option<Cow<'_, Record>> {
        let value = self.raw(k.as_ref())?;
        let frame = String::from_utf8_lossy(&value);
        let ctx = Context::new(crate::node::now_s(), &self.resolver);
        evaluate(&frame, &ctx, None).hint?;
        Some(Cow::Owned(Record { key: k.clone(), value, publisher: None, expires: None }))
    }

    fn put(&mut self, r: Record) -> Result<()> {
        if r.value.len() >= MAX_VALUE_BYTES {
            return Err(Error::ValueTooLarge);
        }
        let key = r.key.as_ref();
        let write = |db: &Database, check_new: bool, at_bound: bool| -> std::result::Result<std::result::Result<bool, Error>, redb::Error> {
            let mut w = db.begin_write()?;
            w.set_durability(Durability::None);
            let new = {
                let mut t = w.open_table(RECORDS)?;
                let new = t.get(key)?.is_none();
                if check_new && new && at_bound {
                    return Ok(Err(Error::MaxRecords));
                }
                t.insert(key, encode(&r.value).as_slice())?;
                new
            };
            w.commit()?;
            Ok(Ok(new))
        };
        match write(&self.db, true, self.count >= self.max_records) {
            Ok(Ok(new)) => {
                self.count += usize::from(new);
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(e) => {
                tracing::warn!("record store: storing a record failed: {e}");
                Err(Error::MaxRecords)
            }
        }
    }

    fn remove(&mut self, k: &RecordKey) {
        let write = || -> std::result::Result<bool, redb::Error> {
            let mut w = self.db.begin_write()?;
            w.set_durability(Durability::None);
            let gone = {
                let mut t = w.open_table(RECORDS)?;
                let gone = t.remove(k.as_ref())?.is_some();
                w.open_table(HELD)?.remove(k.as_ref())?;
                gone
            };
            w.commit()?;
            Ok(gone)
        };
        match write() {
            Ok(true) => self.count = self.count.saturating_sub(1),
            Ok(false) => {}
            Err(e) => tracing::warn!("record store: removing a record failed: {e}"),
        }
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        Records { store: self, buf: VecDeque::new(), cursor: None, done: false }
    }

    fn add_provider(&mut self, record: ProviderRecord) -> Result<()> {
        self.providers.add_provider(record)
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.providers.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.providers.provided()
    }

    fn remove_provider(&mut self, k: &RecordKey, p: &PeerId) {
        self.providers.remove_provider(k, p)
    }
}

/// Every record held, read a batch (512) at a time, unverified.
pub struct Records<'a> {
    store: &'a DiskStore,
    buf: VecDeque<(Vec<u8>, Vec<u8>)>, // one batch of `Pairs`
    cursor: Option<Vec<u8>>,
    done: bool,
}

impl<'a> Iterator for Records<'a> {
    type Item = Cow<'a, Record>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() && !self.done {
            let batch = self.store.batch_after(self.cursor.as_deref(), BATCH);
            self.done = batch.len() < BATCH;
            self.cursor = batch.last().map(|(k, _)| k.clone());
            self.buf.extend(batch);
        }
        let (k, v) = self.buf.pop_front()?;
        Some(Cow::Owned(Record { key: RecordKey::new(&k), value: v, publisher: None, expires: None }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{hint_payload, key_for, sign_hint, Endpoint};
    use dsip_core::keys::KeyPair;

    /// A self-signed `did:key` hint, live for `ttl` seconds from `issued_at`.
    fn hint(issued_at: i64, ttl: i64) -> (Vec<u8>, Vec<u8>) {
        let kp = KeyPair::generate();
        let p = hint_payload(&kp.did(), &kp.did(), &[Endpoint::signaling("wss://relay.example/dsip")], issued_at, issued_at, ttl);
        (key_for(&kp.did()), sign_hint(&p, &kp, vec![]).frame().into_bytes())
    }

    fn rec(k: &[u8], v: &[u8]) -> Record {
        Record { key: RecordKey::new(&k), value: v.to_vec(), publisher: None, expires: None }
    }

    fn open(path: Option<&Path>, max: usize) -> DiskStore {
        DiskStore::open(path, PeerId::random(), StaticResolver::default(), max, 16 << 20).unwrap()
    }

    #[test]
    fn a_held_hint_is_returned_verified_and_one_that_no_longer_verifies_is_not() {
        let now = crate::node::now_s();
        let mut s = open(None, 10);
        let (k, v) = hint(now, 600);
        s.put(rec(&k, &v)).unwrap();
        assert_eq!(s.get(&RecordKey::new(&k)).unwrap().value, v);
        // expired: held, but not served
        let (k2, v2) = hint(now - 3600, 600);
        s.put(rec(&k2, &v2)).unwrap();
        assert!(s.get(&RecordKey::new(&k2)).is_none());
        // changed on disk (a flipped byte in the signature): not served
        let (k3, mut v3) = hint(now, 600);
        let last = v3.len() - 3;
        v3[last] = if v3[last] == b'A' { b'B' } else { b'A' };
        s.put(rec(&k3, &v3)).unwrap();
        assert!(s.get(&RecordKey::new(&k3)).is_none());
        assert_eq!(s.len(), 3, "held until the paced pass deletes them");
    }

    #[test]
    fn at_the_bound_a_new_key_is_refused_and_a_held_one_still_replaced() {
        let now = crate::node::now_s();
        let mut s = open(None, 2);
        let (a, va) = hint(now, 600);
        let (b, vb) = hint(now, 600);
        let (c, vc) = hint(now, 600);
        s.put(rec(&a, &va)).unwrap();
        s.put(rec(&b, &vb)).unwrap();
        assert!(matches!(s.put(rec(&c, &vc)), Err(Error::MaxRecords)));
        s.put(rec(&a, &vb)).unwrap(); // a replacement, not a new key
        assert_eq!(s.len(), 2);
        s.remove(&RecordKey::new(&a));
        assert_eq!(s.len(), 1);
        s.put(rec(&c, &vc)).unwrap();
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn the_store_survives_a_reopen_and_is_walked_in_batches() {
        let dir = std::env::temp_dir().join(format!("dsip-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("records.redb");
        let now = crate::node::now_s();
        let keys: Vec<Vec<u8>> = {
            let mut s = open(Some(&path), 2000);
            let mut keys = vec![];
            for _ in 0..1100 {
                let (k, v) = hint(now, 600);
                s.put(rec(&k, &v)).unwrap();
                keys.push(k);
            }
            s.set_held(&keys[0], true);
            keys
        };
        let s = open(Some(&path), 5000);
        assert_eq!(s.len(), 1100, "counted again at open");
        assert_eq!(s.held_keys(), vec![keys[0].clone()]);
        // the iterator reads BATCH at a time and sees every record once, in key order
        let walked: Vec<Vec<u8>> = s.records().map(|r| r.key.to_vec()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(walked, sorted);
        // a paced pass resumes after its cursor
        let first = s.batch_after(None, 700);
        let rest = s.batch_after(first.last().map(|(k, _)| k.as_slice()), 700);
        assert_eq!((first.len(), rest.len()), (700, 400));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
