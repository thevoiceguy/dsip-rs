//! A device's MLS state and its delivery state in one SQLite database.
//!
//! Spec: M§5.4 — `ack_through` covers only items a device has durably processed.
//!
//! Impl (spec-gap 44): OpenMLS writes group state through its storage provider as it processes a
//! message, and a device's ack cursor and seq positions must commit with it or not at all. Both live
//! in the same database, and [`SqliteProvider::atomically`] wraps one item's processing in a single
//! transaction; the OpenMLS SQLite provider opens no transactions of its own, so its writes join ours.
//! Group state is encoded as JSON.

use std::path::Path;
use std::rc::Rc;

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, OptionalExtension as _};
use serde_json::Value;

use crate::{err, MlsError};

/// The storage codec: serde JSON.
#[derive(Debug, Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// An OpenMLS provider whose storage is a SQLite file, plus a small key-value table for the
/// application's own durable state in the same database.
pub struct SqliteProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Rc<Connection>>,
    conn: Rc<Connection>,
}

impl SqliteProvider {
    /// Open (or create) the database at `path` and run the OpenMLS migrations.
    pub fn open(path: &Path) -> Result<SqliteProvider, MlsError> {
        let mut conn = Connection::open(path).map_err(err("open database"))?;
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn)
            .run_migrations()
            .map_err(err("openmls migrations"))?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS dsip_device_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .map_err(err("state table"))?;
        let conn = Rc::new(conn);
        Ok(SqliteProvider { crypto: RustCrypto::default(), storage: SqliteStorageProvider::new(conn.clone()), conn })
    }

    /// Run `f` in one transaction: every MLS write and [`SqliteProvider::put_state`] inside it commits
    /// together, or, if `f` fails, none does. The caller must reload any in-memory `MlsGroup` after a
    /// failure, since OpenMLS's in-memory view may be ahead of the rolled-back database.
    pub fn atomically<T>(&self, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError> {
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(err("begin"))?;
        match f() {
            Ok(v) => {
                self.conn.execute_batch("COMMIT").map_err(err("commit"))?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Store an application state value under `key`.
    pub fn put_state(&self, key: &str, value: &Value) -> Result<(), MlsError> {
        self.conn
            .execute(
                "INSERT INTO dsip_device_state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value.to_string()),
            )
            .map(|_| ())
            .map_err(err("put state"))
    }

    /// Every application state entry whose key starts with `prefix`, in key order.
    pub fn list_state(&self, prefix: &str) -> Result<Vec<(String, Value)>, MlsError> {
        let mut stmt = self.conn.prepare("SELECT key, value FROM dsip_device_state WHERE key >= ?1 ORDER BY key").map_err(err("list state"))?;
        let rows = stmt.query_map([prefix], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(err("list state"))?;
        let mut out = vec![];
        for row in rows {
            let (k, v) = row.map_err(err("list state"))?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k, serde_json::from_str(&v).map_err(err("state json"))?));
        }
        Ok(out)
    }

    /// The application state value under `key`, if stored.
    pub fn get_state(&self, key: &str) -> Result<Option<Value>, MlsError> {
        let text: Option<String> = self
            .conn
            .query_row("SELECT value FROM dsip_device_state WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(err("get state"))?;
        text.map(|t| serde_json::from_str(&t).map_err(err("state json"))).transpose()
    }
}

impl OpenMlsProvider for SqliteProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Rc<Connection>>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
