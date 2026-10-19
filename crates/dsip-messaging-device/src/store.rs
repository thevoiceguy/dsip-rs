//! Where a device keeps what it must not lose: its MLS state and its own delivery state, written together.
//!
//! Spec: M§5.4 (`ack_through` covers only items a device has durably processed).
//!
//! Impl (spec-gap 44): one item's MLS writes and the delivery state that records it commit together or not at all.
//! A [`Store`] is an OpenMLS provider that also holds the application's state as JSON values by key, and runs a
//! closure [`Store::atomically`]. Natively it is dsip-mls's SQLite provider, one database and one transaction
//! (feature `sqlite`); in the browser it is [`MemoryStore`], whose MLS storage the host saves as
//! `{b64url key: b64url value}` exactly as before, and which restores both maps when a closure fails.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use dsip_mls::MlsError;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use serde_json::Value;

/// An OpenMLS provider that also keeps the device's own durable state.
pub trait Store: OpenMlsProvider {
    /// The state value under `key`, if stored.
    fn get(&self, key: &str) -> Result<Option<Value>, MlsError>;
    /// Store `value` under `key`, replacing what was there.
    fn put(&self, key: &str, value: &Value) -> Result<(), MlsError>;
    /// Every entry whose key starts with `prefix`, in key order.
    fn list(&self, prefix: &str) -> Result<Vec<(String, Value)>, MlsError>;
    /// Run `f`: every MLS write and [`Store::put`] inside it is kept together, or, if `f` fails, none is. A caller
    /// must reload any `MlsGroup` it holds in memory after a failure, since that view may be ahead of the store.
    fn atomically<T>(&self, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError>;
}

#[cfg(feature = "sqlite")]
impl Store for dsip_mls::sqlite::SqliteProvider {
    fn get(&self, key: &str) -> Result<Option<Value>, MlsError> {
        self.get_state(key)
    }

    fn put(&self, key: &str, value: &Value) -> Result<(), MlsError> {
        self.put_state(key, value)
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, Value)>, MlsError> {
        self.list_state(prefix)
    }

    fn atomically<T>(&self, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError> {
        dsip_mls::sqlite::SqliteProvider::atomically(self, f)
    }
}

/// A store in memory: OpenMLS's rust-crypto and memory storage, and the state values. The host persists it.
#[derive(Default)]
pub struct MemoryStore {
    crypto: RustCrypto,
    storage: MemoryStorage,
    state: RwLock<BTreeMap<String, Value>>,
}

fn poisoned<T>(_: T) -> MlsError {
    MlsError("store lock poisoned".into())
}

impl MemoryStore {
    /// A store holding the MLS storage a host saved with [`MemoryStore::mls_json`]; entries that do not decode are
    /// skipped.
    pub fn from_mls_json(saved: &Value) -> MemoryStore {
        let mut values = HashMap::new();
        for (k, v) in saved.as_object().into_iter().flatten() {
            if let (Some(k), Some(v)) = (dsip_core::b64::decode(k), v.as_str().and_then(dsip_core::b64::decode)) {
                values.insert(k, v);
            }
        }
        MemoryStore { storage: MemoryStorage { values: RwLock::new(values) }, ..MemoryStore::default() }
    }

    /// The MLS storage as the host saves it: `{b64url key: b64url value}`.
    pub fn mls_json(&self) -> Value {
        let values = self.storage.values.read().map(|v| v.clone()).unwrap_or_default();
        Value::Object(values.iter().map(|(k, v)| (dsip_core::b64::encode(k), Value::String(dsip_core::b64::encode(v)))).collect())
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<Value>, MlsError> {
        Ok(self.state.read().map_err(poisoned)?.get(key).cloned())
    }

    fn put(&self, key: &str, value: &Value) -> Result<(), MlsError> {
        self.state.write().map_err(poisoned)?.insert(key.to_string(), value.clone());
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, Value)>, MlsError> {
        let state = self.state.read().map_err(poisoned)?;
        Ok(state.range(prefix.to_string()..).take_while(|(k, _)| k.starts_with(prefix)).map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn atomically<T>(&self, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError> {
        let mls = self.storage.values.read().map_err(poisoned)?.clone();
        let state = self.state.read().map_err(poisoned)?.clone();
        let out = f();
        if out.is_err() {
            *self.storage.values.write().map_err(poisoned)? = mls;
            *self.state.write().map_err(poisoned)? = state;
        }
        out
    }
}

impl OpenMlsProvider for MemoryStore {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}
