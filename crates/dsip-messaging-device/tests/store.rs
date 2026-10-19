//! Both stores, held to one behaviour: state values by key and prefix, and a failed `atomically` leaving neither the
//! state nor the MLS storage changed (spec-gap 44), on the SQLite store and the memory store alike.
//!
//! Spec: M§5.4.

use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_messaging_device::{MemoryStore, Store};
use dsip_mls::sqlite::SqliteProvider;
use dsip_mls::{Device, MlsError};

const NOW: i64 = 1_790_000_000;

fn device<S: Store>(store: S) -> Device<S> {
    let (i, d) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    Device::with_provider(d, format!("{}.{}.{}", e.protected, e.payload, e.signature), store)
}

fn conformance<S: Store>(dev: &Device<S>) {
    let s = dev.provider();
    // values by key; prefixes in key order, stopping at the first key past the prefix
    for (k, v) in [("joined:b", json!(2)), ("joined:a", json!(1)), ("joinedx", json!(9)), ("resume", json!({"since": "c:1"}))] {
        s.put(k, &v).unwrap();
    }
    assert_eq!(s.get("resume").unwrap(), Some(json!({"since": "c:1"})));
    assert_eq!(s.get("nothing").unwrap(), None);
    assert_eq!(s.list("joined:").unwrap(), vec![("joined:a".into(), json!(1)), ("joined:b".into(), json!(2))]);
    s.put("joined:a", &json!(3)).unwrap();
    assert_eq!(s.get("joined:a").unwrap(), Some(json!(3)));

    // a failed closure: neither its state writes nor its MLS writes are kept
    let conv = serde_json::to_vec(&json!({"conversation": "c", "kind": "personal"})).unwrap();
    let failed: Result<(), MlsError> = s.atomically(|| {
        s.put("resume", &json!({"since": "c:2"}))?;
        dev.create_group(b"group-rolled-back", &conv)?;
        Err(MlsError("the item could not be processed".into()))
    });
    assert!(failed.is_err());
    assert_eq!(s.get("resume").unwrap(), Some(json!({"since": "c:1"})), "the state write was rolled back");
    assert!(dev.load_group(b"group-rolled-back").unwrap().is_none(), "the MLS write was rolled back");

    // a closure that succeeds keeps both
    s.atomically(|| {
        s.put("resume", &json!({"since": "c:3"}))?;
        dev.create_group(b"group-kept", &conv).map(|_| ())
    })
    .unwrap();
    assert_eq!(s.get("resume").unwrap(), Some(json!({"since": "c:3"})));
    assert!(dev.load_group(b"group-kept").unwrap().is_some());
}

#[test]
fn sqlite_store() {
    let path = std::env::temp_dir().join(format!("dsip-store-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);
    conformance(&device(SqliteProvider::open(&path).unwrap()));
    // durable: a new process opening the file sees what was committed
    let again = device(SqliteProvider::open(&path).unwrap());
    assert_eq!(again.provider().get("resume").unwrap(), Some(json!({"since": "c:3"})));
    assert!(again.load_group(b"group-kept").unwrap().is_some());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn memory_store() {
    let dev = device(MemoryStore::default());
    conformance(&dev);
    // the browser's save format: the MLS storage as {b64url key: b64url value}, restored on load
    let saved = dev.provider().mls_json();
    assert!(saved.as_object().is_some_and(|m| !m.is_empty() && m.values().all(|v| v.is_string())));
    let again = device(MemoryStore::from_mls_json(&saved));
    assert!(again.load_group(b"group-kept").unwrap().is_some());
    assert!(again.load_group(b"group-rolled-back").unwrap().is_none());
}
