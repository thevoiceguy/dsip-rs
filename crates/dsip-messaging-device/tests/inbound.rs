//! Inbound routing, shared by both messaging clients: where each item goes before MLS, and what the delivery state
//! records for it — the classes that need no processing committed, a device's own deposit and pre-join history
//! skipped, a handshake beyond a seq gap held and released when the gap fills, a removal clearing the group, and an
//! item committed with its MLS effect or, when it cannot be processed, rolled back and committed as handled.
//!
//! Spec: M§5.4 (spec-gaps 44, 138), M§6.5 (spec-gaps 47, 69: a device's own copy is no gap), M§8.5, M§11.2, M§12.3.

use std::collections::{BTreeMap, HashSet};

use openmls::prelude::tls_codec::Serialize as _;
use serde_json::{json, Value};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_messaging::client::Resume;
use dsip_messaging_device::{Inbound, MemoryStore, Outcome, Route, Store};
use dsip_mls::{Device, MlsError};

const NOW: i64 = 1_790_000_000;
const G: &str = "Z3JvdXAtMQ";

struct Parts {
    resume: Resume,
    own: HashSet<String>,
    gaps: BTreeMap<String, dsip_messaging::client::GapTracker>,
    held: BTreeMap<String, Vec<Value>>,
}

impl Parts {
    fn new(resume: Value) -> Parts {
        Parts { resume: Resume::new(&resume), own: HashSet::new(), gaps: BTreeMap::new(), held: BTreeMap::new() }
    }

    fn inbound(&mut self) -> Inbound<'_> {
        Inbound { resume: &mut self.resume, own: &self.own, gaps: &mut self.gaps, held_items: &mut self.held, gap_timeout: 60 }
    }

    fn route(&mut self, item: &Value, member: bool, prejoin: bool) -> Route {
        self.inbound().route(item, member, |_| prejoin, NOW)
    }

    fn cursor(&self) -> Value {
        self.resume.snapshot()["cursor"].clone()
    }
}

fn item(cursor: &str, class: &str, seq: i64, mls: &[u8]) -> Value {
    json!({"cursor": cursor, "class": class, "group": G, "seq": seq, "mls": dsip_core::b64::encode(mls)})
}

/// A real MLS application message, so that its header parses (epoch 0).
fn application_bytes() -> Vec<u8> {
    let (i, d) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    let dev = Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature));
    let conv = serde_json::to_vec(&json!({"conversation": "c", "kind": "personal"})).unwrap();
    let mut g = dev.create_group(b"group-1", &conv).unwrap();
    g.create_message(dev.provider(), &dev.signer(), b"hi").unwrap().tls_serialize_detached().unwrap()
}

#[test]
fn classes_that_need_no_processing() {
    let mut p = Parts::new(json!({}));
    assert_eq!(p.route(&json!({"class": "ephemeral", "group": G}), true, false), Route::Ephemeral);
    assert_eq!(p.cursor(), Value::Null, "ephemeral items carry no cursor (M§11.2)");
    assert_eq!(p.route(&item("c1", "group-info", 1, b"gi"), true, false),
               Route::GroupInfo { group: G.into(), mls: json!(dsip_core::b64::encode(b"gi")) });
    assert_eq!(p.cursor(), "c1");
    assert_eq!(p.route(&item("c2", "not-a-class-we-process", 2, b""), true, false), Route::Other);
    assert_eq!(p.cursor(), "c2");
    // handled by the host first, then committed by it
    assert_eq!(p.route(&item("c3", "introduction", 0, b""), true, false), Route::FirstContact);
    assert_eq!(p.route(&item("c3", "archive", 0, b""), true, false), Route::Archive);
    assert_eq!(p.cursor(), "c2");
    // a welcome is always processed
    assert!(matches!(p.route(&item("c4", "welcome", 3, b"w"), false, true), Route::Process { released, .. } if released.is_empty()));
}

#[test]
fn own_deposits_and_prejoin_history() {
    let bytes = application_bytes();
    let mut p = Parts::new(json!({}));
    // this device's own deposit fanned back (spec-gap 47)
    p.own.insert(dsip_mls::digest(&bytes));
    assert_eq!(p.route(&item("c1", "application", 1, &bytes), true, false), Route::Own { released: vec![] });
    assert_eq!(p.cursor(), "c1");
    p.own.clear();
    // M§12.3: a group this device is not in, or an epoch from before it joined
    assert_eq!(p.route(&item("c2", "application", 2, &bytes), false, false), Route::PreJoin);
    assert_eq!(p.route(&item("c3", "application", 3, &bytes), true, true), Route::PreJoin);
    assert_eq!(p.cursor(), "c3");
    assert!(matches!(p.route(&item("c4", "application", 4, &bytes), true, false), Route::Process { bytes: b, .. } if b == bytes));
}

#[test]
fn an_own_deposit_is_no_gap() {
    // processed through seq 4; seq 5 is this device's own, its accepted lost with the binding (spec-gap 69)
    let own = application_bytes();
    let mut p = Parts::new(json!({"groups": {G: {"contiguous": 4}}}));
    p.own.insert(dsip_mls::digest(&own));
    assert_eq!(p.route(&item("c5", "application", 5, &own), true, false), Route::Own { released: vec![] });
    // so the handshake at seq 6 is next, not beyond a gap
    assert!(matches!(p.route(&item("c6", "handshake", 6, b"commit"), true, false), Route::Process { released, .. } if released.is_empty()));

    // the other way round: seq 7 held behind the gap at 6, then 6 turns out to be our own copy, which releases it
    let mut p = Parts::new(json!({"groups": {G: {"contiguous": 5}}}));
    p.own.insert(dsip_mls::digest(&own));
    assert_eq!(p.route(&item("c7", "handshake", 7, b"commit"), true, false), Route::Held);
    let Route::Own { released } = p.route(&item("c6", "application", 6, &own), true, false) else { panic!() };
    assert_eq!(released.iter().map(|r| r["seq"].as_i64().unwrap()).collect::<Vec<_>>(), vec![7]);
}

#[test]
fn a_gap_holds_then_releases() {
    // this device has processed seq 1..5 of the group
    let mut p = Parts::new(json!({"groups": {G: {"contiguous": 5}}}));
    // seq 7 is a handshake beyond the gap at 6: held, and acknowledged since it is kept durably (spec-gap 69)
    assert_eq!(p.route(&item("c7", "handshake", 7, b"commit"), true, false), Route::Held);
    assert_eq!(p.cursor(), "c7");
    assert_eq!(p.held[G].len(), 1);
    assert_eq!(p.held[G][0]["held_release"], true);
    // seq 6 fills the gap: processed, and the held seq 7 released after it
    let Route::Process { released, .. } = p.route(&item("c6", "application", 6, b"msg"), true, false) else { panic!() };
    assert_eq!(released.iter().map(|r| r["seq"].as_i64().unwrap()).collect::<Vec<_>>(), vec![7]);
    assert!(p.held[G].is_empty());
    // the released item is routed again and processed, not held a second time
    assert!(matches!(p.route(&released[0], true, false), Route::Process { .. }));
    // a redelivery of a processed seq is a duplicate (M§8.5)
    p.resume.commit(&item("c6", "application", 6, b"msg"), false);
    assert_eq!(p.route(&item("c6", "application", 6, b"msg"), true, false), Route::Duplicate);

    // removed (spec-gap 127): a welcome back is a join again and the gap tracker and held items go; the seq positions
    // stay, so what was processed remains a duplicate
    let welcome = item("c8", "welcome", 6, b"w");
    p.resume.commit(&welcome, false);
    assert!(p.resume.is_duplicate(&welcome));
    p.route(&item("c9", "handshake", 9, b"commit"), true, false);
    assert!(!p.held[G].is_empty() && p.gaps.contains_key(G));
    p.inbound().removed(G);
    assert!(!p.held.contains_key(G) && !p.gaps.contains_key(G));
    assert!(!p.resume.is_duplicate(&welcome));
    assert_eq!(p.route(&item("c6", "application", 6, b"msg"), true, false), Route::Duplicate);
}

#[test]
fn a_gap_that_does_not_fill_is_re_joined() {
    let mut p = Parts::new(json!({"groups": {G: {"contiguous": 5}}}));
    // seq 7 and 8 beyond the gap at 6, held from NOW
    assert_eq!(p.route(&item("c7", "handshake", 7, b"commit"), true, false), Route::Held);
    assert_eq!(p.route(&item("c8", "application", 8, b"msg"), true, false), Route::Held);
    // within the timeout (60 s here): nothing
    assert!(p.inbound().gap_timeouts(NOW + 59).is_empty());
    assert_eq!(p.held[G].len(), 2);
    // past it (M§6.5, spec-gap 69): re-join, the held items dropped, every seq seen passed
    assert_eq!(p.inbound().gap_timeouts(NOW + 60), vec![(G.to_string(), json!([7, 8]))]);
    assert!(!p.held.contains_key(G) && !p.gaps.contains_key(G));
    assert_eq!(p.route(&item("c6", "application", 6, b"msg"), true, false), Route::Duplicate);
    assert_eq!(p.route(&item("c8", "application", 8, b"msg"), true, false), Route::Duplicate);
    // and only once
    assert!(p.inbound().gap_timeouts(NOW + 600).is_empty());
}

#[test]
fn a_processed_item_is_committed_with_the_delivery_state_in_one_transaction() {
    let mut p = Parts::new(json!({}));
    let store = MemoryStore::default();
    let it = item("c:1", "application", 1, b"x");
    let out = p.inbound().commit_processed(&store, &it, || {
        store.put("mls-write", &json!(1))?;
        Ok(Outcome::Nothing)
    });
    assert!(matches!(out, Ok(Outcome::Nothing)));
    assert_eq!(p.cursor(), json!("c:1"));
    assert_eq!(store.get("resume").unwrap(), Some(p.resume.snapshot()));
    assert_eq!(store.get("mls-write").unwrap(), Some(json!(1)));
}

#[test]
fn an_unprocessable_item_is_rolled_back_then_committed_as_handled() {
    let mut p = Parts::new(json!({}));
    let store = MemoryStore::default();
    let it = item("c:1", "application", 1, b"x");
    let out = p.inbound().commit_processed(&store, &it, || {
        store.put("mls-write", &json!(1))?;
        Err(MlsError("cannot decrypt".into()))
    });
    assert_eq!(out.unwrap_err().0, "cannot decrypt");
    // spec-gap 44: nothing it wrote survives; spec-gap 138: acknowledged, and its redelivery is a duplicate
    assert_eq!(store.get("mls-write").unwrap(), None);
    assert_eq!(p.cursor(), json!("c:1"));
    assert_eq!(p.route(&it, true, false), Route::Duplicate);
}
