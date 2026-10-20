//! Successor groups as both messaging clients drive them: the tracker's decisions as types, where a conversation lives
//! now and which groups make up its thread, the creator a welcome is checked against, and the tracker persisted as
//! before.
//!
//! Spec: M§7.5 (spec-gap 61), M§9.4.

use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_messaging::client::SuccessorTracker;
use dsip_messaging_device::successors::{self, Converge, Create};
use dsip_messaging_device::Successors;
use dsip_mls::Device;

const NOW: i64 = 1_790_000_000;
const ALICE: &str = "did:web:alice.example";
const BOB: &str = "did:web:bob.example";

/// A group id: the base64url of a ULID (M§6.3), ordered by `t`.
fn gid(t: u64) -> String {
    dsip_core::b64::encode(dsip_core::ulid::Ulid::generate_at(1_790_000_000_000 + t).as_str().as_bytes())
}

fn roster(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[test]
fn converging_on_one_successor() {
    let mut s = Successors::default();
    let (g1, g3, g5, g7, g9) = (gid(1), gid(3), gid(5), gid(7), gid(9));
    // a group this device was never in: nothing to succeed, and a successor of it is first contact
    assert_eq!(s.create("dead", ALICE), Create::Refuse("not-a-member".into()));
    assert_eq!(s.welcome(&g5, "dead", BOB, &roster(&[ALICE, BOB])), vec![Converge::FirstContact(g5.clone())]);

    // created at the threshold: the last known roster re-added, this identity excluded
    s.member_of("dead", &roster(&[ALICE, BOB]));
    assert_eq!(s.create("dead", ALICE), Create::Create { peers: roster(&[BOB]) });
    assert_eq!(s.created(&g7, "dead"), vec![]);
    assert_eq!(s.successor("dead"), Some(g7.as_str()));
    // asked again: use it
    assert_eq!(s.create("dead", ALICE), Create::Use(g7.clone()));

    // Bob's lower successor: joined, ours left (the lowest group_id wins); a higher one is declined
    assert_eq!(s.welcome(&g3, "dead", BOB, &roster(&[ALICE, BOB])), vec![Converge::Join(g3.clone()), Converge::Leave(g7.clone())]);
    assert_eq!(s.welcome(&g9, "dead", BOB, &roster(&[ALICE, BOB])), vec![Converge::Decline(g9.clone())]);
    // a successor that adds someone who was not a member: first contact
    assert_eq!(s.welcome(&g1, "dead", BOB, &roster(&[ALICE, BOB, "did:web:mallory.example"])), vec![Converge::FirstContact(g1.clone())]);

    // the conversation lives in g3 while this device is in it; the thread is g3 and the dead group
    let member = ["dead", g3.as_str()];
    assert_eq!(s.live("dead", |g| member.contains(&g)), g3);
    assert_eq!(s.live("dead", |g| g == "dead"), "dead");
    let mut thread = vec!["dead".to_string(), g3.clone()];
    thread.sort();
    assert_eq!(s.lineage(&g3, member.iter().copied()).into_iter().collect::<Vec<_>>(), thread);

    // persisted exactly as the tracker itself (both clients' saved state)
    let mut t = SuccessorTracker::default();
    t.member_of("dead", &roster(&[ALICE, BOB]));
    t.step(&json!({"created": {"group": g7, "successor_of": "dead"}}));
    let mut w = Successors::default();
    w.member_of("dead", &roster(&[ALICE, BOB]));
    w.created(&g7, "dead");
    assert_eq!(serde_json::to_value(&w).unwrap(), serde_json::to_value(&t).unwrap());
    let back: Successors = serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
    assert_eq!(back.successor("dead"), Some(g7.as_str()));
}

#[test]
fn the_creator_is_leaf_zero() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let (i, d) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    let dev = Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature));
    let conv = json!({"conversation": "01K742SG00XZRF7H1Z8WN9CGAD", "kind": "direct",
                      "hub": {"did": "did:web:mbx.example", "uri": "wss://mbx.example/dsip"}, "successor_of": "dead"});
    let g = dev.create_group(b"group-2", &serde_json::to_vec(&conv).unwrap()).unwrap();
    assert_eq!(successors::creator(&g, &ctx), i.did());
}
