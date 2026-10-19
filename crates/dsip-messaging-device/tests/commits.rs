//! Commits both messaging clients make, on real MLS: an Add with its welcome and grants, a whole identity's leaves
//! removed, a device's leaves found by credential, a move of the hub, and `CommitRetry`'s decisions read as types.
//!
//! Spec: M§6.5 (spec-gap 58), M§7.2, M§7.3 (spec-gap 126), M§7.4 (spec-gap 60), M§14.2.

use openmls::prelude::*;
use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_messaging_device::commits::{self, Answer, Change, Synced};
use dsip_messaging_device::Retry;
use dsip_mls::{authenticate_key_package, Device};

const NOW: i64 = 1_790_000_000;

fn device(identity: &str, dev: &str) -> (String, String, Device) {
    let (i, d) = (KeyPair::from_fixture_name(identity), KeyPair::from_fixture_name(dev));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    let did = d.did();
    (i.did(), did, Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature)))
}

#[test]
fn built_merged_and_found() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let (alice, _, alice_dev) = device("alice", "alice-phone");
    let (bob, bob_phone_did, bob_phone) = device("bob", "bob-phone");
    let (_, bob_laptop_did, bob_laptop) = device("bob", "bob-laptop");
    let conv = json!({"conversation": "01K742SG00XZRF7H1Z8WN9CGAD", "kind": "group",
                      "hub": {"did": "did:web:mbx.example", "uri": "wss://mbx.example/dsip"}, "successor_of": null});
    let mut g = alice_dev.create_group(b"group-1", &serde_json::to_vec(&conv).unwrap()).unwrap();
    let kps: Vec<KeyPackage> = [&bob_phone, &bob_laptop]
        .iter()
        .map(|d| authenticate_key_package(&d.key_package().unwrap(), alice_dev.provider(), &ctx).unwrap().0)
        .collect();

    // an Add: both of Bob's devices in one commit, with a welcome and the grant that admitted them (M§7.2, M§14.2)
    let built = commits::build(&alice_dev, &mut g, Change::Add(&kps)).unwrap();
    assert!(built.welcome.is_some());
    let fields = built.fields(&["grant-1".to_string()]);
    assert!(fields["mls"].is_string() && fields["welcome"].is_string());
    assert_eq!(fields["grants"], json!(["grant-1"]));
    // staged, not applied, until the hub accepts it (M§6.5)
    assert!(!commits::has_member(&g, &ctx, &bob, None));
    g.merge_pending_commit(alice_dev.provider()).unwrap();
    assert!(commits::has_member(&g, &ctx, &bob, None));
    assert!(commits::has_member(&g, &ctx, &bob, Some(&bob_laptop_did)));
    assert!(!commits::has_member(&g, &ctx, &bob, Some("did:key:z6MkNotBobsDevice")));
    assert!(commits::has_member(&g, &ctx, &alice, None));

    // Bob's leaves: every device of him by identity, one by credential
    assert_eq!(commits::identity_leaves(&g, &ctx, &bob).len(), 2);
    assert_eq!(commits::device_leaves(&g, &bob_phone_did).len(), 1);
    assert!(commits::identity_leaves(&g, &ctx, "did:web:carol.example").is_empty());

    // a Remove of the whole identity: no welcome, no grants field (M§7.3, spec-gap 126)
    let leaves = commits::identity_leaves(&g, &ctx, &bob);
    let built = commits::build(&alice_dev, &mut g, Change::Remove(&leaves)).unwrap();
    assert_eq!(built.fields(&[]).as_object().unwrap().keys().collect::<Vec<_>>(), vec!["mls"]);
    g.merge_pending_commit(alice_dev.provider()).unwrap();
    assert!(!commits::has_member(&g, &ctx, &bob, None));

    // a move of the hub, then a self-update: each a commit of its own
    let hub = json!({"did": "did:web:hub2.example", "uri": "wss://hub2.example/dsip"});
    let built = commits::build(&alice_dev, &mut g, Change::MoveHub(&hub)).unwrap();
    assert!(built.welcome.is_none() && !built.commit.is_empty());
    g.merge_pending_commit(alice_dev.provider()).unwrap();
    let epoch = g.epoch().as_u64();
    commits::build(&alice_dev, &mut g, Change::Update).unwrap();
    g.merge_pending_commit(alice_dev.provider()).unwrap();
    assert_eq!(g.epoch().as_u64(), epoch + 1);
}

#[test]
fn retry_decisions_as_types() {
    // accepted: merged
    assert_eq!(Retry::default().answer(None), Answer::Merge);

    // a conflict: discarded, synced, proposed again while needed, at most three proposals in all (spec-gap 58)
    let mut r = Retry::default();
    assert_eq!(r.answer(Some("mailbox.commit-conflict")), Answer::Discard { surface: None });
    assert_eq!(r.synced(true, false), Synced::Repropose(2));
    assert_eq!(r.answer(Some("mailbox.stale-epoch")), Answer::Discard { surface: None });
    assert_eq!(r.synced(true, false), Synced::Repropose(3));
    assert_eq!(r.answer(Some("mailbox.commit-conflict")), Answer::Discard { surface: Some("mailbox.commit-conflict".into()) });

    // a winning commit made the change: done
    let mut r = Retry::default();
    r.answer(Some("mailbox.commit-conflict"));
    assert_eq!(r.synced(false, false), Synced::Done);

    // unknown-group: retried only if the sync shows the group moved (spec-gap 60)
    let mut r = Retry::default();
    assert_eq!(r.answer(Some("mailbox.unknown-group")), Answer::Discard { surface: None });
    assert_eq!(r.synced(true, false), Synced::Surface("mailbox.unknown-group".into()));
    let mut r = Retry::default();
    r.answer(Some("mailbox.unknown-group"));
    assert_eq!(r.synced(true, true), Synced::Repropose(2));

    // any other refusal: given up at once
    assert_eq!(Retry::default().answer(Some("auth.forbidden")), Answer::Discard { surface: Some("auth.forbidden".into()) });
}
