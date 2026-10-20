//! The options where dsip-msg and the browser still behave differently, each preset giving what that client did:
//! object keys, welcomes, the still-needed test for a named device and the recorded roster, which differ once a
//! member's delegation has lapsed.
//!
//! Spec: M§8.5, M§9.4 (spec-gap 72), M§6.5, M§7.2, M§7.5, M§12.1.

use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_messaging_device::commits::{self, Change};
use dsip_messaging_device::Config;
use dsip_mls::{authenticate_key_package, Device};

const NOW: i64 = 1_790_000_000;
const DAY: i64 = 86_400;

fn device(identity: &str, dev: &str, days: i64) -> (String, String, Device) {
    let (i, d) = (KeyPair::from_fixture_name(identity), KeyPair::from_fixture_name(dev));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + days * DAY, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    let did = d.did();
    (i.did(), did, Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature)))
}

#[test]
fn keys_welcomes_and_timeouts() {
    let (m, b) = (Config::DSIP_MSG, Config::BROWSER);
    assert_eq!((m.no_answer_s, b.no_answer_s), (20, 60));
    let content = json!({"object": "content", "conversation": "c", "sender": "did:web:bob.example", "id": "x"});
    assert_eq!(m.object_key(&content), "c|did:web:bob.example|x");
    assert_eq!(b.object_key(&content), "c:x");
    let call = json!({"object": "call-event", "session": "s"});
    assert_eq!((m.object_key(&call), b.object_key(&call)), ("call|s".to_string(), "call:s".to_string()));
    // an Add's welcome always goes; another commit's only for dsip-msg
    assert!(m.deposits_welcome(true) && b.deposits_welcome(true));
    assert!(m.deposits_welcome(false) && !b.deposits_welcome(false));
    assert!(m.replace_archive_keys && !b.replace_archive_keys);
    assert!(m.rejoin_gaps && !b.rejoin_gaps);
}

#[test]
fn a_lapsed_member_tells_the_presets_apart() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let (alice, _, alice_dev) = device("alice", "alice-phone", 30);
    let (bob, bob_phone, bob_dev) = device("bob", "bob-phone", 2); // Bob's phone's delegation lapses in two days
    let conv = json!({"conversation": "01K742SG00XZRF7H1Z8WN9CGAD", "kind": "direct",
                      "hub": {"did": "did:web:mbx.example", "uri": "wss://mbx.example/dsip"}, "successor_of": null});
    let mut g = alice_dev.create_group(b"group-3", &serde_json::to_vec(&conv).unwrap()).unwrap();
    let kp = authenticate_key_package(&bob_dev.key_package().unwrap(), alice_dev.provider(), &ctx).unwrap().0;
    commits::build(&alice_dev, &mut g, Change::Add(&[kp])).unwrap();
    g.merge_pending_commit(alice_dev.provider()).unwrap();

    // today: both presets agree
    for c in [Config::DSIP_MSG, Config::BROWSER] {
        assert!(!c.add_needed(&g, &ctx, &bob, Some(&bob_phone)));
        assert!(!c.add_needed(&g, &ctx, &bob, None));
        let mut both = vec![alice.clone(), bob.clone()];
        both.sort();
        assert_eq!(c.roster(&g, &ctx), Some(both));
    }

    // a week on, Bob's phone no longer authenticates: its credential is still a leaf
    let later = Context::new(NOW + 7 * DAY, &resolver);
    assert!(!Config::DSIP_MSG.add_needed(&g, &later, &bob, Some(&bob_phone)));
    assert!(Config::BROWSER.add_needed(&g, &later, &bob, Some(&bob_phone)));
    // no roster from a group with a leaf that does not authenticate (dsip-msg), or the leaves that do (browser)
    assert_eq!(Config::DSIP_MSG.roster(&g, &later), None);
    assert_eq!(Config::BROWSER.roster(&g, &later), Some(vec![alice]));
}
