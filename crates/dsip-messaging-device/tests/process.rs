//! The shared item processing on real MLS: a welcome joined and attributed to the member who added us, content
//! checked and handed over, a forged sender dropped, and a leave proposal ignored or stored as the host's options say.
//!
//! Spec: M§6.2, M§7.3 ("Leaving", spec-gap 125), M§8.1.

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use serde_json::{json, Value};

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_messaging_device::{process, Outcome, ProcessOptions};
use dsip_mls::{authenticate_key_package, Device};

const NOW: i64 = 1_790_000_000;
const ALL: ProcessOptions = ProcessOptions { leaf_device_in_check: true, recorder_content_unauthenticated: true, keep_call_records: true, store_proposals: true };

fn ulid(n: u8) -> String {
    Ulid::from_parts((NOW as u64) * 1000 + u64::from(n), [n; 10]).as_str().to_string()
}

fn device(identity: &str, dev: &str) -> (String, Device) {
    let (i, d) = (KeyPair::from_fixture_name(identity), KeyPair::from_fixture_name(dev));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.signaling", "dsip.messaging"]);
    let e = sign(&p, &i, &i.kid());
    (i.did(), Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature)))
}

fn bytes(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().expect("serialize")
}

#[test]
fn one_processing_for_every_host() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let (alice, alice_dev) = device("alice", "alice-phone");
    let (bob, bob_phone) = device("bob", "bob-phone");
    let (_, bob_laptop) = device("bob", "bob-laptop");
    let conversation = ulid(1);
    let conv = json!({"conversation": conversation, "kind": "group", "hub": {"did": "did:web:mbx.example", "uri": "wss://mbx.example/dsip"},
                      "successor_of": null});
    let mut ag = alice_dev.create_group(ulid(2).as_bytes(), &serde_json::to_vec(&conv).unwrap()).unwrap();
    let kps: Vec<KeyPackage> = [&bob_phone, &bob_laptop]
        .iter()
        .map(|d| authenticate_key_package(&d.key_package().unwrap(), alice_dev.provider(), &ctx).unwrap().0)
        .collect();
    let (_, welcome, _) = ag.add_members(alice_dev.provider(), &alice_dev.signer(), &kps).unwrap();
    ag.merge_pending_commit(alice_dev.provider()).unwrap();

    // a welcome: joined, every member authenticated, the add attributed to Alice (M§6.2, M§7.3)
    let joined = process(&bob_phone, None, "welcome", &bytes(&welcome), &ctx, &bob, ProcessOptions::default()).unwrap();
    let Outcome::Joined { members, conv: got, by, .. } = joined else { panic!("{joined:?}") };
    assert_eq!(by, alice);
    assert!(members.contains(&alice) && members.contains(&bob));
    assert_eq!(got["conversation"], conversation.as_str());
    // the joined group is in the device's storage, where the host loads it from
    let gid = ag.group_id().as_slice().to_vec();
    let mut pg = bob_phone.load_group(&gid).unwrap().expect("stored by the join");

    // content from Alice: checked, handed over; a forged sender is dropped (M§8.1)
    let mut bg = bob_laptop.join(&bytes(&welcome)).unwrap();
    let text = |n: u8, sender: &str| json!({"object": "content", "id": ulid(n), "conversation": conversation, "sender": sender, "sent_at": NOW,
                                            "kind": "text", "purpose": "message", "content_type": "text/plain", "text": "Dinner at 7?"});
    let send = |g: &mut MlsGroup, o: &Value| bytes(&g.create_message(alice_dev.provider(), &alice_dev.signer(), &serde_json::to_vec(o).unwrap()).unwrap());
    let m = send(&mut ag, &text(3, &alice));
    let out = process(&bob_laptop, Some((&mut bg, &conversation, "group")), "application", &m, &ctx, &bob, ALL).unwrap();
    assert!(matches!(&out, Outcome::Object { sender, object, .. } if *sender == alice && object["text"] == "Dinner at 7?"), "{out:?}");
    let forged = send(&mut ag, &text(4, &bob));
    let out = process(&bob_laptop, Some((&mut bg, &conversation, "group")), "application", &forged, &ctx, &bob, ALL).unwrap();
    assert!(matches!(out, Outcome::Dropped(_)), "{out:?}");
    assert_eq!(bg.group_id().as_slice(), gid.as_slice());

    // a leave proposal (M§7.3 "Leaving"): ignored without store_proposals, stored and reported with it
    let own = bytes(&bg.leave_group(bob_laptop.provider(), &bob_laptop.signer()).unwrap());
    let out = process(&alice_dev, Some((&mut ag, &conversation, "group")), "handshake", &own, &ctx, &alice, ProcessOptions::default()).unwrap();
    assert_eq!(out, Outcome::Nothing);
    assert_eq!(ag.pending_proposals().count(), 0, "not stored");
    let phone_leaves = bytes(&pg.leave_group(bob_phone.provider(), &bob_phone.signer()).unwrap());
    let out = process(&alice_dev, Some((&mut ag, &conversation, "group")), "handshake", &phone_leaves, &ctx, &alice, ALL).unwrap();
    let Outcome::Proposal { proposer, removes, others, roster } = out else { panic!("{out:?}") };
    assert_eq!(proposer, json!({"identity": bob, "device": bob_phone.did()}));
    assert_eq!(removes, vec![json!({"identity": bob, "device": bob_phone.did()})]);
    assert_eq!((others, roster.len()), (0, 3));
    assert_eq!(ag.pending_proposals().count(), 1, "stored for the next commit");
}
