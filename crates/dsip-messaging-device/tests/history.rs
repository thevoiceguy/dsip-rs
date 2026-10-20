//! Receipts and history as both messaging clients drive them: the receipts machine's decisions as types, a read
//! watermark held back by the interval coming back with the next event, what of a device's own objects is history,
//! archive records opened once, restored history waiting for its conversation, and a sync's batch collected per
//! conversation, a sibling's watermark in the personal group under the conversation it names.
//!
//! Spec: M§10.2, M§10.3, M§10.5 (spec-gap 52), M§11.2, M§12.2 (spec-gaps 51, 64, 68, 63), M§12.3, M§8.5.

use serde_json::json;

use dsip_messaging_device::archive::{self, Received};
use dsip_messaging_device::history::{self, Decision, Restored};
use dsip_messaging_device::receipts::{self, Emission, Receipt};
use dsip_messaging_device::{History, Receipts};

const NOW: i64 = 1_790_000_000;
const CONV: &str = "01K742SG00XZRF7H1Z8WN9CGAD";

fn content(id: &str, sender: &str) -> serde_json::Value {
    json!({"object": "content", "id": id, "conversation": CONV, "sender": sender, "sent_at": NOW, "kind": "text", "text": "hi"})
}

#[test]
fn receipts_as_types() {
    let policy = json!({"delivered": true, "read": true, "played": true, "activity": true});
    let mut r = Receipts::new("did:web:alice.example", &policy, NOW);

    // a fresh message from Bob: delivered, decided for the batch (M§10.2); our own: nothing to send
    let e = r.sync(NOW, vec![json!({"seq": 1, "object": content("c1", "did:web:bob.example")})]);
    let Emission::Receipt(d) = &e[0] else { panic!("{e:?}") };
    assert_eq!((d.kind.as_str(), d.personal, d.targets.clone()), ("delivered", false, Some(json!(["c1"]))));
    assert!(r.own(NOW, 2, &content("c2", "did:web:alice.example")).is_empty());

    // the receipt object (M§10.1)
    let obj = d.object(CONV, "did:web:alice.example", "r1", NOW);
    assert_eq!(obj, json!({"object": "receipt", "id": "r1", "conversation": CONV, "sender": "did:web:alice.example",
                           "sent_at": NOW, "kind": "delivered", "targets": ["c1"]}));

    // read through c1, then c3 within 5 s: held back (M§10.3), and it comes back with the next event, not lost
    assert!(matches!(&r.read(NOW, &json!("c1"))[..], [Emission::Receipt(Receipt { kind, through: Some(_), .. })] if kind == "read"));
    r.sync(NOW + 1, vec![json!({"seq": 3, "object": content("c3", "did:web:bob.example")})]);
    assert!(r.read(NOW + 1, &json!("c3")).is_empty());
    let e = r.sync(NOW + 6, vec![json!({"seq": 4, "object": content("c4", "did:web:bob.example")})]);
    let kinds: Vec<&str> = e.iter().filter_map(|x| if let Emission::Receipt(r) = x { Some(r.kind.as_str()) } else { None }).collect();
    assert_eq!(kinds, ["read", "delivered"]);

    // a delivered receipt for our content changes rendering: archived (spec-gap 64)
    let items = vec![json!({"seq": 5, "object": {"object": "receipt", "id": "r9", "conversation": CONV, "sender": "did:web:bob.example",
                                                 "sent_at": NOW, "kind": "delivered", "targets": ["c2"]}, "src": "g"})];
    assert_eq!(r.sync(NOW + 6, items.clone()), vec![Emission::Archive(5)]);
    assert_eq!(receipts::archived(&items, 5).count(), 1);
    assert_eq!(receipts::archived(&items, 4).count(), 0);

    // activity, under the same opt-in (M§11.2)
    assert_eq!(r.activity(NOW + 6, "typing", "active"), vec![Emission::Activity { activity: "typing".into(), state: "active".into() }]);

    // undisclosed: the watermark goes to the personal group (M§10.5)
    let mut r = Receipts::new("did:web:alice.example", &json!({"delivered": true}), NOW);
    r.sync(NOW, vec![json!({"seq": 1, "object": content("c1", "did:web:bob.example")})]);
    assert!(matches!(&r.read(NOW, &json!("c1"))[..], [Emission::Receipt(Receipt { personal: true, .. })]));
}

#[test]
fn history_as_types() {
    let mut h = History::new([("ak1", NOW)], [("g", 3)]);
    assert_eq!(h.current_akid().as_deref(), Some("ak1"));

    // our own content is shown and archived (spec-gap 51); a read watermark and a call event archived as state
    // (spec-gaps 68, 63); a delivered receipt or an archive key is not history
    let archive = Decision::Archive { group: "g".into(), seq: 7, akid: "ak1".into() };
    assert_eq!(h.sent("g", 7, "k7", &content("c7", "me")), vec![Decision::Show("k7".into()), archive.clone()]);
    assert_eq!(h.sent("g", 7, "r7", &json!({"object": "receipt", "kind": "read"})), vec![archive.clone()]);
    assert_eq!(h.sent("g", 7, "call:s", &json!({"object": "call-event"})), vec![archive.clone()]);
    assert!(h.sent("g", 8, "r8", &json!({"object": "receipt", "kind": "delivered"})).is_empty());
    assert!(h.sent("g", 8, "a8", &json!({"object": "archive-key"})).is_empty());

    // MLS items from before this device joined are not its (M§12.3); a copy already shown is a duplicate (M§8.5)
    assert_eq!(h.mls("g", 1, 2, "k1"), vec![Decision::Prejoin(json!(1))]);
    assert_eq!(h.mls("g", 7, 3, "k7"), vec![Decision::Duplicate("k7".into())]);

    // the records those decisions ask for
    let at = Received { conversation: CONV, group: "g", seq: 7, sender: "me", sender_device: "did:key:z6Mk", received_at: NOW };
    let records = history::archive_records(&[Decision::Show("k7".into()), archive], &at, &content("c7", "me"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "ak1");
    assert_eq!(records[0].1["payload"]["id"], "c7");

    // an archive item opened: shown once, then a duplicate (M§12.3 step 5, M§8.5)
    let key = [7u8; 32];
    let group = dsip_core::b64::encode(b"group-1");
    let record = archive::record(&Received { group: &group, ..at }, &content("c9", "did:web:bob.example"));
    let fields = archive::seal_record(&key, &[1; 12], "ak1", &record).unwrap();
    let item = json!({"cursor": "cur1", "akid": "ak1", "group": group, "seq": 7, "archive": fields["archive"]});
    let opened = archive::open_item(&key, &item).unwrap();
    assert_eq!(h.opened(&item, &opened, "k9"), vec![Decision::Show("k9".into())]);
    assert_eq!(h.opened(&item, &opened, "k9"), vec![Decision::Duplicate("k9".into())]);

    // an item under a key not held is held
    assert_eq!(h.held(&json!({"cursor": "cur2", "akid": "ak2", "group": "g", "seq": 9})), vec![Decision::Hold(json!("cur2"))]);
    assert_eq!(h.snapshot()["held"], json!(["cur2"]));
}

#[test]
fn restored_history_waits_for_its_conversation() {
    let mut r = Restored::default();
    r.push(4, &content("c4", "did:web:bob.example"));
    r.push(5, &json!({"object": "content", "id": "c5", "conversation": "other"}));
    // the conversation's own group, not the personal group that also carries it (spec-gap 64)
    let groups = [("personal", CONV, true), ("direct", CONV, false)];
    let ready = r.ready(groups.iter().copied());
    assert_eq!(ready.keys().collect::<Vec<_>>(), ["direct"]);
    assert_eq!(ready["direct"][0]["seq"], 4);
    // the other waits, and is kept as the browser persists it
    assert_eq!(r.items(), [json!({"seq": 5, "object": {"object": "content", "id": "c5", "conversation": "other"}, "conversation": "other"})]);
}

#[test]
fn a_batch_collects_per_group_and_a_personal_group_receipt_goes_to_its_conversation() {
    let convs = [("G-personal", "P"), ("G-chat", CONV)];
    let watermark = json!({"object": "receipt", "kind": "read", "conversation": CONV, "through": {"G-chat": 4}});
    // spec-gap 52: a sibling's undisclosed watermark, received in the personal group, describes the conversation
    assert_eq!(receipts::receipt_target("G-personal", true, &watermark, convs.into_iter()).as_deref(), Some("G-chat"));
    let elsewhere = json!({"object": "receipt", "kind": "read", "conversation": "01K742SG00XZRF7H1Z8WN9CGZZ"});
    assert_eq!(receipts::receipt_target("G-personal", true, &elsewhere, convs.into_iter()), None);
    assert_eq!(receipts::receipt_target("G-chat", false, &watermark, convs.into_iter()).as_deref(), Some("G-chat"));

    let mut batch = receipts::Batch::default();
    assert!(batch.is_empty());
    batch.content("G-chat", 3, &content("m1", "did:web:bob"));
    batch.receipt("G-personal", "G-chat", 7, &watermark, "did:key:z6Sibling");
    let taken = batch.take();
    assert!(batch.is_empty());
    let items = &taken["G-chat"];
    assert_eq!(taken.len(), 1);
    assert_eq!(items[0]["seq"], json!(3));
    // spec-gap 64: archived under the group it arrived in
    assert_eq!(items[1], json!({"seq": 7, "object": watermark, "src": "G-personal", "sender_device": "did:key:z6Sibling"}));
    assert_eq!(receipts::archived(items, 7).count(), 1);
}
