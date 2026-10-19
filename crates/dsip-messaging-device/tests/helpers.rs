//! The pure helpers both messaging clients share: KeyPackage selection on real KeyPackages, the recording state, blobs,
//! archive records and call records.
//!
//! Spec: M§5.5, M§8.4, M§12.2, M§13.3, C§5, C§9.

use std::collections::BTreeSet;

use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_messaging::mls_wire::LeafIdentity;
use dsip_messaging_device::{archive, blob, calls, key_packages, recording};
use dsip_mls::Device;

const NOW: i64 = 1_790_000_000;

fn device(identity: &str, dev: &str, caps: &[&str]) -> (String, String, Device) {
    let (i, d) = (KeyPair::from_fixture_name(identity), KeyPair::from_fixture_name(dev));
    let p = delegation_payload(&i.did(), &d.did(), NOW - 3600, NOW + 7 * 86400, caps);
    let e = sign(&p, &i, &i.kid());
    let did = d.did();
    (i.did(), did, Device::new(d, format!("{}.{}.{}", e.protected, e.payload, e.signature)))
}

const PLAIN: &[&str] = &["dsip.signaling", "dsip.messaging"];
const RECORDER: &[&str] = &["dsip.signaling", "dsip.messaging", "dsip.record"];

#[test]
fn key_packages_authenticated_then_selected() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let (alice, alice_phone, alice_dev) = device("alice", "alice-phone", PLAIN);
    let (bob, bob_phone_did, bob_phone) = device("bob", "bob-phone", PLAIN);
    let (_, bob_rec_did, bob_rec) = device("bob", "bob-recorder", RECORDER);
    let kp = |d: &Device| dsip_core::b64::encode(&d.key_package().unwrap());
    let me = key_packages::Me { identity: &alice, device: &alice_phone };

    // every device of the target, the last-resort one included; a forged entry and this device are never added (M§5.5, C§5)
    let payload = json!({"type": "key-packages", "key_packages": [kp(&bob_phone), "AAAA", kp(&alice_dev)], "last_resort": kp(&bob_rec)});
    let got = key_packages::select(&payload, &bob, &me, "conversation", alice_dev.provider(), &ctx).unwrap();
    let devices: BTreeSet<String> = got.iter().map(|(_, k)| dsip_mls::authenticate_key_package(&k.tls_bytes(), alice_dev.provider(), &ctx).unwrap().1.device).collect();
    assert_eq!(devices, BTreeSet::from([bob_phone_did.clone(), bob_rec_did.clone()]));
    for (bytes, _) in &got {
        assert!(dsip_mls::authenticate_key_package(bytes, alice_dev.provider(), &ctx).is_ok(), "the bytes are the KeyPackage's own");
    }

    // only a recorder of someone else: refused (C§5)
    let payload = json!({"type": "key-packages", "key_packages": [kp(&bob_rec)]});
    assert_eq!(key_packages::select(&payload, &bob, &me, "conversation", alice_dev.provider(), &ctx).unwrap_err(), "recorder-only");
    // nothing that authenticates
    let payload = json!({"type": "key-packages", "key_packages": ["AAAA"]});
    assert_eq!(key_packages::select(&payload, &bob, &me, "conversation", alice_dev.provider(), &ctx).unwrap_err(), "no-key-packages");
}

trait TlsBytes {
    fn tls_bytes(&self) -> Vec<u8>;
}

impl TlsBytes for openmls::prelude::KeyPackage {
    fn tls_bytes(&self) -> Vec<u8> {
        use openmls::prelude::tls_codec::Serialize as _;
        self.tls_serialize_detached().unwrap()
    }
}

#[test]
fn recording_state_pending_until_accepted() {
    let leaf = |identity: &str, device: &str, caps: &[&str]| LeafIdentity {
        identity: identity.into(), device: device.into(), capabilities: caps.iter().map(|c| c.to_string()).collect(),
    };
    let leaves = [leaf("did:a", "did:a1", PLAIN), leaf("did:b", "did:b1", PLAIN), leaf("did:b", "did:brec", RECORDER), leaf("did:a", "did:arec", RECORDER)];
    // the recorder of my own identity needs no acceptance; Bob's does (C§5)
    let st = recording::state(&leaves, "did:a", &BTreeSet::new());
    assert_eq!(st["recorded"], true);
    assert_eq!(st["may_send"], false);
    assert_eq!(st["pending"], json!([{"device": "did:brec", "subject": "did:b"}]));
    let st = recording::state(&leaves, "did:a", &BTreeSet::from(["did:brec".to_string()]));
    assert_eq!(st["may_send"], true);
    assert_eq!(st["pending"], json!([]));
    assert_eq!(recording::state(&leaves[..2], "did:a", &BTreeSet::new())["recorded"], false);
}

#[test]
fn blob_sealed_opened_and_fetch_decided() {
    let (key, nonce) = ([7u8; 32], [9u8; 12]);
    let sealed = blob::seal_blob(&key, &nonce, b"OggS opus");
    assert_eq!(sealed.sha256, dsip_mls::digest(&sealed.bytes));
    let key_b64 = dsip_core::b64::encode(&key);
    let up = blob::Uploaded { uri: "https://mbx.example/blob/x", sha256: &sealed.sha256, size: sealed.bytes.len() as u64, key: &key_b64,
                              content_type: "audio/ogg; codecs=opus" };
    let obj = blob::audio_content("01J", "conv", "did:a", NOW, "voicemail", 1200, &up, Some("sess"));
    assert_eq!(obj["blob"]["alg"], "A256GCM");
    assert_eq!(obj["session"], "sess");
    assert!(blob::audio_content("01J", "conv", "did:a", NOW, "voice-message", 1200, &up, None).get("session").is_none());

    // M§8.4 rule 7: the content's bytes open; other bytes do not
    assert_eq!(blob::open(&obj, &sealed.bytes).unwrap(), b"OggS opus");
    let mut other = sealed.bytes.clone();
    other[20] ^= 1;
    assert!(blob::open(&obj, &other).is_err());
    assert_eq!(blob::open(&json!({"blob": {"key": "x"}}), &sealed.bytes), Err("blob-key"));

    // sources: the manifest's copy at another uri first, then the content's own (rule 6)
    let manifest = json!([{"uri": "https://other.example/b", "sha256": sealed.sha256, "size": sealed.bytes.len()}]);
    assert_eq!(blob::sources(&obj, &manifest), vec!["https://other.example/b".to_string(), "https://mbx.example/blob/x".to_string()]);

    // spec-gap 106: nothing served yet → retry; only other bytes → give up
    assert_eq!(blob::fetch_decision(&obj, &json!([{"uri": "u", "status": 404}]), 1), blob::Fetch::Retry);
    assert_eq!(blob::fetch_decision(&obj, &json!([{"uri": "u", "status": 200, "sha256": "00", "size": 1}]), 1),
               blob::Fetch::GiveUp("mismatch".into()));
    let served = json!([{"uri": "u", "status": 200, "sha256": sealed.sha256, "size": sealed.bytes.len()}]);
    assert_eq!(blob::fetch_decision(&obj, &served, 1), blob::Fetch::Play("u".into()));
}

#[test]
fn archive_record_sealed_to_its_group_and_seq() {
    let key = [3u8; 32];
    let group = dsip_core::b64::encode(b"group-1");
    let payload = json!({"object": "content", "id": "01J", "kind": "text", "text": "hi"});
    let rec = archive::record(&archive::Received { conversation: "conv", group: &group, seq: 42, sender: "did:a", sender_device: "did:a1",
                                                   received_at: NOW }, &payload);
    assert_eq!(rec["object"], "archive-record");
    let fields = archive::seal_record(&key, &[1; 12], "ak1", &rec).unwrap();
    assert_eq!((fields["akid"].as_str(), fields["ref_seq"].as_i64()), (Some("ak1"), Some(42)));

    let item = json!({"cursor": "c1", "akid": "ak1", "group": group, "seq": 42, "archive": fields["archive"]});
    let opened = archive::open_item(&key, &item).unwrap();
    assert_eq!((opened.seq, &opened.record), (42, &rec));
    let ev = archive::history_event(&item, &opened, "k");
    assert_eq!(ev["archive"]["object"], "content");
    // AAD group ‖ seq (M§12.2): moved to another seq, or under another key, it does not open
    let moved = json!({"cursor": "c1", "akid": "ak1", "group": group, "seq": 43, "archive": fields["archive"]});
    assert!(matches!(archive::open_item(&key, &moved), Err(archive::OpenError::DoesNotOpen)));
    assert!(matches!(archive::open_item(&[4; 32], &item), Err(archive::OpenError::DoesNotOpen)));
    assert!(archive::seal_record(&key, &[1; 12], "ak1", &json!({"group": "not base64url!", "seq": 1})).is_none());
}

#[test]
fn call_events_and_records() {
    let ended = |alerted, answered_here, ended_by, reason| calls::Ended { session: "s1", peer: "did:b", alerted, answered_here, ended_by, reason };
    // M§13.3: missed and declined are recorded; answered here, answered elsewhere and never alerted are not
    assert_eq!(calls::call_event(&ended(true, false, "remote", ""), NOW).unwrap()["outcome"], "missed");
    assert_eq!(calls::call_event(&ended(true, false, "local", "user.declined"), NOW).unwrap()["outcome"], "declined");
    assert!(calls::call_event(&ended(true, true, "local", ""), NOW).is_none());
    assert!(calls::call_event(&ended(true, false, "remote", "session.answered-elsewhere"), NOW).is_none());
    assert!(calls::call_event(&ended(false, false, "remote", ""), NOW).is_none());

    // C§9: answered_at only when answered; ended_at never before the answer (a peer's clock ahead of ours)
    let dev = KeyPair::from_fixture_name("alice-phone").did();
    let leg = json!({"session": "01K742SG00XZRF7H1Z8WN9CGAD", "direction": "outbound", "peer": "did:web:b.example", "invited_at": NOW - 30, "answered": true,
                     "answered_at": NOW + 5, "ended_by": "local", "relay": "", "media": []});
    let rec = calls::call_record(&leg, &dev, NOW).unwrap_or_else(|c| panic!("{c}"));
    assert_eq!((rec["outcome"].as_str(), rec["answered_at"].as_i64(), rec["ended_at"].as_i64()), (Some("answered"), Some(NOW + 5), Some(NOW + 5)));
    assert!(rec.get("relay").is_none() && rec.get("media").is_none(), "empty optionals are left out");
    let missed = json!({"session": "01K742SG00XZRF7H1Z8WN9CGAD", "direction": "inbound", "peer": "did:web:b.example", "invited_at": NOW - 30, "answered": false,
                        "answered_at": NOW - 20, "ended_by": "remote"});
    let rec = calls::call_record(&missed, &dev, NOW).unwrap_or_else(|c| panic!("{c}"));
    assert!(rec.get("answered_at").is_none());
    assert_eq!(rec["ended_at"], NOW);
}
