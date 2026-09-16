//! End to end on real MLS: two DSIP identities, a hub, a mailbox, a text message, a voicemail,
//! activity, archive sealing and a commit conflict — every protocol decision made by the
//! vector-pinned `dsip-messaging` rules, every byte produced by OpenMLS.
//!
//! Spec: M§5.1, M§5.2, M§5.5, M§6.1–M§6.6, M§8.1, M§8.4, M§9.1, M§11.1, M§12.2, M§13.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use serde_json::{json, Value};

use dsip_core::b64;
use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_messaging::checks::{check_message, check_object, MAX_MLS_BYTES};
use dsip_messaging::hub::Hub;
use dsip_messaging::mailbox::Mailbox;
use dsip_messaging::mls_wire::{self, SealUse, EXT_DSIP_DELEGATION};
use dsip_mls::{
    activity_key, authenticate_key_package, authenticate_members, conversation_extension, digest, member_identity,
    message_header, Device, HubView,
};

const NOW: i64 = 1_790_000_000;
const HUB: &str = "did:web:mbx.alice.example";

fn ulid(n: u8) -> String {
    Ulid::from_parts((NOW as u64) * 1000 + u64::from(n), [n; 10]).as_str().to_string()
}

fn delegation(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> String {
    let p = delegation_payload(&identity.did(), &device.did(), NOW - 3600, NOW + 7 * 86400, caps);
    let e = sign(&p, identity, &identity.kid());
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}

fn device(identity: &str, dev: &str, caps: &[&str]) -> (String, Device) {
    let (i, d) = (KeyPair::from_fixture_name(identity), KeyPair::from_fixture_name(dev));
    let deleg = delegation(&i, &d, caps);
    (i.did(), Device::new(d, deleg))
}

fn bytes(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().expect("serialize")
}

fn deposit(id: &str, from: &str, group: &[u8], class: &str, fields: Value) -> Value {
    let mut p = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": []},
        "type": "deposit", "id": id, "from": from, "to": HUB, "group": b64::encode(group), "class": class,
        "issued_at": NOW, "expires_at": NOW + 30});
    for (k, v) in fields.as_object().expect("fields") {
        p[k] = v.clone();
    }
    p
}

/// Decrypt an application message and return (sender identity, content object).
fn receive(group: &mut MlsGroup, dev: &Device, msg: &[u8], ctx: &Context) -> (String, Value) {
    let pm = MlsMessageIn::tls_deserialize(&mut &msg[..]).unwrap().try_into_protocol_message().unwrap();
    let processed = group.process_message(dev.provider(), pm).expect("process");
    let Sender::Member(idx) = *processed.sender() else { panic!("sender not a member") };
    let who = member_identity(group, idx, ctx).expect("sender leaf authenticates");
    let ProcessedMessageContent::ApplicationMessage(app) = processed.into_content() else { panic!("not application") };
    (who.identity, serde_json::from_slice(&app.into_bytes()).expect("content is JSON"))
}

#[test]
fn messaging_end_to_end_on_real_mls() {
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let caps = ["dsip.signaling", "dsip.messaging"];
    let (alice, alice_dev) = device("alice", "alice-phone", &caps);
    let (bob, bob_dev) = device("bob", "bob-phone", &caps);

    // --- M§5.5: Bob's KeyPackage fits the profile size limit and authenticates as Bob (M§6.2)
    let kp_bytes = bob_dev.key_package().unwrap();
    assert!(kp_bytes.len() <= MAX_MLS_BYTES);
    let upload = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": []},
        "type": "key-packages", "id": ulid(1), "from": bob_dev.did(), "to": "did:web:mbx.bob.example", "subject": bob,
        "key_packages": [b64::encode(&kp_bytes)], "issued_at": NOW, "expires_at": NOW + 30});
    assert_eq!(check_message(&upload)["verdict"], "accept");
    let (kp, who) = authenticate_key_package(&kp_bytes, alice_dev.provider(), &ctx).expect("bob's key package");
    assert_eq!((who.identity.as_str(), who.device.as_str()), (bob.as_str(), bob_dev.did().as_str()));

    // --- A device delegated for calls only cannot enter a group (M§6.2, spec-gap 39)
    let (_, calls_only) = device("carol", "carol-phone", &["dsip.signaling"]);
    let e = authenticate_key_package(&calls_only.key_package().unwrap(), alice_dev.provider(), &ctx).unwrap_err();
    assert!(e.0.contains("delegation-capability"), "{e}");

    // --- M§6.3, M§7.2: Alice creates the direct conversation hubbed at her mailbox
    let conversation = ulid(2);
    let gid = ulid(3).into_bytes();
    let conv = json!({"conversation": conversation, "kind": "direct", "hub": {"did": HUB, "uri": "wss://mbx.alice.example/dsip"},
        "successor_of": null});
    let conv_bytes = serde_json::to_vec(&conv).unwrap();
    assert_eq!(mls_wire::check_conversation_bytes(&conv_bytes)["effective"]["kind"], "direct");
    let mut ag = alice_dev.create_group(&gid, &conv_bytes).unwrap();

    // The hub starts tracking the group from a GroupInfo with the ratchet tree; it holds no group secret.
    let gi = ag.export_group_info(alice_dev.provider().crypto(), &alice_dev.signer(), true).unwrap();
    let mut hub_view = HubView::from_group_info(&bytes(&gi)).unwrap();
    let mut hub = Hub::new(&json!({"now": NOW, "kind": "direct", "epoch": hub_view.epoch(),
        "roster": {alice.clone(): [alice_dev.did()]}}));

    // --- M§6.4–M§6.5: the commit adding Bob is a PublicMessage the hub validates, then sequences
    let (commit, welcome, _) = ag.add_members(alice_dev.provider(), &alice_dev.signer(), &[kp]).unwrap();
    let (commit, welcome) = (bytes(&commit), bytes(&welcome));
    let (hdr_gid, hdr_epoch, handshake) = message_header(&commit).unwrap();
    assert!(handshake && hdr_gid == gid && hdr_epoch == 0);
    let dep = deposit(&ulid(4), &alice_dev.did(), &gid, "handshake",
        json!({"mls": b64::encode(&commit), "welcome": b64::encode(&welcome)}));
    assert_eq!(check_message(&dep)["verdict"], "accept", "real commit + welcome fit the deposit rules");
    let observed = hub_view.observe_commit(&commit, &ctx).unwrap();
    assert_eq!(observed["adds"], json!([{"identity": bob, "device": bob_dev.did()}]));
    let emitted = hub.step(&json!({"deposit": {"id": ulid(4), "device": alice_dev.did(), "identity": alice, "class": "handshake",
        "epoch": hdr_epoch, "digest": digest(&commit), "commit": observed}}));
    assert_eq!(emitted[0]["accepted"]["seq"], 1);
    assert!(emitted.contains(&json!({"fanout": {"to": bob, "class": "welcome"}})), "{emitted:?}");
    assert_eq!(hub_view.epoch(), 1);
    ag.merge_pending_commit(alice_dev.provider()).unwrap();

    // --- M§14.2, M§6.6: Bob's mailbox admits the welcome under Bob's grant; Bob joins and authenticates everyone
    let mut bob_mbx = Mailbox::new(&json!({"now": NOW, "owner": bob, "serves": [bob], "devices": [bob_dev.did()]}));
    let grant = json!({"id": ulid(5), "from": bob, "to": alice, "scope": ["dsip.message"], "valid_until": NOW + 86400});
    let out = bob_mbx.step(&json!({"welcome": {"id": ulid(6), "from": alice_dev.did(), "adder_identity": alice, "recipient": bob,
        "group": b64::encode(&gid), "hub": HUB, "grant": grant}}));
    assert!(out[0].get("accepted").is_some(), "{out:?}");
    let mut bg = bob_dev.join(&welcome).unwrap();
    let members: Vec<String> = authenticate_members(&bg, &ctx).unwrap().into_iter().map(|m| m.identity).collect();
    assert_eq!(members, vec![alice.clone(), bob.clone()]);
    assert_eq!(conversation_extension(&bg).unwrap(), conv_bytes);

    // --- M§8.1, M§9.1: a text message, sequenced by the hub, decrypted and checked by Bob
    let text = json!({"object": "content", "id": ulid(7), "conversation": conversation, "sender": alice, "sent_at": NOW,
        "kind": "text", "purpose": "message", "content_type": "text/plain", "text": "Dinner at 7?"});
    let msg = bytes(&ag.create_message(alice_dev.provider(), &alice_dev.signer(), &serde_json::to_vec(&text).unwrap()).unwrap());
    let (_, epoch, handshake) = message_header(&msg).unwrap();
    assert!(!handshake && epoch == 1, "application messages are PrivateMessage");
    let emitted = hub.step(&json!({"deposit": {"id": ulid(8), "device": alice_dev.did(), "identity": alice, "class": "application",
        "epoch": epoch, "digest": digest(&msg)}}));
    assert_eq!(emitted[0]["accepted"]["seq"], 2);
    let (sender, obj) = receive(&mut bg, &bob_dev, &msg, &ctx);
    let octx = json!({"conversation": conversation, "conversation_kind": "direct", "leaf_identity": sender});
    assert_eq!(check_object(&obj, &octx), json!({"verdict": "accept", "effective": {"kind": "text", "purpose": "message"}}));
    assert_eq!(obj["text"], "Dinner at 7?");

    // A member cannot put words in another identity's mouth: sender is bound to the MLS leaf (M§8.1).
    let forged = json!({"object": "content", "id": ulid(9), "conversation": conversation, "sender": bob, "sent_at": NOW,
        "kind": "text", "purpose": "message", "content_type": "text/plain", "text": "I owe Alice $100"});
    let msg = bytes(&ag.create_message(alice_dev.provider(), &alice_dev.signer(), &serde_json::to_vec(&forged).unwrap()).unwrap());
    let (sender, obj) = receive(&mut bg, &bob_dev, &msg, &ctx);
    let octx = json!({"conversation": conversation, "conversation_kind": "direct", "leaf_identity": sender});
    assert_eq!(check_object(&obj, &octx)["code"], "sender-mismatch");

    // --- M§13, M§8.4: a voicemail as an encrypted blob referenced from an MLS message
    let audio: Vec<u8> = b"OggS".iter().copied().chain((0..4000u32).map(|i| (i % 251) as u8)).collect();
    let blob_key = [9u8; 32];
    let stored = mls_wire::seal(&blob_key, &[3u8; 12], &audio, SealUse::Blob);
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&stored));
    let vm = json!({"object": "content", "id": ulid(10), "conversation": conversation, "sender": alice, "sent_at": NOW,
        "kind": "audio", "purpose": "voicemail", "duration_ms": 28400, "session": ulid(11),
        "blob": {"uri": format!("https://mbx.alice.example/blobs/{sha}"), "sha256": sha, "size": stored.len(),
                 "key": b64::encode(&blob_key), "alg": "A256GCM", "content_type": "audio/ogg; codecs=opus"}});
    let msg = bytes(&ag.create_message(alice_dev.provider(), &alice_dev.signer(), &serde_json::to_vec(&vm).unwrap()).unwrap());
    let (sender, obj) = receive(&mut bg, &bob_dev, &msg, &ctx);
    let octx = json!({"conversation": conversation, "conversation_kind": "direct", "leaf_identity": sender});
    assert_eq!(check_object(&obj, &octx)["effective"], json!({"kind": "audio", "purpose": "voicemail"}));
    let key: [u8; 32] = b64::decode(obj["blob"]["key"].as_str().unwrap()).unwrap().try_into().unwrap();
    let opened = mls_wire::open_blob(&key, &stored, obj["blob"]["size"].as_u64().unwrap() as usize, obj["blob"]["sha256"].as_str().unwrap());
    assert_eq!(opened.unwrap(), audio, "Bob plays Alice's voicemail; the mailbox only ever held ciphertext");

    // --- M§11.1: both members derive the same activity key; the seal is bound to the epoch
    let (ka, kb) = (activity_key(&ag, alice_dev.provider()).unwrap(), activity_key(&bg, bob_dev.provider()).unwrap());
    assert_eq!(ka, kb);
    let activity = b"eyJ.typing.sig";
    let sealed = mls_wire::seal(&ka, &[4u8; 12], activity, SealUse::Activity { group: &gid, epoch: ag.epoch().as_u64() });
    assert_eq!(mls_wire::open(&kb, &sealed, SealUse::Activity { group: &gid, epoch: bg.epoch().as_u64() }).unwrap(), activity);
    assert!(mls_wire::open(&kb, &sealed, SealUse::Activity { group: &gid, epoch: bg.epoch().as_u64() + 1 }).is_err());

    // --- M§12.2: Bob archives the voicemail record under his archive key, bound to (group, seq)
    let record = serde_json::to_vec(&json!({"object": "archive-record", "payload": obj})).unwrap();
    let archived = mls_wire::seal(&[5u8; 32], &[6u8; 12], &record, SealUse::Archive { group: &gid, seq: 4 });
    assert_eq!(mls_wire::open(&[5u8; 32], &archived, SealUse::Archive { group: &gid, seq: 4 }).unwrap(), record);

    // --- M§6.5 rule 2 on real commits: Bob's update wins epoch 1; Alice's concurrent commit is refused
    let bob_update = bytes(bg.self_update(bob_dev.provider(), &bob_dev.signer(), LeafNodeParameters::default()).unwrap().commit());
    let alice_update = bytes(ag.self_update(alice_dev.provider(), &alice_dev.signer(), LeafNodeParameters::default()).unwrap().commit());
    let (_, be, _) = message_header(&bob_update).unwrap();
    let observed = hub_view.observe_commit(&bob_update, &ctx).unwrap();
    assert_eq!(observed["valid"], true);
    let emitted = hub.step(&json!({"deposit": {"id": ulid(12), "device": bob_dev.did(), "identity": bob, "class": "handshake",
        "epoch": be, "digest": digest(&bob_update), "commit": observed}}));
    assert!(emitted[0].get("accepted").is_some(), "{emitted:?}");
    let (_, ae, _) = message_header(&alice_update).unwrap();
    let emitted = hub.step(&json!({"deposit": {"id": ulid(13), "device": alice_dev.did(), "identity": alice, "class": "handshake",
        "epoch": ae, "digest": digest(&alice_update), "commit": {"adds": [], "removes": []}}}));
    assert_eq!(emitted[0]["error"]["reason"], "mailbox.commit-conflict");
    assert_eq!(hub_view.observe_commit(&alice_update, &ctx).unwrap()["valid"], false, "the public view also refuses the stale commit");
}

#[test]
fn extension_bytes_match_openmls() {
    // The vector-pinned encoder and OpenMLS/tls_codec agree byte for byte, and both refuse a non-minimal length.
    for n in [5usize, 63, 64, 100, 16_383, 16_384, 20_000] {
        let data = vec![0xABu8; n];
        let ours = mls_wire::encode_extension(EXT_DSIP_DELEGATION, &data);
        let theirs = Extension::Unknown(EXT_DSIP_DELEGATION, UnknownExtension(data.clone())).tls_serialize_detached().unwrap();
        assert_eq!(ours, theirs, "length {n}");
        let back = Extension::tls_deserialize(&mut &ours[..]).unwrap();
        assert_eq!(back, Extension::Unknown(EXT_DSIP_DELEGATION, UnknownExtension(data)));
    }
    let non_minimal = [0xF0, 0xD1, 0x40, 0x03, b'a', b'b', b'c'];
    assert_eq!(mls_wire::decode_extension(&non_minimal), Err("mls-length-non-minimal"));
    assert!(Extension::tls_deserialize(&mut &non_minimal[..]).is_err());
}
