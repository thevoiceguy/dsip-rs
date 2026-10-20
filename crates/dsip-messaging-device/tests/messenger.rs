//! The messaging device as a library: opened over any store with either client's `Config`, its state taken back, and
//! the Recording Profile's rule for a recorder sibling.
//!
//! Spec: M§5.4 (state kept with the MLS state, spec-gap 44), M§7.1 (the personal group), M§12.3 (a new device joins
//! the personal group first), C§5 (a recorder device joins conversations only).

use serde_json::{json, Value};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_messaging::wire;
use dsip_messaging_device::messenger::Messenger;
use dsip_messaging_device::{Config, MemoryStore};
use dsip_mls::Device;

const NOW: i64 = 1_790_000_000;
const PLAIN: &[&str] = &["dsip.signaling", "dsip.messaging"];
const RECORDER: &[&str] = &["dsip.signaling", "dsip.messaging", "dsip.record"];

fn delegation(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> dsip_core::envelope::Envelope {
    sign(&delegation_payload(&identity.did(), &device.did(), NOW - 3600, NOW + 7 * 86400, caps), identity, &identity.kid())
}

fn identity_json(identity: &KeyPair, device: &KeyPair) -> String {
    json!({"identity": identity.did(), "display_name": "Alice", "device_seed_hex": hex(&device.seed()),
           "controller_seed_hex": hex(&identity.seed()), "delegation": delegation(identity, device, PLAIN).frame()}).to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A `key-packages` answer holding one KeyPackage of `device`, a device of `identity` with `caps`.
fn key_packages(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> String {
    let e = delegation(identity, device, caps);
    let d = Device::new(device.clone(), format!("{}.{}.{}", e.protected, e.payload, e.signature));
    json!({"type": "key-packages", "key_packages": [dsip_core::b64::encode(&d.key_package().unwrap())]}).to_string()
}

#[test]
fn opened_over_a_store_with_either_config() {
    let (alice, phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let id = identity_json(&alice, &phone);
    let mut m = Messenger::open(&id, "did:key:mbx", "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null, Config::DSIP_MSG,
                                NOW as f64).unwrap();
    m.create_personal(NOW as f64).unwrap();
    let personal = m.personal().unwrap();

    // what it keeps comes back: the personal group, and the MLS group under it from the same store
    let state = m.state();
    assert_eq!(state["personal"], json!(personal));
    assert_eq!(state["convs"][&personal]["kind"], "personal");

    // the browser's record is that state with its MLS storage, and opens as the same device
    let mut browser = Messenger::new(&id, "did:key:mbx", "wss://mbx.example/dsip", None, NOW as f64).unwrap();
    browser.create_personal(NOW as f64).unwrap();
    let record = browser.save();
    let saved: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(saved["state"], browser.state());
    let reopened = Messenger::new(&id, "did:key:mbx", "wss://mbx.example/dsip", Some(record), NOW as f64).unwrap();
    assert_eq!(reopened.personal(), browser.personal());
    assert_eq!(reopened.state()["convs"], browser.state()["convs"], "the group reloads from the saved MLS storage");
}

#[test]
fn a_recorder_sibling_never_joins_the_personal_group() {
    let (alice, phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let mut m = Messenger::new(&identity_json(&alice, &phone), "did:key:mbx", "wss://mbx.example/dsip", None, NOW as f64).unwrap();
    m.create_personal(NOW as f64).unwrap();
    let personal = m.personal().unwrap();

    let recorder = KeyPair::from_fixture_name("alice-recorder");
    let err = m.add_device(&personal, &recorder.did(), &key_packages(&alice, &recorder, RECORDER), NOW as f64).unwrap_err();
    assert!(err.0.contains("is a recorder device"), "{err}");

    // a plain sibling is proposed (M§12.3)
    let laptop = KeyPair::from_fixture_name("alice-laptop");
    assert!(m.add_device(&personal, &laptop.did(), &key_packages(&alice, &laptop, PLAIN), NOW as f64).is_ok());
}

/// A mailbox that hosts every group and accepts everything: each deposit gets the next seq (M§5.3).
struct Hub {
    key: KeyPair,
    seq: i64,
}

impl Hub {
    fn new() -> Hub {
        Hub { key: KeyPair::from_fixture_name("mailbox"), seq: 0 }
    }

    fn did(&self) -> String {
        self.key.did()
    }

    /// Send what the device returned, answer it, and feed the answers back until nothing more is sent: the events.
    fn drive(&mut self, m: &mut Messenger, out: &str) -> Vec<Value> {
        let mut events = vec![];
        let mut queue: Vec<Value> = serde_json::from_str(out).unwrap();
        while let Some(e) = (!queue.is_empty()).then(|| queue.remove(0)) {
            let frame = match (&e, e.get("send")) {
                (Value::String(f), _) => f.clone(),
                (_, Some(Value::String(f))) if !f.is_empty() => f.clone(),
                _ => {
                    events.push(e);
                    continue;
                }
            };
            let env = Envelope::from_frame(&frame).unwrap();
            let p = wire::payload_of(&env).unwrap();
            let extra = if p["type"] == "deposit" && p["class"] != "archive" {
                self.seq += 1;
                json!({"seq": self.seq})
            } else {
                json!({})
            };
            let reply = wire::accepted(&self.key, p["from"].as_str().unwrap(), NOW, p["id"].as_str().unwrap(), extra);
            queue.extend(serde_json::from_str::<Vec<Value>>(&m.inbound(&reply.frame(), NOW as f64)).unwrap());
        }
        events
    }
}

fn ui<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["ui"] == kind).collect()
}

#[test]
fn rekey_remove_device_and_rotate_the_archive_key() {
    let (alice, phone, laptop) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
                                  KeyPair::from_fixture_name("alice-laptop"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                Config::DSIP_MSG, NOW as f64).unwrap();
    let out = m.create_personal(NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    assert_eq!(ui(&ev, "archive_key_created").len(), 1, "{ev:?}");
    let personal = m.personal().unwrap();

    // a sibling joins the personal group (M§12.3)
    let out = json!([{"send": m.add_device(&personal, &laptop.did(), &key_packages(&alice, &laptop, PLAIN), NOW as f64).unwrap()}]);
    let ev = hub.drive(&mut m, &out.to_string());
    assert_eq!(ui(&ev, "committed")[0]["device"], json!(laptop.did()));
    let epoch = ui(&ev, "committed")[0]["epoch"].as_u64().unwrap();

    // its leaf still verifies: only its own identity may remove it as lapsed (M§7.3)
    assert!(m.remove_lapsed_leaf(&personal, &laptop.did(), NOW as f64).unwrap_err().0.contains("still verifies"));

    // a rekey moves the epoch
    let out = json!([{"send": m.rekey(&personal, NOW as f64).unwrap()}]);
    let ev = hub.drive(&mut m, &out.to_string());
    assert_eq!(ui(&ev, "committed")[0]["epoch"], json!(epoch + 1));

    // removed by credential, then a new archive key, sent after the merge: in the epoch the laptop is not in (M§12.4)
    let out = m.remove_device(&laptop.did(), NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let committed = ev.iter().position(|e| e["ui"] == "committed").expect("committed");
    let created = ev.iter().position(|e| e["ui"] == "archive_key_created").expect("a new archive key");
    assert!(committed < created, "{ev:?}");
    assert_eq!(m.state()["archive_keys"].as_object().unwrap().len(), 2);
    assert!(m.remove_device(&laptop.did(), NOW as f64).unwrap_err().0.contains("no group holds"));
}
