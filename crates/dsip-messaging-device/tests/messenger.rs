//! The messaging device as a library: opened over any store with either client's `Config`, its state taken back, and
//! the Recording Profile's rule for a recorder sibling.
//!
//! Spec: M§5.4 (state kept with the MLS state, spec-gap 44), M§7.1 (the personal group), M§12.3 (a new device joins
//! the personal group first), C§5 (a recorder device joins conversations only).

use serde_json::{json, Value};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
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
