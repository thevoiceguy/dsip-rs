//! Sealed presence through the core (P§12): the keys a grant carries are sealed to the grantee and opened by it,
//! records are sealed at the current epoch and opened with the keys held, an ended grant rotates and re-grants with the
//! revocations its chain needs, a sibling's higher epoch is adopted, and the key state survives a restart.
//!
//! Spec: P§7, P§12.1–P§12.5.

use std::collections::BTreeSet;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_endpoint::{ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys, PresenceSealing};
use dsip_session::{Emission, KeysAction, LocalEvent};
use serde_json::{json, Value};

const NOW: i64 = 1_790_000_000;
const RELAY: &str = "did:key:z6MkhzX9qTeXBWkucyMVric1E9JrqUD5LPAkD2BNavakAptf";

/// A device `device_seed` of the identity `seed`, sealing `main` when `sealing`.
fn core(seed: u8, device_seed: u8, name: &str, sealing: bool) -> Core {
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([device_seed; 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), NOW - 60, NOW + 86_400, &["dsip.signaling"]);
    let keys = IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() };
    let cfg = CoreConfig {
        unseal_keys: vec![(controller.did(), dsip_core::hpke::x25519_from_ed25519_seed(&controller.seed()))],
        presence: sealing.then(|| PresenceSealing { sealed: BTreeSet::from(["main".to_string()]), t_rotate: None }),
        ..Default::default()
    };
    Core::new(keys, cfg, StaticResolver::default(), NOW)
}

fn id(c: &Core) -> String {
    c.keys().identity.clone()
}

fn payload(frame: &str) -> Value {
    let env = Envelope::from_frame(frame).unwrap();
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap()
}

fn frames(events: &[CoreEvent], ty: &str) -> Vec<String> {
    events.iter().filter_map(|e| match e { CoreEvent::Send { frame, msg_type, .. } if msg_type == ty => Some(frame.clone()), _ => None }).collect()
}

fn sent_types(events: &[CoreEvent]) -> Vec<String> {
    events.iter().filter_map(|e| match e { CoreEvent::Send { msg_type, .. } => Some(msg_type.clone()), _ => None }).collect()
}

/// `grantee` introduces itself to `grantor`, which grants it `dsip.subscribe` until `NOW + 3600` as `grant`. Returns
/// the grant frame, delivered.
fn grant(grantor: &mut Core, grantee: &mut Core, intro: &str, grant: &str, now: i64) -> String {
    let ev = grantee.local(LocalEvent::Introduce { id: intro.into(), to: id(grantor), purpose: None, contact_token: None }, now).unwrap();
    grantor.inbound(&frames(&ev, "introduction")[0], now).unwrap();
    let ev = grantor
        .local(
            LocalEvent::Grant { introduction: intro.into(), id: grant.into(), scope: vec!["dsip.subscribe".into()], valid_until: NOW + 3600, presence_audience: None },
            now,
        )
        .unwrap();
    let frame = frames(&ev, "grant").pop().expect("a grant");
    grantee.inbound(&frame, now).unwrap();
    frame
}

/// A record of `c`'s device for no audience, signed (and sealed when `c` seals `main`).
fn record(c: &mut Core, state: &str, seq: i64, now: i64) -> String {
    let p = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["presence/0.1"], "extensions": [], "critical": []},
                   "type": "presence", "to": RELAY, "subject": id(c), "device": c.keys().device.did(), "state": state, "seq": seq});
    c.sign_presence(p, now, 300).unwrap()
}

/// What `watcher` reads of `frame`: the state, or the P§12.4 code.
fn read(watcher: &Core, frame: &str, now: i64) -> Result<String, &'static str> {
    let (p, _) = watcher.verify_record(frame, now).expect("the record verifies");
    let fields = dsip_core::presence_seal::RecordFields::of(&p).expect("sealed fields");
    let subject = p["subject"].as_str().unwrap().to_string();
    dsip_core::presence_seal::open_record(&fields, p["sealed_state"].as_str().unwrap(), |kid| watcher.presence_key(&subject, kid)).map_err(|e| e.code())
}

/// A ULID of `NOW` ending in `tail` (§10.3: its time is the message's `issued_at`).
fn ulid(tail: &str) -> String {
    let base = dsip_core::ulid::Ulid::from_parts(NOW as u64 * 1000, [0; 10]).to_string();
    format!("{}{tail}", &base[..26 - tail.len()])
}

#[test]
fn a_grant_carries_sealed_keys_the_grantee_opens_and_records_are_sealed() {
    let (mut alice, mut bob) = (core(1, 101, "Alice", true), core(2, 102, "Bob", false));
    let frame = grant(&mut alice, &mut bob, &ulid("NTR01"), &ulid("GRNT01"), NOW);
    let g = payload(&frame);
    assert_eq!(g["presence_keys"]["alg"], "hpke-base-x25519-sha256-aes128gcm", "P§12.3: {g}");
    assert!(bob.presence_key(&id(&alice), "main.0").is_some(), "P§12.4: the grantee holds main.0");
    assert_eq!(bob.presence_key(&id(&alice), "main.0"), alice.presence_key(&id(&alice), "main.0"));

    let rec = record(&mut alice, "busy", 1, NOW);
    let p = payload(&rec);
    assert!(p.get("state").is_none() && p["kid"] == "main.0", "P§12.2: {p}");
    assert_eq!(p["dsip"]["profiles"], json!(["presence/0.2"]));
    assert_eq!(read(&bob, &rec, NOW), Ok("busy".into()));
    let carol = core(3, 103, "Carol", false);
    assert_eq!(read(&carol, &rec, NOW), Err("presence-key-unknown"), "no grant, no key");
}

#[test]
fn revoking_rotates_re_grants_the_others_and_revokes_the_whole_chain() {
    let mut alice = core(1, 101, "Alice", true);
    let (mut bob, mut carol) = (core(2, 102, "Bob", false), core(3, 103, "Carol", false));
    alice.set_authority(Some(RELAY.into()));
    grant(&mut alice, &mut bob, &ulid("NTR01"), &ulid("GRNT01"), NOW);
    grant(&mut alice, &mut carol, &ulid("NTR02"), &ulid("GRNT02"), NOW);

    // Bob's share ends: its revocation, then main rotates at once and Carol's grant is followed by one with main.1
    let ev = alice.local(LocalEvent::Revoke { grant: ulid("GRNT01") }, NOW + 10).unwrap();
    assert_eq!(sent_types(&ev), vec!["grant-revocation", "grant"], "P§7 then P§12.5: {ev:?}");
    assert_eq!(payload(&frames(&ev, "grant-revocation")[0])["grant"], ulid("GRNT01").as_str());
    assert!(ev.iter().any(|e| matches!(e, CoreEvent::Emission(Emission::Keys { action: KeysAction::Rotated, scope, epoch: 1 }) if scope == "main")));
    let regrant = frames(&ev, "grant").pop().unwrap();
    let g3 = payload(&regrant)["id"].as_str().unwrap().to_string();
    assert_eq!(payload(&regrant)["session"], ulid("GRNT02").as_str(), "it follows Carol's grant");
    carol.inbound(&regrant, NOW + 10).unwrap();
    assert!(carol.presence_key(&id(&alice), "main.0").is_some() && carol.presence_key(&id(&alice), "main.1").is_some(), "two epochs held");

    let rec = record(&mut alice, "dnd", NOW + 20, NOW + 20);
    assert_eq!(payload(&rec)["kid"], "main.1");
    assert_eq!(read(&carol, &rec, NOW + 20), Ok("dnd".into()));
    assert_eq!(read(&bob, &rec, NOW + 20), Err("presence-key-unknown"), "Bob's grant ended: he cannot read main.1");

    // Carol's share ends: the newest grant and the one it followed are both revoked (spec-gap 159)
    let ev = alice.local(LocalEvent::Revoke { grant: g3.clone() }, NOW + 30).unwrap();
    let revoked: Vec<Value> = frames(&ev, "grant-revocation").iter().map(|f| payload(f)["grant"].clone()).collect();
    assert_eq!(revoked, vec![json!(g3), json!(ulid("GRNT02"))]);
    for f in frames(&ev, "grant-revocation") {
        assert_eq!(payload(&f)["grantee"], id(&carol).as_str());
    }
}

#[test]
fn without_an_authority_the_host_is_told_what_to_revoke() {
    let (mut alice, mut bob) = (core(1, 101, "Alice", true), core(2, 102, "Bob", false));
    grant(&mut alice, &mut bob, &ulid("NTR01"), &ulid("GRNT01"), NOW);
    let ev = alice.local(LocalEvent::Revoke { grant: ulid("GRNT01") }, NOW + 10).unwrap();
    assert!(sent_types(&ev).is_empty(), "{ev:?}");
    assert!(ev.iter().any(|e| matches!(e, CoreEvent::Emission(Emission::Revoke(ids)) if ids == &vec![ulid("GRNT01")])));
}

#[test]
fn a_sibling_adopts_a_higher_epoch_and_re_grants() {
    let mut phone = core(1, 101, "Alice", true);
    let mut laptop = core(1, 111, "Alice", true);
    let (mut bob, mut carol) = (core(2, 102, "Bob", false), core(3, 103, "Carol", false));
    grant(&mut phone, &mut bob, &ulid("NTR01"), &ulid("GRNT01"), NOW);
    grant(&mut laptop, &mut carol, &ulid("NTR02"), &ulid("GRNT02"), NOW);
    phone.local(LocalEvent::Revoke { grant: ulid("GRNT01") }, NOW + 10).unwrap();

    // the laptop sees the phone's record at main.1 through its own watch
    let rec = record(&mut phone, "away", NOW + 20, NOW + 20);
    let (p, _) = laptop.verify_record(&rec, NOW + 20).unwrap();
    let ev = laptop.own_record(&p, NOW + 20).unwrap();
    assert!(ev.iter().any(|e| matches!(e, CoreEvent::Emission(Emission::Keys { action: KeysAction::Seen, epoch: 1, .. }))), "{ev:?}");
    let regrant = frames(&ev, "grant").pop().expect("Carol's grant is followed");
    carol.inbound(&regrant, NOW + 20).unwrap();
    assert_eq!(read(&carol, &rec, NOW + 20), Ok("away".into()), "Carol reads the phone's main.1 through the laptop's grant");
    assert_eq!(payload(&record(&mut laptop, "away", NOW + 21, NOW + 21))["kid"], "main.1", "the laptop seals at main.1");

    // its own records change nothing
    let own = record(&mut laptop, "busy", NOW + 30, NOW + 30);
    let (p, _) = laptop.verify_record(&own, NOW + 30).unwrap();
    assert!(laptop.own_record(&p, NOW + 30).unwrap().iter().all(|e| !matches!(e, CoreEvent::Emission(Emission::Keys { .. }) | CoreEvent::Send { .. })));
}

#[test]
fn key_state_survives_a_restart() {
    let (mut alice, mut bob) = (core(1, 101, "Alice", true), core(2, 102, "Bob", false));
    grant(&mut alice, &mut bob, &ulid("NTR01"), &ulid("GRNT01"), NOW);
    alice.local(LocalEvent::Revoke { grant: ulid("GRNT01") }, NOW + 10).unwrap();

    let saved: ContactFile = serde_json::from_str(&serde_json::to_string(&alice.contacts()).unwrap()).unwrap();
    let mut again = core(1, 101, "Alice", true);
    again.load_contacts(&saved);
    assert_eq!(payload(&record(&mut again, "busy", NOW + 20, NOW + 20))["kid"], "main.1", "the epoch is kept");

    let saved: ContactFile = serde_json::from_str(&serde_json::to_string(&bob.contacts()).unwrap()).unwrap();
    let mut bob_again = core(2, 102, "Bob", false);
    bob_again.load_contacts(&saved);
    assert_eq!(bob_again.presence_key(&id(&alice), "main.0"), alice.presence_key(&id(&alice), "main.0"), "held keys are kept");
}
