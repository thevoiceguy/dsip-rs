//! A subscription refused by its authority: the `reject` naming our `subscribe` in `session` reaches the host and is
//! answered with nothing, while a `reject` for a session we never had is still refused as `session.unknown-session`.
//!
//! Spec: §9.3, §12.2.

use dsip_core::did::StaticResolver;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_endpoint::{Core, CoreConfig, CoreEvent, IdentityKeys};
use serde_json::json;

const NOW: i64 = 1_790_000_000;

fn keys(seed: u8, name: &str) -> IdentityKeys {
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), NOW - 60, NOW + 86_400, &["dsip.signaling"]);
    IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() }
}

fn core(seed: u8, name: &str) -> (Core, String) {
    let k = keys(seed, name);
    let identity = k.identity.clone();
    (Core::new(k, CoreConfig::default(), StaticResolver::default(), NOW), identity)
}

fn dsip() -> serde_json::Value {
    json!({"core": "1.0", "min_core": "1.0", "profiles": ["interactive-media/1.0"], "extensions": [], "critical": []})
}

/// The authority's §9.3 refusal of `session`, signed by `relay`.
fn refusal(relay: &mut Core, to: &str, session: &str) -> String {
    relay.sign_payload(json!({"dsip": dsip(), "type": "reject", "to": to, "session": session, "reason": "policy.blocked"}), NOW, 30).unwrap()
}

fn sends(events: &[CoreEvent]) -> Vec<String> {
    events.iter().filter_map(|e| match e { CoreEvent::Send { msg_type, .. } => Some(msg_type.clone()), _ => None }).collect()
}

#[test]
fn a_refused_subscription_reaches_the_host_and_is_not_answered() {
    let (mut alice, alice_id) = core(1, "Alice");
    let (mut relay, relay_id) = core(3, "Relay");
    let sub = alice
        .sign_payload(json!({"dsip": dsip(), "type": "subscribe", "to": relay_id, "target": "did:key:z6MkhzX9qTeXBWkucyMVric1E9JrqUD5LPAkD2BNavakAptf",
                             "events": ["presence"], "expires_in": 3600}), NOW, 30)
        .unwrap();
    let id = {
        let env = dsip_core::envelope::Envelope::from_frame(&sub).unwrap();
        serde_json::from_slice::<serde_json::Value>(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap()["id"].as_str().unwrap().to_string()
    };
    let events = alice.inbound(&refusal(&mut relay, &alice_id, &id), NOW).unwrap();
    assert!(events.iter().any(|e| matches!(e, CoreEvent::Received { message, .. } if message.msg_type == "reject")), "{events:?}");
    assert!(sends(&events).is_empty(), "§9.3: nothing answers a refused subscription: {events:?}");
}

#[test]
fn a_reject_for_no_session_of_ours_is_still_unknown_session() {
    let (mut alice, alice_id) = core(1, "Alice");
    let (mut relay, _) = core(3, "Relay");
    let events = alice.inbound(&refusal(&mut relay, &alice_id, "01K742SGZ8J9J7XY75S4YY8Y78"), NOW).unwrap();
    assert_eq!(sends(&events), vec!["error".to_string()], "§12.2: {events:?}");
}
