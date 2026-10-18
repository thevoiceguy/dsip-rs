//! No input reaches a panic: arbitrary text, and real frames with bytes flipped, cut or spliced, go into
//! `Core::inbound` and come back as a refusal or an event, never a panic.
//!
//! Spec: §10.2–§10.3 (a frame is verified before anything acts on it), §13.2 (the receive path of `ws/1.0`).

use dsip_core::did::StaticResolver;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_endpoint::{Core, CoreConfig, CoreEvent, IdentityKeys};
use dsip_session::LocalEvent;
use proptest::prelude::*;

const NOW: i64 = 1_790_000_000;

fn keys(seed: u8, name: &str) -> IdentityKeys {
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(
        &controller.did(),
        &device.did(),
        NOW - 60,
        NOW + 86_400,
        &["dsip.signaling", "dsip.media.interactive"],
    );
    IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() }
}

fn core(seed: u8, name: &str) -> Core {
    Core::new(keys(seed, name), CoreConfig::default(), StaticResolver::default(), NOW)
}

/// A real invite from Alice to Bob, as Bob would receive it.
fn invite_frame() -> (String, String) {
    let mut alice = core(1, "Alice");
    let bob = keys(2, "Bob").identity;
    let sid = alice.new_id(NOW);
    let out = alice.local(LocalEvent::PlaceCall { session: sid, to: bob.clone() }, NOW).unwrap();
    let frame = out
        .into_iter()
        .find_map(|e| match e {
            CoreEvent::Send { frame, msg_type, .. } if msg_type == "invite" => Some(frame),
            _ => None,
        })
        .expect("alice sends an invite");
    (frame, bob)
}

#[test]
fn the_unmutated_invite_is_received() {
    let (frame, _) = invite_frame();
    let mut bob = core(2, "Bob");
    let out = bob.inbound(&frame, NOW).unwrap();
    assert!(out.iter().any(|e| matches!(e, CoreEvent::Received { .. })), "{out:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_text_never_panics(text in ".{0,600}") {
        let mut bob = core(2, "Bob");
        let _ = bob.inbound(&text, NOW);
    }

    #[test]
    fn mutated_invites_never_panic(flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
                                   cut in any::<prop::sample::Index>(), splice in "[{}\\[\\]\":,.0-9a-zA-Z_-]{0,24}") {
        let (frame, _) = invite_frame();
        let mut bytes = frame.into_bytes();
        for (i, b) in &flips {
            let at = i.index(bytes.len());
            bytes[at] = *b;
        }
        let mut bob = core(2, "Bob");
        let _ = bob.inbound(&String::from_utf8_lossy(&bytes), NOW);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let at = cut.index(text.len().max(1));
        if text.is_char_boundary(at) {
            let _ = bob.inbound(&text[..at], NOW);
            let _ = bob.inbound(&format!("{}{}{}", &text[..at], splice, &text[at..]), NOW);
        }
    }

    #[test]
    fn re_signed_payloads_with_odd_fields_never_panic(field in "(from|id|issued_at|expires_at|type|session|to|media|transports|dsip)",
                                                       value in prop_oneof![Just(serde_json::json!(null)), Just(serde_json::json!(1.5)),
                                                           Just(serde_json::json!("x")), Just(serde_json::json!([])), Just(serde_json::json!({})),
                                                           Just(serde_json::json!(-1)), Just(serde_json::json!(i64::MAX))]) {
        // A payload validly signed by Alice's device, with one field replaced: what passes the signature must still
        // be refused cleanly by the shape and semantic checks.
        let (frame, _) = invite_frame();
        let env = dsip_core::envelope::Envelope::from_frame(&frame).unwrap();
        let raw = dsip_core::b64::decode(&env.payload).unwrap();
        let mut p: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        p[field.as_str()] = value;
        let k = keys(1, "Alice");
        let forged = dsip_core::envelope::sign_bytes(&serde_json::to_vec(&p).unwrap(), &k.device, &k.device.kid(), vec![k.delegation.clone()]);
        let mut bob = core(2, "Bob");
        let _ = bob.inbound(&forged.frame(), NOW);
    }
}
