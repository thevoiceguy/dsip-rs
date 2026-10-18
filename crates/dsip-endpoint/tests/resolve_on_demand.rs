//! A frame carrying a delegation from a `did:web` identity whose document the receiver lacks is held, the host is
//! asked for the document, and the frame is verified once the answer comes back: the caller is the identity. Without
//! an answer, or with a failed one, it is verified as before, and counts as from the bare device.
//!
//! Spec: §8.1 (the DID document is authoritative, obtained by the method), §10.2 (`kid` resolves through it).

use dsip_core::did::{DidDocument, ResolveError, StaticResolver};
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_endpoint::core::{RESOLVE_MAX_PENDING, RESOLVE_RETRY_S, RESOLVE_WAIT_S};
use dsip_endpoint::{Core, CoreConfig, CoreEvent, IdentityKeys};
use dsip_session::LocalEvent;

const NOW: i64 = 1_790_000_000;

fn web_keys(n: u8) -> (IdentityKeys, DidDocument) {
    let did = format!("did:web:alice{n}.example");
    let controller = KeyPair::from_seed([n; 32]);
    let device = KeyPair::from_seed([n.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(&did, &device.did(), NOW - 60, NOW + 86_400, &["dsip.signaling", "dsip.media.interactive"]);
    let delegation = sign(&payload, &controller, &format!("{did}#key-1"));
    let doc = DidDocument::minimal_web(&did, &controller.public(), None);
    (IdentityKeys { identity: did, delegation, device, display_name: "Alice".into() }, doc)
}

fn bob(on_demand: bool) -> Core {
    let controller = KeyPair::from_seed([200; 32]);
    let device = KeyPair::from_seed([201; 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), NOW - 60, NOW + 86_400, &["dsip.signaling", "dsip.media.interactive"]);
    let keys = IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: "Bob".into() };
    Core::new(keys, CoreConfig { resolve_on_demand: on_demand, ..Default::default() }, StaticResolver::default(), NOW)
}

/// An invite from did:web identity `n` to Bob.
fn invite(n: u8, bob: &Core) -> (String, DidDocument) {
    let (keys, doc) = web_keys(n);
    let mut resolver = StaticResolver::default();
    resolver.insert(doc.clone());
    let mut alice = Core::new(keys, CoreConfig::default(), resolver, NOW);
    let sid = alice.new_id(NOW);
    let out = alice.local(LocalEvent::PlaceCall { session: sid, to: bob.keys().identity.clone() }, NOW).unwrap();
    let frame = out.into_iter().find_map(|e| match e {
        CoreEvent::Send { frame, msg_type, .. } if msg_type == "invite" => Some(frame),
        _ => None,
    });
    (frame.expect("alice sends an invite"), doc)
}

/// The identities `out` received frames from.
fn from(out: &[CoreEvent]) -> Vec<String> {
    out.iter().filter_map(|e| if let CoreEvent::Received { identity, .. } = e { Some(identity.clone()) } else { None }).collect()
}

/// Received from the bare device: the delegation was not verified.
fn from_device(out: &[CoreEvent]) -> bool {
    matches!(from(out).as_slice(), [d] if d.starts_with("did:key:"))
}

fn asks(out: &[CoreEvent]) -> Vec<String> {
    out.iter().filter_map(|e| if let CoreEvent::Resolve { did } = e { Some(did.clone()) } else { None }).collect()
}

#[test]
fn off_by_default_the_frame_is_verified_at_once() {
    let mut b = bob(false);
    let (frame, _) = invite(1, &b);
    let out = b.inbound(&frame, NOW).unwrap();
    assert!(from_device(&out), "{out:?}");
    assert!(asks(&out).is_empty());
}

#[test]
fn the_frame_waits_for_the_document_then_is_received() {
    let mut b = bob(true);
    let (frame, doc) = invite(1, &b);
    let out = b.inbound(&frame, NOW).unwrap();
    assert_eq!(asks(&out), vec![doc.id.clone()], "{out:?}");
    assert!(from(&out).is_empty(), "held: {out:?}");
    let out = b.resolved(&doc.id.clone(), Ok(doc.clone()), NOW + 1).unwrap();
    assert_eq!(from(&out), vec![doc.id], "{out:?}");
}

#[test]
fn a_failed_fetch_verifies_without_and_is_not_asked_again_at_once() {
    let mut b = bob(true);
    let (frame, doc) = invite(1, &b);
    b.inbound(&frame, NOW).unwrap();
    let out = b.resolved(&doc.id, Err(ResolveError::Fetch { did: doc.id.clone(), detail: "timeout".into() }), NOW + 1).unwrap();
    assert!(from_device(&out), "{out:?}");
    let (again, _) = invite(1, &b);
    let out = b.inbound(&again, NOW + 2).unwrap();
    assert!(from_device(&out) && asks(&out).is_empty(), "{out:?}");
    let (later, _) = invite(1, &b);
    let out = b.inbound(&later, NOW + 2 + RESOLVE_RETRY_S).unwrap();
    assert_eq!(asks(&out), vec![doc.id], "after the retry interval the core asks again: {out:?}");
}

#[test]
fn a_document_for_another_did_is_a_failure() {
    let mut b = bob(true);
    let (frame, doc) = invite(1, &b);
    let (_, other) = web_keys(2);
    b.inbound(&frame, NOW).unwrap();
    let out = b.resolved(&doc.id, Ok(other), NOW + 1).unwrap();
    assert!(from_device(&out), "{out:?}");
}

#[test]
fn without_an_answer_the_frame_is_verified_after_the_wait() {
    let mut b = bob(true);
    let (frame, _) = invite(1, &b);
    b.inbound(&frame, NOW).unwrap();
    assert_eq!(b.next_deadline(), Some(NOW + RESOLVE_WAIT_S));
    assert!(b.tick(NOW + RESOLVE_WAIT_S - 1).unwrap().is_empty());
    let out = b.tick(NOW + RESOLVE_WAIT_S).unwrap();
    assert!(from_device(&out), "{out:?}");
}

#[test]
fn two_frames_for_one_did_ask_once() {
    let mut b = bob(true);
    let (first, doc) = invite(1, &b);
    let (second, _) = invite(1, &b);
    assert_eq!(asks(&b.inbound(&first, NOW).unwrap()).len(), 1);
    assert!(asks(&b.inbound(&second, NOW).unwrap()).is_empty());
    let out = b.resolved(&doc.id.clone(), Ok(doc.clone()), NOW + 1).unwrap();
    assert_eq!(from(&out), vec![doc.id.clone(), doc.id], "{out:?}");
}

#[test]
fn past_the_bound_frames_are_verified_without_asking() {
    let mut b = bob(true);
    for n in 1..=RESOLVE_MAX_PENDING as u8 {
        let (frame, _) = invite(n, &b);
        assert_eq!(asks(&b.inbound(&frame, NOW).unwrap()).len(), 1);
    }
    let (frame, _) = invite(RESOLVE_MAX_PENDING as u8 + 1, &b);
    let out = b.inbound(&frame, NOW).unwrap();
    assert!(from_device(&out) && asks(&out).is_empty(), "{out:?}");
}
