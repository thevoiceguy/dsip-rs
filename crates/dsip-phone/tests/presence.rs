//! Presence between phones on the testkit's in-process relays: a grant issued in answer to an introduction that came
//! another way (as at a mailbox) and held by its grantee, a watch it admits, the relay's assertion and then a record
//! the watched device signed, a watch no grant admits, and a watch through the relay a `did:key`'s hint names.
//!
//! Spec: P§3 (records to the authority, verified by the subscriber), P§4, P§6 (private unless granted; a grant in
//! `claims` admits), §9.3, §19.4, M§14.1, §8.1 (a hint says where to try).

use std::collections::BTreeMap;
use std::time::Duration;

use dsip_phone::{GrantRequest, Phone, Presence};
use dsip_testkit::Network;

async fn phone(net: &Network, name: &str) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).build().await.expect("phone")
}

/// Wait until `phone` shows a presence for `target` that `want` accepts.
async fn until(phone: &Phone, target: &str, what: &str, want: impl Fn(&Presence) -> bool) -> Presence {
    let mut rx = phone.presence();
    let got = tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        loop {
            if let Some(p) = rx.borrow_and_update().get(target).filter(|p| want(p)) {
                return p.clone();
            }
            rx.changed().await.expect("the phone runs");
        }
    })
    .await;
    got.unwrap_or_else(|_| panic!("{what}: {:?}", phone.presence().borrow().clone()))
}

/// `grantor` answers an introduction from `grantee` with a grant that shares presence, and `grantee` holds it.
async fn grant(grantor: &Phone, grantee: &Phone) {
    let request = GrantRequest {
        introduction: dsip_core::ulid::Ulid::generate().to_string(),
        requester: grantee.identity().into(),
        scope: vec!["dsip.invite".into(), "dsip.message".into(), "dsip.subscribe".into()],
        valid_until: dsip_transport::now_s() + 86_400,
    };
    let frame = grantor.grant_request(request).await.unwrap().expect("a grant");
    assert!(grantee.hold_grant(&frame).await.unwrap(), "the grantee holds it");
}

#[tokio::test]
async fn a_granted_watcher_sees_the_relays_claim_then_the_record_the_device_signed() {
    let net = Network::new();
    let alice = phone(&net, "Alice").await;
    let bob = phone(&net, "Bob").await;
    grant(&bob, &alice).await;

    alice.watch(bob.identity()).await;
    // §9.3: bound, and no device of his has said more: his relay's claim
    let p = until(&alice, bob.identity(), "Bob's relay says he is there", |p| p.source == "assertion").await;
    assert_eq!(p.state, "available");

    bob.set_presence(Some("busy"));
    let p = until(&alice, bob.identity(), "Bob's busy record", |p| p.source == "record").await;
    assert_eq!((p.state.as_str(), p.token.as_str(), p.unreadable), ("busy", "busy", 0));

    alice.unwatch(bob.identity());
    tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        while alice.presence().borrow().contains_key(bob.identity()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("nothing shown once unwatched");
}

#[tokio::test]
async fn presence_is_private_unless_granted() {
    let net = Network::new();
    let alice = phone(&net, "Alice").await;
    let bob = phone(&net, "Bob").await;
    bob.set_presence(Some("away"));
    // P§6: no grant of Bob's to present; the relay refuses, and nothing is shown
    alice.watch(bob.identity()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(alice.presence().borrow().clone(), BTreeMap::new());
}

#[tokio::test]
async fn a_grant_is_held_only_by_its_grantee() {
    let net = Network::new();
    let (alice, bob, carol) = (phone(&net, "Alice").await, phone(&net, "Bob").await, phone(&net, "Carol").await);
    let request = GrantRequest {
        introduction: dsip_core::ulid::Ulid::generate().to_string(),
        requester: alice.identity().into(),
        scope: vec!["dsip.subscribe".into()],
        valid_until: dsip_transport::now_s() + 60,
    };
    let frame = bob.grant_request(request).await.unwrap().expect("a grant");
    assert!(!carol.hold_grant(&frame).await.unwrap(), "addressed to Alice");
    assert!(!alice.hold_grant("not.a.grant").await.unwrap());
    assert!(alice.hold_grant(&frame).await.unwrap());
}

#[tokio::test]
async fn a_did_key_bound_elsewhere_is_watched_at_the_relay_its_hint_names() {
    // §8.1: Bob has no document; his hint names his relay, which is not Alice's
    let (mine, theirs) = (Network::new(), Network::new());
    let node = dsip_testkit::hints_node().await;
    let hints = dsip_transport::hints::HintsClient::new(vec![node], None).unwrap();
    let bob_id = theirs.identity("Bob");
    let now = dsip_transport::now_s();
    let endpoints = dsip_transport::hints::endpoints(Some(theirs.url()), None);
    hints.publish(&dsip_transport::hints::reachability(&bob_id.meta.identity, &bob_id.device, &bob_id.delegation, &endpoints, now, now, 3600)).await;
    let bob = Phone::builder().identity(bob_id).relay(theirs.url()).dialer(theirs.dialer()).build().await.unwrap();
    let peers = Network::peers(&[&mine, &theirs]);
    let alice = Phone::builder()
        .identity(mine.identity("Alice"))
        .relay(mine.url())
        .dialer(mine.dialer())
        .hints(hints)
        .configure(move |c| c.peer_dialer = Some(peers))
        .build()
        .await
        .unwrap();
    grant(&bob, &alice).await;

    bob.set_presence(Some("dnd"));
    alice.watch(bob.identity()).await;
    let p = until(&alice, bob.identity(), "Bob's record, through his relay", |p| p.source == "record").await;
    assert_eq!(p.state, "dnd");
}
