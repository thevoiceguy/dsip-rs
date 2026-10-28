//! The testkit's own checks, each a small multi-party scenario run in-process: a call answered and hung up, a forked
//! call answered on one device while the other stops ringing, a call to an identity never seen, and a device that
//! binds again on a second connection.
//!
//! Spec: §12.4 (invite, answer, bye), §12.7 (forking to every bound device; the losing legs are cancelled), §13.2
//! (a new `hello` from a bound device replaces its connection, `transport.replaced`), §13.3 (an identity never seen is refused `transport.unknown-recipient`).

use dsip_session::SessionState;
use dsip_testkit::Network;
use dsip_transport::agent::AgentEvent;
use dsip_transport::{CallCommand, CallEvent};

fn ringing(e: &AgentEvent) -> Option<String> {
    match e {
        AgentEvent::Call(CallEvent::Ringing { session }) => Some(session.clone()),
        _ => None,
    }
}

#[tokio::test]
async fn a_call_is_answered_and_hung_up() {
    let net = Network::new();
    let mut alice = net.device("Alice").await;
    let mut bob = net.device("Bob").await;

    let sid = alice.call(&bob.identity()).await;
    assert_eq!(bob.expect("ringing", ringing).await, sid);
    bob.command(CallCommand::Accept { session: sid.clone() }).await;
    alice.until(&sid, SessionState::Active).await;

    alice.command(CallCommand::Hangup { session: sid.clone() }).await;
    bob.until(&sid, SessionState::Ended).await;
}

#[tokio::test]
async fn a_forked_call_stops_ringing_on_the_device_that_did_not_answer() {
    let net = Network::new();
    let mut alice = net.device("Alice").await;
    let bob_phone = net.identity("Bob");
    let bob_laptop = net.device_of(&bob_phone, "Bob");
    let mut phone = net.connect(bob_phone, net.config()).await;
    let mut laptop = net.connect(bob_laptop, net.config()).await;

    let sid = alice.call(&phone.identity()).await;
    assert_eq!(phone.expect("ringing on the phone", ringing).await, sid);
    assert_eq!(laptop.expect("ringing on the laptop", ringing).await, sid);
    phone.command(CallCommand::Accept { session: sid.clone() }).await;
    alice.until(&sid, SessionState::Active).await;
    // §12.7: the relay cancels the leg that lost; the laptop's call ends without being answered
    laptop.until(&sid, SessionState::Ended).await;
}

#[tokio::test]
async fn a_call_to_an_identity_never_seen_is_refused() {
    let net = Network::new();
    let mut alice = net.device("Alice").await;
    let nobody = net.identity("Nobody");

    alice.call(&nobody.meta.identity).await;
    let reason = alice
        .expect("the refusal", |e| match e {
            AgentEvent::Received { payload, .. } if payload["type"] == "error" => payload["reason"].as_str().map(String::from),
            _ => None,
        })
        .await;
    assert_eq!(reason, "transport.unknown-recipient");
}

#[tokio::test]
async fn a_device_bound_again_replaces_its_connection() {
    let net = Network::new();
    let alice = net.identity("Alice");
    let dir = alice.dir.clone();
    let mut first = net.connect(alice, net.config()).await;
    let mut second = net.connect(dsip_transport::identity::Identity::load(&dir).unwrap(), net.config()).await;

    // §13.2: the relay tells the first connection it was replaced, and the agent does not reconnect
    let replaced = tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        loop {
            if let Err(e) = first.agent.next().await {
                return e;
            }
        }
    })
    .await
    .expect("the first connection ends");
    assert!(matches!(replaced, dsip_transport::Error::Replaced { .. }), "{replaced}");

    // the second still takes calls
    let mut bob = net.device("Bob").await;
    let sid = bob.call(&second.identity()).await;
    assert_eq!(second.expect("ringing", ringing).await, sid);
}
