//! A call through another relay (§8.1): Alice is bound to her relay, Bob to his; Alice places the call through
//! Bob's, binding there on a connection of its own, and the session's envelopes go over it both ways. When the call
//! has ended, the connection closes. A relay that does not bind her leaves the call to her own relay.
//!
//! Spec: §8.1 (the hints tier says where to try), §13.2 (a device bound at a relay), §12.4.

use std::time::Duration;

use dsip_endpoint::CallCommand;
use dsip_session::SessionState;
use dsip_testkit::Network;
use dsip_transport::agent::AgentEvent;
use dsip_transport::{CallEvent, Invite};

#[tokio::test]
async fn a_call_through_the_callees_relay_and_back() {
    let (mine, theirs) = (Network::new(), Network::new());
    assert_ne!(mine.url(), theirs.url());
    let mut cfg = mine.config();
    cfg.peer_dialer = Some(Network::peers(&[&mine, &theirs]));
    let mut alice = mine.connect(mine.identity("Alice"), cfg).await;
    let mut bob = theirs.device("Bob").await;

    let sid = alice.place_via(&bob.identity(), Invite::default(), theirs.url()).await.unwrap();
    assert_eq!(alice.route_of(&sid), Some(theirs.url()));
    assert_eq!(alice.peer_relays(), vec![theirs.url().to_string()]);
    bob.expect("ringing at Bob", |e| matches!(e, AgentEvent::Call(CallEvent::Ringing { .. })).then_some(())).await;
    bob.command(CallCommand::Accept { session: sid.clone() }).await;
    alice.until(&sid, SessionState::Active).await;
    bob.until(&sid, SessionState::Active).await;

    alice.command(CallCommand::Hangup { session: sid.clone() }).await;
    bob.until(&sid, SessionState::Ended).await;
    alice.until(&sid, SessionState::Ended).await;
    // the next tick forgets the route and closes the connection no call uses
    alice.pump(Duration::from_millis(1500)).await;
    assert!(alice.peer_relays().is_empty(), "{:?}", alice.peer_relays());
    assert_eq!(alice.route_of(&sid), None);
}

#[tokio::test]
async fn a_relay_that_does_not_bind_leaves_the_call_to_our_own() {
    let net = Network::new();
    let mut alice = net.device("Alice").await;
    let mut bob = net.device("Bob").await;
    // no dialer has it, and wss to an .invalid name fails
    let sid = alice.place_via(&bob.identity(), Invite::default(), "wss://nowhere.invalid/dsip").await.unwrap();
    assert_eq!(alice.route_of(&sid), None);
    assert!(alice.peer_relays().is_empty());
    bob.expect("ringing at Bob, through Alice's relay", |e| matches!(e, AgentEvent::Call(CallEvent::Ringing { .. })).then_some(())).await;
}
