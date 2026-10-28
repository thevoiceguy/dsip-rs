//! Phones on the testkit's in-process network: a call answered and hung up from either side, a call declined, a call
//! cancelled while it rings, a phone that answers by policy, a call to nobody, and two phones calling with native
//! audio, whose media starts on the signed answer.
//!
//! Spec: §12.4, §12.11 (cancel before the answer, bye after), §14.1, §14.3 (`answered_by`), §14.4 (screening).

use std::time::Duration;

use dsip_phone::{AnswerPolicy, CallState, Outcome, Phone};
use dsip_testkit::Network;

async fn phone(net: &Network, name: &str, answer: AnswerPolicy) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).answer(answer).build().await.expect("phone")
}

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(dsip_testkit::TIMEOUT, f).await.unwrap_or_else(|_| panic!("no {what} within {:?}", dsip_testkit::TIMEOUT))
}

#[tokio::test]
async fn a_call_is_answered_then_hung_up_by_the_caller() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let incoming = within("incoming call", bob.incoming()).await.unwrap();
    assert_eq!(incoming.from, alice.identity());
    assert_eq!(incoming.display_name.as_deref(), Some("Alice"));
    let mut theirs = incoming.accept();

    assert_eq!(within("answer", call.outcome()).await, Outcome::Answered { answered_by: "user".into() });
    call.hang_up();
    assert_eq!(within("bye", theirs.ended()).await, "user.hangup");
    assert!(matches!(call.state(), CallState::Ended { .. }) || within("our end", call.ended()).await == "user.hangup");
}

#[tokio::test]
async fn the_callee_hangs_up() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Accept).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let mut theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    within("answered on Bob's side", async {
        while !matches!(theirs.state(), CallState::Answered { .. }) {
            theirs.changed().await;
        }
    })
    .await;
    theirs.hang_up();
    assert_eq!(within("bye", call.ended()).await, "user.hangup");
}

#[tokio::test]
async fn a_declined_call_ends_with_the_callees_reason() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    within("incoming call", bob.incoming()).await.unwrap().decline();
    match within("rejection", call.outcome()).await {
        Outcome::Ended { reason } => assert!(reason.starts_with("user."), "{reason}"),
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn a_ringing_call_is_cancelled() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let mut theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    within("ringing", async {
        while call.state() != CallState::Ringing {
            call.changed().await;
        }
    })
    .await;
    call.hang_up();
    within("cancel on Bob's side", theirs.ended()).await;
    within("our end", call.ended()).await;
}

#[tokio::test]
async fn a_screening_phone_answers_as_screening() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Screen).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    assert_eq!(within("answer", call.outcome()).await, Outcome::Answered { answered_by: "screening".into() });
}

#[tokio::test]
async fn a_call_to_nobody_says_why_and_ends_by_its_timer() {
    let net = Network::new();
    // T-Establish at its 5 s floor (§12.9): the relay's refusal changes no state (§12.7 rule 6), the timer ends it
    let alice = Phone::builder().identity(net.identity("Alice")).dialer(net.dialer()).configure(|c| c.t_establish = Some(5))
        .build().await.unwrap();
    let nobody = net.identity("Nobody");

    let mut call = alice.call(&nobody.meta.identity).await.unwrap();
    assert!(matches!(within("the call's end", call.outcome()).await, Outcome::Ended { .. }));
    assert_eq!(call.error().as_deref(), Some("transport.unknown-recipient"));
}

#[tokio::test]
async fn closing_a_phone_ends_its_calls() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Accept).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    alice.close().await.unwrap();
    assert_eq!(within("end", call.ended()).await, "transport.closed");
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn two_phones_with_native_audio_hear_each_other() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let net = Network::new();
    let media = || {
        dsip_phone::Media::Native(dsip_media::MediaConfig { source: dsip_media::Source::Tone { hz: 440.0 }, ..Default::default() })
    };
    let alice = Phone::builder().identity(net.identity("Alice")).dialer(net.dialer()).media(media()).build().await.unwrap();
    let bob = Phone::builder().identity(net.identity("Bob")).dialer(net.dialer()).media(media()).answer(AnswerPolicy::Accept)
        .build().await.unwrap();

    let mut call = alice.call(bob.identity()).await.unwrap();
    let theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    // §14.1: both sides send once the answer is signed; each hears the other
    within("media both ways", async {
        while !(call.media_received() && theirs.media_received()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    call.hang_up();
}
