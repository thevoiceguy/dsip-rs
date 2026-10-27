//! A relay embedded in the test process, with two devices bound over in-memory pipes: no sockets, no TLS. Alice
//! calls Bob, whose call glue answers at once, and the call is ACTIVE on both sides; then Alice hangs up.
//!
//! Spec: §13.2 (the `hello` binding, over any stream), §12.4 (invite, answer, bye through a relay).

use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_endpoint::{AnswerPolicy, CallCommand, CallOut, Calls, CallsConfig, Core, CoreConfig, CoreEvent, IdentityKeys, Invite};
use dsip_relay::{RelayConfig, RelayServer};
use dsip_session::SessionState;
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;

fn keys(seed: u8, name: &str) -> IdentityKeys {
    let now = now_s();
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), now - 60, now + 86_400,
                                                            &["dsip.signaling", "dsip.media.interactive"]);
    IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() }
}

/// One device: its core and call glue, bound to the relay over a pipe.
struct Device {
    core: Core,
    calls: Calls,
    conn: Connection,
}

impl Device {
    async fn bind(relay: &RelayServer, k: IdentityKeys, answer: AnswerPolicy) -> Device {
        let (ours, theirs) = tokio::io::duplex(1 << 17);
        let r = relay.clone();
        let name = k.display_name.clone();
        tokio::spawn(async move {
            let _ = r.accept(theirs, &name).await;
        });
        let params = ConnectParams {
            url: "wss://relay.test/dsip".into(),
            tls: None,
            device: &k.device,
            on_behalf_of: Some(k.identity.clone()),
            delegations: vec![k.delegation.clone()],
            supported: Supported::all_known(),
        };
        let conn = Connection::over(ours, &params, &StaticResolver::default(), &mut SeenIds::default()).await.expect("bound");
        assert_eq!(conn.relay.did, relay.did());
        let mut core = Core::new(k, CoreConfig::default(), StaticResolver::default(), now_s());
        core.set_video(false);
        Device { core, calls: Calls::new(CallsConfig { media: false, answer, ..CallsConfig::default() }), conn }
    }

    /// Send the frames among `out`.
    async fn act(&mut self, out: Vec<CallOut>) {
        for o in out {
            if let CallOut::Core(CoreEvent::Send { frame, .. }) = o {
                self.conn.send(&Envelope::from_frame(&frame).unwrap()).await.unwrap();
            }
        }
    }

    /// Take frames until `session` is in `state`.
    async fn until(&mut self, session: &str, state: SessionState) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.core.endpoint().session(session).map(|s| s.state) != Some(state) {
                let frame = self.conn.recv().await.unwrap().expect("open");
                let ev = self.core.inbound(&frame, now_s()).unwrap();
                let out = self.calls.observe(&mut self.core, ev, now_s()).unwrap();
                self.act(out).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{session} never reached {state:?}"));
    }
}

#[tokio::test]
async fn a_call_through_an_embedded_relay() {
    let relay = RelayServer::new(KeyPair::generate(), StaticResolver::default(), RelayConfig::default());
    relay.spawn_clock();
    let mut alice = Device::bind(&relay, keys(1, "Alice"), AnswerPolicy::Ring).await;
    let mut bob = Device::bind(&relay, keys(2, "Bob"), AnswerPolicy::Accept).await;

    let to = bob.core.keys().identity.clone();
    let (sid, out) = alice.calls.place(&mut alice.core, &to, Invite::default(), now_s()).unwrap();
    alice.act(out).await;
    bob.until(&sid, SessionState::Active).await;
    alice.until(&sid, SessionState::Active).await;

    let out = alice.calls.command(&mut alice.core, CallCommand::Hangup { session: sid.clone() }, now_s()).unwrap();
    alice.act(out).await;
    bob.until(&sid, SessionState::Ended).await;
}
