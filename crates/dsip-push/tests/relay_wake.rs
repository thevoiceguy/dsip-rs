//! A sleeping phone woken for a call, end to end in one process: a push gateway over HTTPS with a recording
//! provider, a relay that wakes, Bob's phone enrolling, registering and going away, Alice calling.
//!
//! Spec: W§3 (enrolment), W§4.2 (registration), W§5.1–W§5.3 (`call`, `call-ended`, the gateway's checks and what it
//! forwards, `wake.registration-ended`), W§6 (the sealed hint), §13.3 (the held invite flushed on the binding).

use std::sync::Arc;
use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_endpoint::{AnswerPolicy, CallCommand, CallOut, Calls, CallsConfig, Core, CoreConfig, CoreEvent, IdentityKeys, Invite};
use dsip_push::providers::Recorder;
use dsip_push::{Gateway, GatewayConfig, Limits, Provider};
use dsip_relay::wake::WakeConfig;
use dsip_relay::{RelayConfig, RelayServer};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;
use dsip_transport::wake::{Answer, WakeClient};
use serde_json::Value;

fn keys(seed: u8, name: &str) -> IdentityKeys {
    let now = now_s();
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), now - 60, now + 86_400,
                                                            &["dsip.signaling", "dsip.media.interactive"]);
    IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() }
}

async fn bind(relay: &RelayServer, k: &IdentityKeys) -> Connection {
    let (ours, theirs) = tokio::io::duplex(1 << 17);
    let (r, name) = (relay.clone(), k.display_name.clone());
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
    Connection::over(ours, &params, &StaticResolver::default(), &mut SeenIds::default()).await.expect("bound")
}

fn payload(frame: &str) -> Value {
    let env = Envelope::from_frame(frame).unwrap();
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap()
}

/// The next frame whose payload satisfies `want`.
async fn next(conn: &mut Connection, want: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let f = conn.recv().await.unwrap().expect("open");
            let p = payload(&f);
            if want(&p) {
                return p;
            }
        }
    })
    .await
    .expect("the frame arrived")
}

/// Wait until the recorder holds `n` pushes.
async fn pushes(rec: &Recorder, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let p = rec.pushes();
            if p.len() >= n {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{n} pushes never arrived: {:?}", rec.pushes()))
}

struct World {
    relay: RelayServer,
    recorder: Recorder,
    client: WakeClient,
    gateway: String,
    _dir: std::path::PathBuf,
}

async fn world(tag: &str) -> World {
    let dir = std::env::temp_dir().join(format!("dsip-push-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (cert, key) = dsip_transport::tls::ensure_self_signed(&dir, &["localhost".into(), "127.0.0.1".into()]).unwrap();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let did = format!("did:web:localhost%3A{port}");
    let endpoint = format!("https://localhost:{port}/wake");
    let recorder = Recorder::default();
    let providers: std::collections::HashMap<String, Arc<dyn Provider>> = [("fcm".to_string(), Arc::new(recorder.clone()) as Arc<dyn Provider>)].into();
    let gateway = Arc::new(Gateway::new(GatewayConfig {
        key: KeyPair::generate(),
        did: did.clone(),
        handle_key: rand::random(),
        apps: vec![("fcm".into(), "dsip-test".into())],
        providers,
        resolver: StaticResolver::default(),
        web: None,
        limits: Limits::default(),
    }));
    let mut docs = StaticResolver::default();
    docs.insert(gateway.document(&endpoint));
    let acceptor = dsip_transport::tls::acceptor(&cert, &key).unwrap();
    let ep = endpoint.clone();
    tokio::spawn(async move { dsip_push::server::serve(gateway, &ep, tcp, acceptor).await });
    let client = WakeClient::new(Arc::new(docs)).with_ca(&std::fs::read(&cert).unwrap()).unwrap();
    let cfg = RelayConfig { wake: Some(WakeConfig { client: client.clone(), gateways: Some(vec![did.clone()]), store: None }), ..RelayConfig::default() };
    let relay = RelayServer::new(KeyPair::generate(), StaticResolver::default(), cfg);
    relay.spawn_clock();
    World { relay, recorder, client, gateway: did, _dir: dir }
}

/// Bob's phone enrols `token` at the gateway and registers with the relay; returns its seal secret.
async fn enrol_and_register(w: &World, bob: &IdentityKeys, conn: &mut Connection, token: &str) -> [u8; 32] {
    let now = now_s();
    let wake_key = KeyPair::generate();
    let enrol = dsip_wake::enrol_message(&wake_key.did(), &w.gateway, "fcm", "dsip-test", token, None, now);
    let answer = w.client.send(&w.gateway, &sign(&enrol, &wake_key, &wake_key.kid())).await.expect("the gateway answered");
    let Answer::Accepted { handle: Some(handle) } = answer else { panic!("enrolment refused: {answer:?}") };
    let reg = dsip_wake::registration_payload(&wake_key.did(), w.relay.did(), &w.gateway, &handle, now - 1, now + 86_400);
    let reg = serde_json::to_value(sign(&reg, &wake_key, &wake_key.kid())).unwrap();
    let secret: [u8; 32] = rand::random();
    let seal_key = dsip_core::hpke::x25519_public(&secret);
    let msg = dsip_wake::register_message(&bob.device.did(), w.relay.did(), &reg, Some(&seal_key), None, now);
    let id = msg["id"].as_str().unwrap().to_string();
    conn.send(&sign(&msg, &bob.device, &bob.device.kid())).await.unwrap();
    let a = next(conn, |p| p["in_reply_to"] == id.as_str()).await;
    assert_eq!(a["type"], "wake-accepted", "{a}");
    secret
}

fn core(k: IdentityKeys) -> (Core, Calls) {
    let mut core = Core::new(k, CoreConfig::default(), StaticResolver::default(), now_s());
    core.set_video(false);
    (core, Calls::new(CallsConfig { media: false, answer: AnswerPolicy::Ring, ..CallsConfig::default() }))
}

async fn act(conn: &mut Connection, out: Vec<CallOut>) {
    for o in out {
        if let CallOut::Core(CoreEvent::Send { frame, .. }) = o {
            conn.send(&Envelope::from_frame(&frame).unwrap()).await.unwrap();
        }
    }
}

/// Close Bob's connection and wait until the relay has unbound him.
async fn sleep_phone(mut conn: Connection) {
    conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "asleep").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn a_sleeping_phone_is_woken_for_a_call_and_receives_it_when_it_binds() {
    let w = world("call").await;
    let (alice, bob) = (keys(1, "Alice"), keys(2, "Bob"));
    let mut bob_conn = bind(&w.relay, &bob).await;
    let secret = enrol_and_register(&w, &bob, &mut bob_conn, "fcm-token-bob").await;
    sleep_phone(bob_conn).await;

    let mut alice_conn = bind(&w.relay, &alice).await;
    let (mut a_core, mut a_calls) = core(alice.clone());
    let (sid, out) = a_calls.place(&mut a_core, &bob.identity, Invite::default(), now_s()).unwrap();
    act(&mut alice_conn, out).await;

    let p = pushes(&w.recorder, 1).await;
    let data = &p[0]["data"]["dsip-wake"];
    assert_eq!((p[0]["class"].as_str(), p[0]["token"].as_str()), (Some("call"), Some("fcm-token-bob")));
    assert_eq!((data["kind"].as_str(), data["session"].as_str(), data["waker"].as_str()), (Some("call"), Some(sid.as_str()), Some(w.relay.did())));
    let hint = dsip_wake::open_hint(&data["sealed"], &sid, &secret).expect("the hint opens");
    assert_eq!(hint, serde_json::json!({"from": alice.device.did(), "on_behalf_of": alice.identity}));

    // woken, the phone binds and the held invite is flushed to it (§13.3)
    let mut bob_conn = bind(&w.relay, &bob).await;
    let invite = next(&mut bob_conn, |p| p["type"] == "invite").await;
    assert_eq!(invite["id"], sid.as_str());
}

#[tokio::test]
async fn a_call_cancelled_before_the_phone_binds_ends_on_its_screen() {
    let w = world("cancel").await;
    let (alice, bob) = (keys(3, "Alice"), keys(4, "Bob"));
    let mut bob_conn = bind(&w.relay, &bob).await;
    enrol_and_register(&w, &bob, &mut bob_conn, "fcm-token-bob").await;
    sleep_phone(bob_conn).await;

    let mut alice_conn = bind(&w.relay, &alice).await;
    let (mut a_core, mut a_calls) = core(alice);
    let (sid, out) = a_calls.place(&mut a_core, &bob.identity, Invite::default(), now_s()).unwrap();
    act(&mut alice_conn, out).await;
    pushes(&w.recorder, 1).await;
    let out = a_calls.command(&mut a_core, CallCommand::Cancel { session: sid.clone() }, now_s()).unwrap();
    act(&mut alice_conn, out).await;

    let p = pushes(&w.recorder, 2).await;
    let data = &p[1]["data"]["dsip-wake"];
    assert_eq!((data["kind"].as_str(), data["session"].as_str()), (Some("call-ended"), Some(sid.as_str())));
    assert!(data.get("sealed").is_none(), "only a call carries the hint");
}

#[tokio::test]
async fn a_dead_token_ends_the_registration() {
    let w = world("dead").await;
    let (alice, bob) = (keys(5, "Alice"), keys(6, "Bob"));
    let mut bob_conn = bind(&w.relay, &bob).await;
    // the recorder answers a token beginning `unregistered-` as a dead one (APNs 410)
    enrol_and_register(&w, &bob, &mut bob_conn, "unregistered-bob").await;
    sleep_phone(bob_conn).await;

    let mut alice_conn = bind(&w.relay, &alice).await;
    let (mut a_core, mut a_calls) = core(alice);
    let (sid, out) = a_calls.place(&mut a_core, &bob.identity, Invite::default(), now_s()).unwrap();
    act(&mut alice_conn, out).await;
    // the gateway answers wake.registration-ended and the relay forgets the registration: the cancel wakes nothing
    tokio::time::sleep(Duration::from_millis(500)).await;
    let out = a_calls.command(&mut a_core, CallCommand::Cancel { session: sid }, now_s()).unwrap();
    act(&mut alice_conn, out).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(w.recorder.pushes().is_empty(), "{:?}", w.recorder.pushes());
}
