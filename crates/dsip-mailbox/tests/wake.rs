//! A sleeping device woken when an item is stored for its identity, end to end in one process: a push gateway over
//! HTTPS with a recording provider, a mailbox that wakes, Bob's device enrolling, registering and going away, Alice's
//! introductions arriving for him.
//!
//! Spec: W§4.2 (`wake-register` at a mailbox; spec-gap 176: an owner operation, M§4.1), W§4.4 (the `wake`
//! capability), W§5.1 (`message`: not while bound, at most one per W-Coalesce), W§5.3 (what the gateway forwards).

use std::sync::Arc;
use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{encode_payload, sign, sign_bytes, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_mailbox::{wire, MailboxConfig, MailboxServer};
use dsip_push::providers::Recorder;
use dsip_push::{Gateway, GatewayConfig, Limits, Provider};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;
use dsip_transport::wake::{Answer, WakeClient};
use dsip_transport::waker::WakeConfig;
use serde_json::{json, Value};

struct Keys {
    identity: KeyPair,
    device: KeyPair,
    delegation: Envelope,
}

fn keys() -> Keys {
    let (identity, device) = (KeyPair::generate(), KeyPair::generate());
    let now = now_s();
    let p = dsip_core::delegation::delegation_payload(&identity.did(), &device.did(), now - 60, now + 86_400, &["dsip.signaling", "dsip.messaging"]);
    let delegation = sign(&p, &identity, &identity.kid());
    Keys { identity, device, delegation }
}

async fn bind(server: &MailboxServer, k: &Keys) -> Connection {
    let (ours, theirs) = tokio::io::duplex(1 << 17);
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.accept(theirs).await;
    });
    let params = ConnectParams {
        url: "wss://mailbox.invalid/dsip".into(),
        tls: None,
        device: &k.device,
        on_behalf_of: Some(k.identity.did()),
        delegations: vec![k.delegation.clone()],
        supported: Supported::all_known(),
    };
    Connection::over(ours, &params, &StaticResolver::default(), &mut SeenIds::default()).await.expect("bound")
}

fn payload(frame: &str) -> Value {
    let env = Envelope::from_frame(frame).unwrap();
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap()
}

/// The answer to the request `id`.
async fn answer(conn: &mut Connection, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let p = payload(&conn.recv().await.unwrap().expect("open"));
            if p["in_reply_to"] == id {
                return p;
            }
        }
    })
    .await
    .expect("answered")
}

struct World {
    server: MailboxServer,
    recorder: Recorder,
    client: WakeClient,
    gateway: String,
    dir: std::path::PathBuf,
}

async fn world(tag: &str, cfg: impl FnOnce(&mut MailboxConfig)) -> World {
    let dir = std::env::temp_dir().join(format!("dsip-mailbox-wake-{tag}-{}", std::process::id()));
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
    let mut c = MailboxConfig::new(dir.join("mailbox"), "https://mailbox.invalid/blobs".into());
    c.wake = Some(WakeConfig { client: client.clone(), gateways: Some(vec![did.clone()]), store: None });
    cfg(&mut c);
    let server = MailboxServer::open(c).unwrap();
    server.spawn_tasks();
    World { server, recorder, client, gateway: did, dir }
}

/// `device` enrols `token` at the gateway and sends `wake-register` to the mailbox; returns the mailbox's answer.
async fn register(w: &World, k: &Keys, conn: &mut Connection, token: &str) -> Value {
    let now = now_s();
    let wake_key = KeyPair::generate();
    let enrol = dsip_wake::enrol_message(&wake_key.did(), &w.gateway, "fcm", "dsip-test", token, None, now);
    let answer_ = w.client.send(&w.gateway, &sign(&enrol, &wake_key, &wake_key.kid())).await.expect("the gateway answered");
    let Answer::Accepted { handle: Some(handle) } = answer_ else { panic!("enrolment refused: {answer_:?}") };
    let reg = dsip_wake::registration_payload(&wake_key.did(), w.server.did(), &w.gateway, &handle, now - 1, now + 86_400);
    let reg = serde_json::to_value(sign(&reg, &wake_key, &wake_key.kid())).unwrap();
    let msg = dsip_wake::register_message(&k.device.did(), w.server.did(), &reg, None, None, now);
    let id = msg["id"].as_str().unwrap().to_string();
    conn.send(&sign(&msg, &k.device, &k.device.kid())).await.unwrap();
    answer(conn, &id).await
}

/// Alice introduces herself to Bob through his mailbox (M§14.1): an item stored for Bob's identity.
async fn introduce(conn: &mut Connection, alice: &Keys, bob: &str, mailbox: &str) {
    let now = now_s();
    let p = json!({"dsip": wire::version_block(), "type": "introduction", "id": wire::new_id(now), "from": alice.identity.did(),
        "to": bob, "identity": {"display_name": "Alice"}, "purpose": "hi", "issued_at": now, "expires_at": now + 86_400});
    let e = sign_bytes(&encode_payload(&p), &alice.device, &alice.device.kid(), vec![alice.delegation.clone()]);
    let env = wire::message(&alice.device, "deposit", mailbox, now, wire::TTL_S,
        json!({"class": "introduction", "recipient": bob, "envelope": format!("{}.{}.{}", e.protected, e.payload, e.signature)}));
    let id = wire::payload_of(&env).unwrap()["id"].as_str().unwrap().to_string();
    conn.send(&env).await.unwrap();
    let a = answer(conn, &id).await;
    assert_eq!(a["type"], "accepted", "{a}");
}

/// Wait until the recorder holds `n` pushes, then a little longer to see that no more come.
async fn pushes(rec: &Recorder, n: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while rec.pushes().len() < n {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{n} pushes never arrived: {:?}", rec.pushes()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    rec.pushes()
}

#[tokio::test]
async fn a_sleeping_device_is_woken_once_a_minute_for_what_is_stored_for_it() {
    let w = world("message", |c| c.serve_any = Some(4)).await;
    let (alice, bob) = (keys(), keys());
    let mut bob_conn = bind(&w.server, &bob).await;
    assert_eq!(bob_conn.relay.capabilities["wake"], json!({"profiles": ["wake/0.1"], "kinds": ["message"]}));
    // the registration is Bob's first owner operation: it enrols him (spec-gap 176)
    let a = register(&w, &bob, &mut bob_conn, "fcm-token-bob").await;
    assert_eq!(a["type"], "wake-accepted", "{a}");

    // stored while Bob is bound: no wake
    let mut alice_conn = bind(&w.server, &alice).await;
    introduce(&mut alice_conn, &alice, &bob.identity.did(), w.server.did()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(w.recorder.pushes().is_empty(), "{:?}", w.recorder.pushes());

    // asleep: the next item wakes him, the one after it within W-Coalesce does not
    bob_conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "asleep").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let carol = keys();
    introduce(&mut alice_conn, &carol, &bob.identity.did(), w.server.did()).await;
    let dave = keys();
    introduce(&mut alice_conn, &dave, &bob.identity.did(), w.server.did()).await;
    let p = pushes(&w.recorder, 1).await;
    assert_eq!(p.len(), 1, "coalesced: {p:?}");
    assert_eq!((p[0]["class"].as_str(), p[0]["token"].as_str()), (Some("message"), Some("fcm-token-bob")));
    assert_eq!(p[0]["data"]["dsip-wake"], json!({"kind": "message", "waker": w.server.did()}), "no session, no hint");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[tokio::test]
async fn an_identity_the_mailbox_does_not_serve_cannot_register() {
    let owner = KeyPair::generate();
    let w = world("not-served", |c| c.owners = vec![owner.did()]).await;
    let bob = keys();
    let mut bob_conn = bind(&w.server, &bob).await;
    let a = register(&w, &bob, &mut bob_conn, "fcm-token-bob").await;
    assert_eq!((a["type"].as_str(), a["reason"].as_str()), (Some("error"), Some("mailbox.not-served")), "{a}");
    let _ = std::fs::remove_dir_all(&w.dir);
}
