//! The HTTP hints API end to end (DHT Hints Profile §10): every route, over real HTTP, against a node whose overlay
//! is a real one-node Kademlia and whose Pkarr store is the `check: "store"` rule.

use std::sync::Arc;

use dsip_core::keys::KeyPair;
use dsip_core::pkarr::{build_payload, z32_encode, PublishEndpoint};
use dsip_dht::record::{hint_payload, sign_hint, Endpoint};

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn serve(node: dsip_node::Node) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let app = dsip_node::router(Arc::new(node));
    tokio::spawn(async move { axum::serve(l, app).await });
    base
}

fn packet(key: &KeyPair, uri: &str, ts: u64) -> Vec<u8> {
    let ep = PublishEndpoint { uri: uri.into(), bindings: vec!["ws/1.0".into()], service: None };
    build_payload(key, &[ep], 1800, ts, &[]).unwrap()
}

#[tokio::test]
async fn pkarr_routes_store_serve_and_refuse() {
    let base = serve(dsip_node::Node::new(None, None, "-".into(), None)).await;
    let http = reqwest::Client::new();
    let (k, other) = (KeyPair::from_seed([7; 32]), KeyPair::from_seed([8; 32]));
    let z = z32_encode(&k.public());
    let ts = now_s() as u64 * 1_000_000;
    let (p1, p2) = (packet(&k, "wss://a.example/dsip", ts), packet(&k, "wss://b.example/dsip", ts + 1_000_000));
    let put = |body: Vec<u8>, key: String| http.put(format!("{base}/{key}")).body(body).send();

    let r = http.get(format!("{base}/{z}")).send().await.unwrap();
    assert_eq!(r.status(), 404, "nothing held, no Mainline");
    assert_eq!(put(p1.clone(), z.clone()).await.unwrap().status(), 204, "stored");
    let r = http.get(format!("{base}/{z}")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    assert_eq!(r.bytes().await.unwrap().to_vec(), p1, "served byte for byte");
    assert_eq!(put(p1.clone(), z.clone()).await.unwrap().status(), 204, "the same bytes: idempotent");
    assert_eq!(put(p2.clone(), z.clone()).await.unwrap().status(), 204, "newer replaces");
    let r = put(p1.clone(), z.clone()).await.unwrap();
    assert_eq!((r.status().as_u16(), r.text().await.unwrap()), (409, "older".into()), "§8.3: older is kept out");
    let r = put(packet(&other, "wss://evil.example/dsip", ts + 9_000_000), z.clone()).await.unwrap();
    assert_eq!((r.status().as_u16(), r.text().await.unwrap()), (400, "signature".into()), "another key's packet");
    let r = put(p2.clone(), z.to_uppercase()).await.unwrap();
    assert_eq!((r.status().as_u16(), r.text().await.unwrap()), (400, "bad-key".into()), "the path is canonical");
    assert_eq!(http.get(format!("{base}/{z}")).send().await.unwrap().bytes().await.unwrap().to_vec(), p2);
}

#[tokio::test]
async fn overlay_routes_verify_before_store() {
    let (h, id) = dsip_dht::node::start(Default::default()).await.unwrap();
    let base = serve(dsip_node::Node::new(Some(h), None, id.to_string(), None)).await;
    let http = reqwest::Client::new();
    let k = KeyPair::from_seed([9; 32]);
    let did = k.did();
    let ep = [Endpoint { uri: "wss://relay.example/dsip".into(), bindings: vec!["ws/1.0".into()] }];
    let now = now_s();
    let frame = |seq: i64| sign_hint(&hint_payload(&did, &did, &ep, seq, now, 1800), &k, vec![]).frame();

    let r = http.post(format!("{base}/dsip/v1/hints")).body(frame(now)).send().await.unwrap();
    assert_eq!(r.status(), 202, "{}", r.text().await.unwrap());
    let r: serde_json::Value = http.get(format!("{base}/dsip/v1/hints/{did}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["hints"].as_array().map(Vec::len), Some(1), "{r}");
    assert_eq!(http.post(format!("{base}/dsip/v1/hints")).body("not a frame").send().await.unwrap().status(), 400);
    assert_eq!(http.post(format!("{base}/dsip/v1/hints")).body(frame(now - 10)).send().await.unwrap().status(), 409,
               "§8.3: a lower seq loses to the held record");
    let info: serde_json::Value = http.get(format!("{base}/dsip/v1/node")).send().await.unwrap().json().await.unwrap();
    assert_eq!(info["peer_id"], id.to_string());
}
