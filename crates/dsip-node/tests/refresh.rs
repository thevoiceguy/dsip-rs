//! A held Pkarr packet is not served forever (DHT Hints Profile §10): a node looks for the publisher's newer packet
//! on Mainline — in the background while what it holds is fresh, and before answering once it has expired. On the
//! WAN, a node kept serving the first packet it had fetched after it expired, while Mainline held its replacement.
//! Mainline here is a local testnet: nothing reaches the public DHT.

use std::sync::Arc;
use std::time::Duration;

use dsip_core::keys::KeyPair;
use dsip_core::pkarr::{build_payload, z32_encode, PublishEndpoint};

fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() * 1_000_000
}

fn packet(key: &KeyPair, uri: &str, ttl: u32, ts: u64) -> Vec<u8> {
    let ep = PublishEndpoint { uri: uri.into(), bindings: vec!["ws/1.0".into()], service: None };
    build_payload(key, &[ep], ttl, ts, &[]).unwrap()
}

/// Two nodes on one Mainline testnet, serving HTTP: (A, C).
async fn pair(net: &mainline::Testnet) -> (String, String) {
    let mut bases = vec![];
    for _ in 0..2 {
        let dht = mainline::Dht::builder().bootstrap(&net.bootstrap).server_mode().build().unwrap().as_async();
        assert!(dht.bootstrapped().await);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        bases.push(format!("http://{}", l.local_addr().unwrap()));
        let app = dsip_node::router(Arc::new(dsip_node::Node::new(None, Some(dht), "-".into(), None)));
        tokio::spawn(async move { axum::serve(l, app).await });
    }
    (bases[0].clone(), bases[1].clone())
}

async fn get(http: &reqwest::Client, url: &str) -> Vec<u8> {
    let r = http.get(url).send().await.unwrap();
    assert_eq!(r.status(), 200);
    r.bytes().await.unwrap().to_vec()
}

/// Poll `url` until it serves `want`, for up to `secs`.
async fn serves(http: &reqwest::Client, url: &str, want: &[u8], secs: u64) -> bool {
    for _ in 0..secs * 5 {
        if get(http, url).await == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_packet_is_replaced_from_mainline_before_it_is_served() {
    let net = mainline::Testnet::builder(10).build().unwrap();
    let (a, c) = pair(&net).await;
    let http = reqwest::Client::new();
    let k = KeyPair::from_seed([21; 32]);
    let z = z32_encode(&k.public());
    let ts = now_us();
    let (short, newer) = (packet(&k, "wss://old.example/dsip", 2, ts), packet(&k, "wss://new.example/dsip", 1800, ts + 1));

    // C holds a packet that lives 2 s; the publisher's newer one reaches Mainline through A
    assert_eq!(http.put(format!("{c}/{z}")).body(short.clone()).send().await.unwrap().status(), 204);
    assert_eq!(http.put(format!("{a}/{z}")).body(newer.clone()).send().await.unwrap().status(), 204);
    assert!(serves(&http, &format!("{a}/{z}"), &newer, 5).await);
    tokio::time::sleep(Duration::from_secs(3)).await;

    // the first GET after expiry already serves the newer packet: C looked before answering
    assert_eq!(get(&http, &format!("{c}/{z}")).await, newer, "C served its expired packet");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_packet_is_served_at_once_and_replaced_in_the_background() {
    let net = mainline::Testnet::builder(10).build().unwrap();
    let (a, c) = pair(&net).await;
    let http = reqwest::Client::new();
    let k = KeyPair::from_seed([22; 32]);
    let z = z32_encode(&k.public());
    let ts = now_us();
    let (held, newer) = (packet(&k, "wss://old.example/dsip", 1800, ts), packet(&k, "wss://new.example/dsip", 1800, ts + 1));

    assert_eq!(http.put(format!("{c}/{z}")).body(held.clone()).send().await.unwrap().status(), 204);
    assert_eq!(http.put(format!("{a}/{z}")).body(newer.clone()).send().await.unwrap().status(), 204);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // fresh: served without waiting on Mainline, which is then searched behind it
    assert_eq!(get(&http, &format!("{c}/{z}")).await, held);
    assert!(serves(&http, &format!("{c}/{z}"), &newer, 8).await, "C never picked up the newer packet");
}
