//! The state directory: what a node held survives a restart, checked again on the way back in; the config file.

use std::sync::Arc;

use dsip_core::keys::KeyPair;
use dsip_core::pkarr::{build_payload, z32_encode, PublishEndpoint};
use dsip_node::config::{Config, StateDir};

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn node(state: &StateDir) -> dsip_node::Node {
    dsip_node::Node::new(None, None, "-".into(), Some(state.clone()))
}

async fn serve(n: Arc<dsip_node::Node>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let app = dsip_node::router(n);
    tokio::spawn(async move { axum::serve(l, app).await });
    base
}

#[tokio::test]
async fn held_packets_survive_a_restart_and_are_checked_again() {
    let dir = std::env::temp_dir().join(format!("dsip-node-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let st = StateDir::open(&dir).unwrap();
    let (k, k2) = (KeyPair::from_seed([3; 32]), KeyPair::from_seed([4; 32]));
    let ep = PublishEndpoint { uri: "wss://a.example/dsip".into(), bindings: vec!["ws/1.0".into()], service: None };
    let p = build_payload(&k, std::slice::from_ref(&ep), 1800, now_s() as u64 * 1_000_000, &[]).unwrap();
    let (z, z2) = (z32_encode(&k.public()), z32_encode(&k2.public()));

    let base = serve(Arc::new(node(&st))).await;
    let http = reqwest::Client::new();
    assert_eq!(http.put(format!("{base}/{z}")).body(p.clone()).send().await.unwrap().status(), 204);
    // a packet planted on disk under another key's name: it must not survive the check at restore
    std::fs::write(st.pkarr(&z2), &p).unwrap();

    let restarted = Arc::new(node(&st));
    assert_eq!(restarted.restore().await, (1, 1), "the stored packet back, the planted one dropped");
    assert!(!st.pkarr(&z2).exists(), "a packet that fails the check is removed from disk");
    let base2 = serve(restarted).await;
    let r = http.get(format!("{base2}/{z}")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().to_vec(), p, "served at once after the restart");
    assert_eq!(http.get(format!("{base2}/{z2}")).send().await.unwrap().status(), 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_overlay_identity_is_stable_and_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("dsip-node-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let st = StateDir::open(&dir).unwrap();
    let a = st.overlay_seed().unwrap();
    assert_eq!(st.overlay_seed().unwrap(), a, "generated once, then kept");
    let mode = std::fs::metadata(dir.join("overlay.key")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_keys_are_checked() {
    let dir = std::env::temp_dir().join(format!("dsip-node-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.toml");
    std::fs::write(&good, "[node]\nstate_dir = \"/var/lib/dsip-node\"\n[mainline]\nenabled = true\nport = 6881\n").unwrap();
    let c = Config::load(&good).unwrap();
    assert_eq!((c.mainline.enabled, c.mainline.port), (Some(true), Some(6881)));
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "[mainline]\nenable = true\n").unwrap();
    assert!(Config::load(&bad).is_err(), "a misspelt key is an error, not ignored");
    let _ = std::fs::remove_dir_all(&dir);
}
