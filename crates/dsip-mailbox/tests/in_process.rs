//! A mailbox embedded in the test process: a device binds to it over an in-memory pipe and gets the service's own
//! `hello`, with the mailbox capabilities; it enrols by binding (spec-gap 115).
//!
//! Spec: M§4.3 (bind with `hello`, mailbox capabilities), §13.2.

use dsip_core::did::StaticResolver;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_mailbox::{MailboxConfig, MailboxServer};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;

#[tokio::test]
async fn a_device_binds_to_an_embedded_mailbox() {
    let state = std::env::temp_dir().join(format!("dsip-mailbox-in-process-{}", std::process::id()));
    let mut cfg = MailboxConfig::new(state.clone(), "https://mailbox.invalid/blobs".into());
    cfg.serve_any = Some(4);
    let server = MailboxServer::open(cfg).unwrap();

    let (ours, theirs) = tokio::io::duplex(1 << 17);
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.accept(theirs).await;
    });
    let (controller, device) = (KeyPair::generate(), KeyPair::generate());
    let now = now_s();
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), now - 60, now + 3600, &["dsip.signaling", "dsip.messaging"]);
    let params = ConnectParams {
        url: "wss://mailbox.invalid/dsip".into(),
        tls: None,
        device: &device,
        on_behalf_of: Some(controller.did()),
        delegations: vec![sign(&payload, &controller, &controller.kid())],
        supported: Supported::all_known(),
    };
    let conn = Connection::over(ours, &params, &StaticResolver::default(), &mut SeenIds::default()).await.expect("bound");
    assert_eq!(conn.relay.did, server.did());
    assert_eq!(conn.relay.capabilities["mailbox"]["blob_endpoint"], "https://mailbox.invalid/blobs");
    let _ = std::fs::remove_dir_all(state);
}
