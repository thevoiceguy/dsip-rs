//! A relay inside your own process: an open relay on `wss://127.0.0.1:8443/dsip` with a self-signed certificate made
//! in `./.embedded-relay`. Clients trust it with `--ca .embedded-relay/cert.pem`.
//!
//! ```sh
//! cargo run -p dsip-relay --example embedded_relay
//! ```

use std::sync::Arc;

use dsip_core::did::StaticResolver;
use dsip_core::keys::KeyPair;
use dsip_relay::{www, RelayConfig, RelayServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::path::Path::new(".embedded-relay");
    std::fs::create_dir_all(dir)?;
    let (cert, key) = dsip_transport::tls::ensure_self_signed(dir, &["localhost".into(), "127.0.0.1".into()])?;

    let relay = RelayServer::new(KeyPair::generate(), StaticResolver::default(), RelayConfig::default());
    relay.spawn_clock();
    println!("relay {} on wss://127.0.0.1:8443/dsip (clients: --ca {})", relay.did(), cert.display());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    let routes = Arc::new(www::Routes::default());
    relay.serve_tls(listener, dsip_transport::tls::acceptor(&cert, &key)?, routes).await?;
    Ok(())
}
