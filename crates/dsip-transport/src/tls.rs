//! TLS material for the `wss` requirement.
//!
//! Spec: §13.2 — the URI scheme MUST be `wss`; plaintext `ws` MUST NOT be
//! offered or accepted; TLS 1.3+ with certificate validation against the
//! advertised hostname. Impl: for local demos the relay generates a
//! self-signed certificate and clients trust it explicitly via `--ca`; no
//! plaintext fallback exists anywhere in this crate.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed certificate for `hosts` and write `cert.pem` / `key.pem` into `dir`.
/// Returns the two paths. Existing files are reused.
pub fn ensure_self_signed(dir: &Path, hosts: &[String]) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    let cert = rcgen::generate_simple_self_signed(hosts.to_vec()).context("generating self-signed certificate")?;
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    Ok((cert_path, key_path))
}

/// Server-side acceptor from PEM files.
pub fn acceptor(cert_pem: &Path, key_pem: &Path) -> Result<TlsAcceptor> {
    install_provider();
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert_pem)?)).collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key_pem)?))?
            .context("no private key in key.pem")?;
    let cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Client config trusting exactly the CA/self-signed certificate(s) in `ca_pem`
/// (plus nothing else). `None` ⇒ the platform's native roots via tokio-tungstenite's default connector.
pub fn client_config(ca_pem: Option<&Path>) -> Result<Option<Arc<ClientConfig>>> {
    install_provider();
    let Some(p) = ca_pem else { return Ok(None) };
    let mut roots = RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(p)?)) {
        roots.add(c?)?;
    }
    let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Some(Arc::new(cfg)))
}
