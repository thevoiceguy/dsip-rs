//! TLS material for the `wss` requirement.
//!
//! Spec: §13.2 — the URI scheme MUST be `wss`; plaintext `ws` MUST NOT be
//! offered or accepted; TLS 1.3+ with certificate validation against the
//! advertised hostname. Impl: for local demos the relay generates a
//! self-signed certificate and clients trust it explicitly via `--ca`; no
//! plaintext fallback exists anywhere in this crate.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::error::{file, Error, Result};

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed certificate for `hosts` and write `cert.pem` / `key.pem` into `dir`.
/// Returns the two paths. Existing files are reused.
pub fn ensure_self_signed(dir: &Path, hosts: &[String]) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    file(dir, std::fs::create_dir_all(dir))?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    // Impl: a distinct subject per certificate. rcgen's default subject is the same everywhere
    // ("rcgen self signed cert"), and OpenSSL picks a trust anchor from a PEM bundle by subject, so a
    // bundle of several such roots verified only the first server (found on the WAN testbed).
    let key_pair = rcgen::KeyPair::generate()?;
    let tag: String = key_pair.public_key_raw().iter().rev().take(4).map(|b| format!("{b:02x}")).collect();
    let first = hosts.first().map(String::as_str).unwrap_or("localhost");
    let mut params = rcgen::CertificateParams::new(hosts.to_vec())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("DSIP self-signed {first} {tag}"));
    let cert = params.self_signed(&key_pair)?;
    file(&cert_path, std::fs::write(&cert_path, cert.pem()))?;
    file(&key_path, std::fs::write(&key_path, key_pair.serialize_pem()))?;
    Ok((cert_path, key_path))
}

/// Server-side acceptor from PEM files.
pub fn acceptor(cert_pem: &Path, key_pem: &Path) -> Result<TlsAcceptor> {
    install_provider();
    let certs: Vec<CertificateDer<'static>> =
        file(cert_pem, rustls_pemfile::certs(&mut std::io::BufReader::new(file(cert_pem, std::fs::File::open(cert_pem))?)).collect())?;
    let key: PrivateKeyDer<'static> =
        file(key_pem, rustls_pemfile::private_key(&mut std::io::BufReader::new(file(key_pem, std::fs::File::open(key_pem))?)))?
            .ok_or_else(|| Error::NoPrivateKey(key_pem.to_path_buf()))?;
    let cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Client config trusting the CA/self-signed certificate(s) in `ca_pem` beside the platform's native roots: a
/// service dials peers under self-signed certificates (a lab) and under public ones (a deployment) from the same
/// configuration. `None` ⇒ the native roots alone via tokio-tungstenite's default connector.
pub fn client_config(ca_pem: Option<&Path>) -> Result<Option<Arc<ClientConfig>>> {
    install_provider();
    let Some(p) = ca_pem else { return Ok(None) };
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(file(p, std::fs::File::open(p))?)) {
        roots.add(file(p, c)?)?;
    }
    let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Some(Arc::new(cfg)))
}
