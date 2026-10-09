//! On-disk identity: controller key, device key, and the device delegation.
//!
//! Spec: §7.3 (identity vs device keys), §7.4 (device delegation). The
//! controller key signs exactly one thing in Phase 1 — the delegation — and
//! never a session message; the device key signs everything on the wire.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;

/// Metadata written next to the keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMeta {
    /// Controller DID.
    pub identity: String,
    /// Device DID.
    pub device: String,
    /// Display name (a claim; §18.2).
    pub display_name: String,
}

/// A loaded identity directory.
pub struct Identity {
    /// Directory.
    pub dir: PathBuf,
    /// Controller key (`did:key`).
    pub controller: KeyPair,
    /// Device key (`did:key`).
    pub device: KeyPair,
    /// Delegation controller→device (signed by the controller).
    pub delegation: Envelope,
    /// Metadata.
    pub meta: IdentityMeta,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
    }
    Ok(out)
}

impl Identity {
    /// Create a new identity directory with fresh keys and a one-year delegation.
    pub fn init(dir: &Path, display_name: &str, fixture: Option<&str>, controller_from: Option<&Path>) -> Result<Identity> {
        Identity::init_with(dir, display_name, fixture, controller_from, &[])
    }

    /// As [`Identity::init`], delegating `extra` capabilities as well (e.g. `dsip.record`, Recording Profile C§1).
    pub fn init_with(dir: &Path, display_name: &str, fixture: Option<&str>, controller_from: Option<&Path>, extra: &[String]) -> Result<Identity> {
        std::fs::create_dir_all(dir)?;
        let (controller, device) = match (fixture, controller_from) {
            // A second device of an existing identity: reuse its controller, mint a new device key.
            (_, Some(src)) => (Identity::load(src)?.controller, KeyPair::generate()),
            (Some(f), None) => (KeyPair::from_fixture_name(f), KeyPair::from_fixture_name(&format!("{f}-phone"))),
            (None, None) => (KeyPair::generate(), KeyPair::generate()),
        };
        let now = crate::now_s();
        let payload = delegation_payload(
            &controller.did(),
            &device.did(),
            now - 60,
            now + 365 * 86_400,
            &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"]
                .iter()
                .copied()
                .chain(extra.iter().map(String::as_str))
                .collect::<Vec<_>>(),
        );
        let delegation = sign(&payload, &controller, &controller.kid());
        let meta = IdentityMeta { identity: controller.did(), device: device.did(), display_name: display_name.into() };
        std::fs::write(dir.join("controller.key"), hex(&controller.seed()))?;
        std::fs::write(dir.join("device.key"), hex(&device.seed()))?;
        std::fs::write(dir.join("delegation.json"), delegation.frame())?;
        std::fs::write(dir.join("identity.json"), serde_json::to_string_pretty(&meta)?)?;
        Ok(Identity { dir: dir.to_path_buf(), controller, device, delegation, meta })
    }

    /// Re-home this identity on `did:web` `did`: its controller key becomes the document's `#key-1`, the delegation is
    /// re-signed with that subject and kid, and `did.json` is written for the domain to serve. `also_known_as` lists
    /// aliases the document claims, e.g. `tel:+15551234567` for a bound number (Number Attestation N§3.3).
    ///
    /// Spec: §7.2 (did:web), §7.4 (the delegation names the identity), §8.1 (the document is authoritative).
    pub fn rehome_did_web(&mut self, did: &str, also_known_as: &[String]) -> Result<()> {
        anyhow::ensure!(did.starts_with("did:web:"), "not a did:web DID: {did}");
        let kid = format!("{did}#key-1");
        // Keep the capabilities the current delegation grants (its payload is our own, already trusted).
        use base64::Engine as _;
        let payload: serde_json::Value = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.delegation.payload)
            .ok()
            .and_then(|b: Vec<u8>| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let caps: Vec<String> = payload["capabilities"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
        let now = crate::now_s();
        let caps_ref: Vec<&str> = caps.iter().map(String::as_str).collect();
        let payload = delegation_payload(did, &self.device.did(), now - 60, now + 365 * 86_400, &caps_ref);
        self.delegation = sign(&payload, &self.controller, &kid);
        self.meta.identity = did.to_string();
        let multibase = self.controller.did().trim_start_matches("did:key:").to_string();
        let mut doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{"id": kid, "type": "Multikey", "controller": did, "publicKeyMultibase": multibase}],
            "authentication": [kid],
            "assertionMethod": [kid],
        });
        if !also_known_as.is_empty() {
            doc["alsoKnownAs"] = serde_json::json!(also_known_as);
        }
        std::fs::write(self.dir.join("delegation.json"), self.delegation.frame())?;
        std::fs::write(self.dir.join("identity.json"), serde_json::to_string_pretty(&self.meta)?)?;
        std::fs::write(self.dir.join("did.json"), serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }

    /// Load an identity directory.
    pub fn load(dir: &Path) -> Result<Identity> {
        let read = |n: &str| std::fs::read_to_string(dir.join(n)).with_context(|| format!("reading {}/{n}", dir.display()));
        let controller = KeyPair::from_seed(unhex(&read("controller.key")?)?);
        let device = KeyPair::from_seed(unhex(&read("device.key")?)?);
        let delegation = Envelope::from_frame(&read("delegation.json")?).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
        let meta: IdentityMeta = serde_json::from_str(&read("identity.json")?)?;
        Ok(Identity { dir: dir.to_path_buf(), controller, device, delegation, meta })
    }
}
