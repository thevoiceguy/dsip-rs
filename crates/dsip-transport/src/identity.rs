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
            &["dsip.signaling", "dsip.media.interactive"],
        );
        let delegation = sign(&payload, &controller, &controller.kid());
        let meta = IdentityMeta { identity: controller.did(), device: device.did(), display_name: display_name.into() };
        std::fs::write(dir.join("controller.key"), hex(&controller.seed()))?;
        std::fs::write(dir.join("device.key"), hex(&device.seed()))?;
        std::fs::write(dir.join("delegation.json"), delegation.frame())?;
        std::fs::write(dir.join("identity.json"), serde_json::to_string_pretty(&meta)?)?;
        Ok(Identity { dir: dir.to_path_buf(), controller, device, delegation, meta })
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
