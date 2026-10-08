//! `dsip-node`'s configuration: a TOML file whose every key can be overridden by a command-line flag, and the
//! state directory that lets a restarted node rejoin at once.
//!
//! Spec: none (infrastructure). Plan `impl/docs/dsip-node-plan.md` §4–§5.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The config file (`/etc/dsip-node/config.toml`). Every key is optional; a flag wins over the file, and the file
/// over the default. Unknown keys are an error, so a misspelt one is not silently ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[node]`.
    #[serde(default)]
    pub node: NodeSection,
    /// `[overlay]`.
    #[serde(default)]
    pub overlay: OverlaySection,
    /// `[mainline]`.
    #[serde(default)]
    pub mainline: MainlineSection,
    /// `[http]`.
    #[serde(default)]
    pub http: HttpSection,
    /// `[limits]`.
    #[serde(default)]
    pub limits: LimitsSection,
}

/// `[limits]`: what a misbehaving peer or client costs before it is cut off.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Ban an overlay peer for this long once it spends its rejection budget (default 600; 0: never ban).
    pub ban_secs: Option<u64>,
    /// Also refuse a banned peer's IP (default false: honest peers behind the same NAT would be refused too).
    pub ban_ip: Option<bool>,
    /// HTTP requests per client IP per minute (default 120; 0: no limit).
    pub http_requests_per_ip_per_min: Option<u32>,
    /// Take the client IP from `X-Forwarded-For` (default false; only behind a proxy that sets it).
    pub trust_x_forwarded_for: Option<bool>,
}

/// `[node]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Where the identity, peers and held records live.
    pub state_dir: Option<PathBuf>,
}

/// `[overlay]`: the DSIP overlay (libp2p Kademlia).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySection {
    /// Listen multiaddrs; empty stays out of the overlay.
    pub listen: Option<Vec<String>>,
    /// Bootstrap multiaddrs with `/p2p/<PeerId>` (`/dns4/…` names let an operator rotate nodes).
    pub bootstrap: Option<Vec<String>>,
}

/// `[mainline]`: the BitTorrent Mainline DHT.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MainlineSection {
    /// Join it.
    pub enabled: Option<bool>,
    /// UDP port (0: any).
    pub port: Option<u16>,
    /// Store and answer for others, not only query.
    pub server: Option<bool>,
    /// Bootstrap nodes (`host:port`); empty: the public ones.
    pub bootstrap: Option<Vec<String>>,
}

/// `[http]`: the hints API.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSection {
    /// Listen address.
    pub listen: Option<String>,
}

impl Config {
    /// Read and parse a config file.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }
}

/// The state directory's files.
#[derive(Debug, Clone)]
pub struct StateDir(pub PathBuf);

impl StateDir {
    /// Create the directory (and `pkarr/`) if needed.
    pub fn open(path: &Path) -> anyhow::Result<StateDir> {
        std::fs::create_dir_all(path.join("pkarr"))?;
        Ok(StateDir(path.to_path_buf()))
    }

    /// The overlay identity: a 32-byte seed, generated once, so the PeerId survives restarts.
    pub fn overlay_seed(&self) -> anyhow::Result<[u8; 32]> {
        let p = self.0.join("overlay.key");
        if let Ok(hex) = std::fs::read_to_string(&p) {
            let b: Vec<u8> = (0..32).filter_map(|i| u8::from_str_radix(hex.trim().get(2 * i..2 * i + 2)?, 16).ok()).collect();
            return b.try_into().map_err(|_| anyhow::anyhow!("{}: not 32 bytes of hex", p.display()));
        }
        // a fresh Ed25519 key from libp2p (the OS's CSPRNG); its secret is the seed kept from now on
        let kp = libp2p::identity::Keypair::generate_ed25519().try_into_ed25519().map_err(|e| anyhow::anyhow!("{e}"))?;
        let seed: [u8; 32] = kp.secret().as_ref().try_into().map_err(|_| anyhow::anyhow!("ed25519 secret"))?;
        let tmp = p.with_extension("tmp");
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            // the node's signing identity: readable by its owner only, from the first byte written
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(seed.iter().map(|b| format!("{b:02x}")).collect::<String>().as_bytes())?;
        }
        std::fs::rename(&tmp, &p)?;
        Ok(seed)
    }

    /// Learned overlay peers.
    pub fn overlay_peers(&self) -> PathBuf {
        self.0.join("overlay-peers")
    }

    /// Held overlay records.
    pub fn overlay_records(&self) -> PathBuf {
        self.0.join("overlay-records.jsonl")
    }

    /// Mainline routing nodes, the next start's extra bootstrap.
    pub fn mainline_nodes(&self) -> PathBuf {
        self.0.join("mainline-nodes")
    }

    /// This node's public IPv4 address as the Mainline DHT last saw it, for a BEP 42 node id at the next start.
    pub fn mainline_public_ip(&self) -> PathBuf {
        self.0.join("mainline-public-ip")
    }

    /// The file holding the Pkarr packet for `z32`.
    pub fn pkarr(&self, z32: &str) -> PathBuf {
        self.0.join("pkarr").join(z32)
    }

    /// Every held Pkarr packet on disk, as (z32, bytes).
    pub fn pkarr_all(&self) -> Vec<(String, Vec<u8>)> {
        std::fs::read_dir(self.0.join("pkarr"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Some((e.file_name().into_string().ok()?, std::fs::read(e.path()).ok()?)))
            .filter(|(name, _)| !name.ends_with(".tmp"))
            .collect()
    }
}

/// Write via a temporary file and a rename, so a crash never leaves half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}
