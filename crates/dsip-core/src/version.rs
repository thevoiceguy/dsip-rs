//! Version and extension negotiation.
//!
//! Spec: §11.1 (core version fields), §11.2 (compatibility rules), §11.3
//! (version error reason tokens).

use serde_json::Value;

use crate::verdict::{RejectCode, Verdict};

/// What this endpoint supports.
///
/// Spec: §11.2 — "a responder must indicate the selected mutually supported version."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supported {
    /// Core version, e.g. `1.0`.
    pub core: String,
    /// Supported profile identifiers, e.g. `interactive-media/1.0`.
    pub profiles: Vec<String>,
    /// Supported extension identifiers.
    pub extensions: Vec<String>,
}

impl Default for Supported {
    fn default() -> Self {
        Supported { core: "1.0".into(), profiles: vec!["interactive-media/1.0".into()], extensions: vec![] }
    }
}

impl Supported {
    /// Everything this implementation speaks: both v1.0 profiles (provenance is a core
    /// message since v0.7; no extension id).
    /// Live endpoints and relays use this; the vectors pin negotiation with explicit contexts.
    pub fn all_known() -> Supported {
        Supported {
            core: "1.0".into(),
            profiles: vec!["interactive-media/1.0".into(), "verified-broadcast/1.0".into()],
            extensions: vec![],
        }
    }

    /// From the vector `context.supported` shape.
    pub fn from_json(v: Option<&Value>) -> Supported {
        let Some(v) = v else { return Supported::default() };
        let strs = |k: &str| {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default()
        };
        Supported {
            core: v.get("core").and_then(Value::as_str).unwrap_or("1.0").to_string(),
            profiles: strs("profiles"),
            extensions: strs("extensions"),
        }
    }

    fn knows(&self, id: &str) -> bool {
        self.profiles.iter().any(|p| p == id) || self.extensions.iter().any(|e| e == id)
    }
}

fn parse_version(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.split_once('.')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Stage 12: apply the §11.2 compatibility rules to a payload's `dsip` block.
///
/// A malformed block is left to the schema stage (accept here).
pub fn check_version(payload: &Value, supported: &Supported) -> Verdict {
    let Some(blk) = payload.get("dsip").and_then(Value::as_object) else { return Verdict::accept() };
    let (Some(core), Some(min_core), Some(mine)) = (
        blk.get("core").and_then(Value::as_str).and_then(parse_version),
        blk.get("min_core").and_then(Value::as_str).and_then(parse_version),
        parse_version(&supported.core),
    ) else {
        return Verdict::accept();
    };
    // §11.2: major versions are incompatible by default; the sender's floor must not exceed ours.
    if core.0 != mine.0 || min_core > mine {
        return Verdict::reject_with(RejectCode::VersionUnsupported, "session.unsupported-core-version");
    }
    if let Some(crit) = blk.get("critical").and_then(Value::as_array) {
        for c in crit.iter().filter_map(Value::as_str) {
            if !supported.knows(c) {
                // §11.2: unknown critical extensions require rejection
                return Verdict::reject_with(RejectCode::VersionUnsupported, "session.unsupported-critical-extension");
            }
        }
    }
    if let Some(profiles) = blk.get("profiles").and_then(Value::as_array) {
        if !profiles.is_empty() && !profiles.iter().filter_map(Value::as_str).any(|p| supported.knows(p)) {
            return Verdict::reject_with(RejectCode::VersionUnsupported, "session.unsupported-profile-version");
        }
    }
    Verdict::accept()
}

/// The version block this endpoint stamps on outbound payloads.
pub fn version_block(supported: &Supported, profiles: &[&str]) -> Value {
    serde_json::json!({
        "core": supported.core, "min_core": supported.core,
        "profiles": profiles, "extensions": [], "critical": []
    })
}
