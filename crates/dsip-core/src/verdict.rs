//! Verdicts and implementation-neutral rejection codes.
//!
//! Spec: none (infrastructure) — the codes are defined by `impl/vectors/README.md`
//! so that Python and Rust classify every rejection identically. Where the spec
//! assigns a reason token to a condition (§15), [`Verdict::reason`] carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why an envelope or payload was rejected. Serialized in kebab-case to match the vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum RejectCode {
    FrameTooLarge,
    EnvelopeShape,
    HeaderInvalid,
    AlgUnsupported,
    KidInvalid,
    KidUnresolvable,
    SignatureInvalid,
    PayloadNotUtf8,
    PayloadNotJson,
    PayloadFloat,
    PayloadShape,
    SignerMismatch,
    DelegationInvalid,
    DelegationExpired,
    DelegationCapability,
    ExpiryOrder,
    ReplayWindow,
    Expired,
    DuplicateId,
    UlidIssuedAtMismatch,
    HelloRequired,
    VersionUnsupported,
    UnknownType,
    SchemaInvalid,
    SelectionNotSubset,
    SubscriptionLifetimeExceeded,
    IntroductionTooLarge,
    GrantUnknownIntroduction,
    HelloInReplyToMismatch,
    HintSubjectMismatch,
}

/// The outcome of a pipeline stage.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// `None` = accept.
    pub code: Option<RejectCode>,
    /// Reason token the implementation signals for this rejection, when the spec defines one.
    pub reason: Option<&'static str>,
    /// Human detail; never compared.
    pub detail: Option<String>,
    /// Accept-side extras (`type`, `signer`, `identity`, `effective`, `warnings`, …).
    pub extra: serde_json::Map<String, Value>,
}

impl Verdict {
    /// An accept with no extras.
    pub fn accept() -> Verdict {
        Verdict { code: None, reason: None, detail: None, extra: Default::default() }
    }

    /// A rejection.
    pub fn reject(code: RejectCode) -> Verdict {
        Verdict { code: Some(code), reason: None, detail: None, extra: Default::default() }
    }

    /// A rejection carrying a reason token.
    pub fn reject_with(code: RejectCode, reason: &'static str) -> Verdict {
        Verdict { code: Some(code), reason: Some(reason), detail: None, extra: Default::default() }
    }

    /// Attach human detail.
    pub fn detail(mut self, d: impl Into<String>) -> Verdict {
        self.detail = Some(d.into());
        self
    }

    /// Add an accept-side extra.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Verdict {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    /// Is this an accept?
    pub fn ok(&self) -> bool {
        self.code.is_none()
    }

    /// The comparable projection used by the vector runner (`expect` shape).
    pub fn to_expect(&self) -> Value {
        let mut m = serde_json::Map::new();
        match self.code {
            None => {
                m.insert("verdict".into(), "accept".into());
                for (k, v) in &self.extra {
                    m.insert(k.clone(), v.clone());
                }
            }
            Some(c) => {
                m.insert("verdict".into(), "reject".into());
                m.insert("code".into(), serde_json::to_value(c).expect("enum"));
                if let Some(r) = self.reason {
                    m.insert("reason".into(), r.into());
                }
            }
        }
        Value::Object(m)
    }
}

/// Early-return helper: `try_stage!(verdict)` returns the verdict from the enclosing fn if it rejects.
#[macro_export]
macro_rules! try_stage {
    ($v:expr) => {{
        let v = $v;
        if !v.ok() {
            return v;
        }
        v
    }};
}
