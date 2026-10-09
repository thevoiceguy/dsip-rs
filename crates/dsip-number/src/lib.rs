//! `dsip-number` — the DSIP Number Attestation Profile (draft `tn-binding/0.1`,
//! `v0.11/dsip-number-attestation-profile-v0.11-draft.md`, cited `N§n`). Pure: no network.
//!
//! Spec: sections owned by this crate — N§3.1 (the binding's format — [`parse_binding`]), N§3.2 (the STIR
//! certificate path and TNAuthList coverage — [`parse_tnauth`], [`covers`]), N§3.4 (the order of the checks —
//! [`verify`]).
//!
//! Impl (spec-gap 110): certificates are checked at the verification time, not at `iat`; every TNAuthList on the
//! path must cover the number; `iat` may be up to 300 s ahead of the clock; E.164 only. Every rule is pinned by
//! `impl/vectors/tn-binding/`; the Python reference is `impl/tools/dsipvec/tnbinding.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::HashSet;

use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{json, Map, Value};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{FromDer as _, X509Version};

/// The longest a binding may live: `exp − iat` (N§3.1), 7 days.
pub const LIFETIME_MAX: i64 = 604_800;
/// How far `iat` may be ahead of the verifier's clock (N§3.4 step 5, the §12.9 tolerance).
pub const IAT_TOLERANCE: i64 = 300;
/// The protected header's `typ` (N§3.1, N§9).
pub const TYP: &str = "dsip-tn-binding+jwt";

const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const TNAUTH: &str = "1.3.6.1.5.5.7.1.26";

/// A verification failure: the N§3.4 reason token (N§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reject(pub &'static str);

const MALFORMED: Reject = Reject("malformed");
const UNTRUSTED: Reject = Reject("untrusted-certificate");

/// The relying party's side of a verification: trust list, `x5u` contents, SPC lookup and status policy.
///
/// Spec: N§3.2, N§3.4 step 8.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// The STI-CA trust list: DER certificates.
    pub trust_anchors: Vec<Vec<u8>>,
    /// What each `x5u` URL serves (PEM text). A missing URL cannot be fetched.
    pub certificates: Map<String, Value>,
    /// The numbers (digits, no `+`) assigned to each Service Provider Code.
    pub spc_numbers: Map<String, Value>,
    /// Whether step 8 runs.
    pub require_status: bool,
    /// What each status URL answers (`good` or `revoked`). A missing URL does not answer.
    pub status: Map<String, Value>,
}

/// A verified binding: what a client may render (N§3.4, N§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The number, E.164.
    pub tn: String,
    /// The DID that uses it.
    pub did: String,
    /// The binding's `exp`.
    pub expires: i64,
    /// The leaf subject's first organizationName, else its first commonName.
    pub attested_by: Option<String>,
}

/// A parsed binding (N§3.1): the header and payload objects, the signing input, and the raw signature.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The payload.
    pub payload: Map<String, Value>,
    /// The JWS signing input: the header and payload segments as received, joined by `.`.
    pub signing_input: Vec<u8>,
    /// The decoded third segment.
    pub signature: Vec<u8>,
}

/// base64url without padding. Non-zero unused bits are accepted (RFC 4648 §3.5), as the README pins.
const B64U: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::RequireNone).with_decode_allow_trailing_bits(true),
);

/// Padded base64 (RFC 4648 alphabet, `=` padding), for PEM bodies and trust anchors. Non-zero unused bits are
/// accepted (RFC 4648 §3.5), as the README pins.
const PADDED: GeneralPurpose =
    GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true));

fn b64u(s: &str) -> Result<Vec<u8>, Reject> {
    if s.len() % 4 == 1 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(MALFORMED);
    }
    B64U.decode(s).map_err(|_| MALFORMED)
}

fn json_object(b: &[u8]) -> Result<Map<String, Value>, Reject> {
    let text = std::str::from_utf8(b).map_err(|_| MALFORMED)?;
    match dsip_core::webvh::ijson(text) {
        Some(Value::Object(m)) => Ok(m),
        _ => Err(MALFORMED),
    }
}

fn is_tn(s: &str) -> bool {
    let d = s.as_bytes();
    d.len() >= 3 && d.len() <= 16 && d[0] == b'+' && (b'1'..=b'9').contains(&d[1]) && d[2..].iter().all(u8::is_ascii_digit)
}

fn is_ulid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 26
        && (b'0'..=b'7').contains(&b[0])
        && b.iter().all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'L' | b'O' | b'U')))
}

fn int(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_i64)
}

/// Step 1: parse and shape-check a compact JWS binding.
///
/// Spec: N§3.1, N§3.4 step 1.
pub fn parse_binding(binding: &str) -> Result<Binding, Reject> {
    let parts: Vec<&str> = binding.split('.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Err(MALFORMED);
    }
    let (h, p, sig) = (b64u(parts[0])?, b64u(parts[1])?, b64u(parts[2])?);
    let (header, payload) = (json_object(&h)?, json_object(&p)?);
    let https = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| s.starts_with("https://"));
    let header_ok = header.get("alg") == Some(&json!("ES256"))
        && header.get("typ") == Some(&json!(TYP))
        && https(header.get("x5u"))
        && !header.contains_key("crit");
    let (iat, exp) = (int(payload.get("iat")), int(payload.get("exp")));
    let payload_ok = payload.get("tn").and_then(Value::as_str).is_some_and(is_tn)
        && payload.get("did").and_then(Value::as_str).is_some_and(|d| d.starts_with("did:"))
        && iat.is_some_and(|i| i >= 0)
        && matches!((iat, exp), (Some(i), Some(e)) if e > i)
        && payload.get("jti").and_then(Value::as_str).is_some_and(is_ulid)
        && (!payload.contains_key("status") || https(payload.get("status")));
    if !header_ok || !payload_ok {
        return Err(MALFORMED);
    }
    Ok(Binding { header, payload, signing_input: format!("{}.{}", parts[0], parts[1]).into_bytes(), signature: sig })
}

// --- strict DER, for TNAuthList ------------------------------------------------------------------------------

/// One TLV at the start of `b`: (tag, contents, rest). Definite, minimal lengths; single-byte tags.
fn der_read(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&l0, mut rest) = rest.split_first()?;
    let n = if l0 < 0x80 {
        l0 as usize
    } else {
        let k = (l0 & 0x7F) as usize;
        if k == 0 || k > 4 || rest.len() < k || rest[0] == 0 {
            return None;
        }
        let n = rest[..k].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        if n < 0x80 {
            return None;
        }
        rest = &rest[k..];
        n
    };
    (rest.len() >= n).then(|| (tag, &rest[..n], &rest[n..]))
}

fn der_one(b: &[u8], tag: u8) -> Option<&[u8]> {
    match der_read(b)? {
        (t, c, rest) if t == tag && rest.is_empty() => Some(c),
        _ => None,
    }
}

fn der_seq(mut c: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = vec![];
    while !c.is_empty() {
        let (t, v, rest) = der_read(c)?;
        out.push((t, v));
        c = rest;
    }
    Some(out)
}

/// One TNAuthList entry (RFC 8226 §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TnEntry {
    /// `[0]` ServiceProviderCode.
    Spc(String),
    /// `[1]` TelephoneNumberRange: start and count. A count beyond `u64` saturates: no number of 15 digits can tell.
    Range(String, u64),
    /// `[2]` TelephoneNumber.
    One(String),
}

fn tel_number(tag: u8, c: &[u8]) -> Option<String> {
    let ok = tag == 0x16 && (1..=15).contains(&c.len()) && c.iter().all(|x| x.is_ascii_digit() || *x == b'#' || *x == b'*');
    ok.then(|| String::from_utf8_lossy(c).into_owned())
}

fn der_count(ib: &[u8]) -> Option<u64> {
    let redundant = ib.len() > 1 && ((ib[0] == 0 && ib[1] < 0x80) || (ib[0] == 0xFF && ib[1] >= 0x80));
    if ib.is_empty() || redundant || ib[0] >= 0x80 {
        return None; // empty, non-minimal, or negative
    }
    let digits = ib.iter().skip_while(|&&x| x == 0).collect::<Vec<_>>();
    let n = if digits.len() > 8 { u64::MAX } else { digits.iter().fold(0u64, |a, &&x| (a << 8) | x as u64) };
    (n >= 2).then_some(n)
}

/// Decode a TNAuthList extension value: RFC 8226 §9 with EXPLICIT tags, strict DER, at least one entry.
///
/// Spec: N§3.2; README `tn-binding` step 2 ("a well-formed TNAuthList").
pub fn parse_tnauth(value: &[u8]) -> Option<Vec<TnEntry>> {
    let entries = der_seq(der_one(value, 0x30)?)?;
    if entries.is_empty() {
        return None;
    }
    entries
        .into_iter()
        .map(|(tag, c)| match tag {
            0xA0 => {
                let s = der_one(c, 0x16)?;
                (!s.is_empty() && s.is_ascii()).then(|| TnEntry::Spc(String::from_utf8_lossy(s).into_owned()))
            }
            0xA1 => match der_seq(der_one(c, 0x30)?)?.as_slice() {
                [(st, s), (0x02, n)] => Some(TnEntry::Range(tel_number(*st, s)?, der_count(n)?)),
                _ => None,
            },
            0xA2 => {
                let (t, n, rest) = der_read(c)?;
                if !rest.is_empty() {
                    return None;
                }
                Some(TnEntry::One(tel_number(t, n)?))
            }
            _ => None,
        })
        .collect()
}

/// Does a TNAuthList cover `d` (the number's digits, no `+`)?
///
/// Spec: N§3.2 ("Coverage"); README `tn-binding` step 4.
pub fn covers(entries: &[TnEntry], d: &str, spc_numbers: &Map<String, Value>) -> bool {
    entries.iter().any(|e| match e {
        TnEntry::One(n) => n == d,
        TnEntry::Range(start, count) => {
            // Same length and all digits; both are at most 15 digits, so u64 holds them.
            start.len() == d.len()
                && start.bytes().all(|b| b.is_ascii_digit())
                && match (start.parse::<u64>(), d.parse::<u64>()) {
                    (Ok(s), Ok(n)) => n >= s && n - s < *count,
                    _ => false,
                }
        }
        TnEntry::Spc(code) => spc_numbers.get(code).and_then(Value::as_array).is_some_and(|a| a.contains(&json!(d))),
    })
}

// --- certificates --------------------------------------------------------------------------------------------

struct Cert {
    der: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    tbs: Vec<u8>,
    sig: Vec<u8>,
    key: Option<VerifyingKey>,
    alg_ok: bool,
    not_before: i64,
    not_after: i64,
    ca: Option<(bool, Option<u32>)>,
    ku: Option<(bool, bool)>, // (digitalSignature, keyCertSign)
    unknown_critical: bool,
    tnauth: Option<Vec<TnEntry>>,
    attested_by: Option<String>,
}

impl Cert {
    fn parse(der: &[u8]) -> Option<Cert> {
        let (rest, c) = X509Certificate::from_der(der).ok()?;
        if !rest.is_empty() || c.version() != X509Version::V3 {
            return None;
        }
        // RFC 5280 §4.1.1.2: the tbsCertificate's `signature` is the outer signatureAlgorithm.
        let same_alg = |a: &x509_parser::x509::AlgorithmIdentifier, b: &x509_parser::x509::AlgorithmIdentifier| {
            a.algorithm == b.algorithm
                && match (&a.parameters, &b.parameters) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x.header.tag() == y.header.tag() && x.data == y.data,
                    _ => false,
                }
        };
        if !same_alg(&c.tbs_certificate.signature, &c.signature_algorithm) {
            return None;
        }
        // RFC 5280 §4.2: no extension twice.
        let mut seen = HashSet::new();
        if !c.extensions().iter().all(|e| seen.insert(e.oid.to_id_string())) {
            return None;
        }
        let spki = c.public_key();
        let p256 = spki.algorithm.algorithm.to_id_string() == EC_PUBLIC_KEY
            && spki.algorithm.parameters.as_ref().is_some_and(|p| p.header.tag().0 == 6 && p.data == PRIME256V1);
        // A P-256 key that does not decode is not a valid point: the certificate is unusable.
        let key = if p256 { Some(VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data).ok()?) } else { None };
        let (mut ca, mut ku, mut unknown_critical, mut tnauth) = (None, None, false, None);
        for e in c.extensions() {
            let oid = e.oid.to_id_string();
            match oid.as_str() {
                BASIC_CONSTRAINTS => {
                    let bc = c.basic_constraints().ok()??.value;
                    if !bc.ca && bc.path_len_constraint.is_some() {
                        return None; // RFC 5280 §4.2.1.9
                    }
                    ca = Some((bc.ca, bc.path_len_constraint));
                }
                KEY_USAGE => {
                    let k = c.key_usage().ok()??.value;
                    ku = Some((k.digital_signature(), k.key_cert_sign()));
                }
                TNAUTH => tnauth = Some(parse_tnauth(e.value)?),
                _ => unknown_critical |= e.critical,
            }
        }
        let attested_by = {
            let first = |want: &str| {
                c.subject().iter().flat_map(|rdn| rdn.iter()).find_map(|a| {
                    let v = a.attr_value();
                    let string = matches!(v.header.tag().0, 12 | 19);
                    // Bytes that are not UTF-8 are passed over, never shown lossily.
                    let text = std::str::from_utf8(v.data).ok().filter(|_| string);
                    text.filter(|_| a.attr_type().to_id_string() == want).map(str::to_string)
                })
            };
            first("2.5.4.10").or_else(|| first("2.5.4.3"))
        };
        Some(Cert {
            der: der.to_vec(),
            subject: c.subject().as_raw().to_vec(),
            issuer: c.issuer().as_raw().to_vec(),
            tbs: c.tbs_certificate.as_ref().to_vec(),
            sig: c.signature_value.data.to_vec(),
            key,
            alg_ok: c.signature_algorithm.algorithm.to_id_string() == ECDSA_SHA256
                && c.signature_algorithm.parameters.is_none(),
            not_before: c.validity().not_before.timestamp(),
            not_after: c.validity().not_after.timestamp(),
            ca,
            ku,
            unknown_critical,
            tnauth,
            attested_by,
        })
    }

    /// Does `issuer`'s key verify this certificate's signature (ECDSA P-256, SHA-256, DER signature)?
    fn signed_by(&self, issuer: &Cert) -> bool {
        match (&issuer.key, Signature::from_der(&self.sig)) {
            (Some(k), Ok(s)) => k.verify(&self.tbs, &s).is_ok(),
            _ => false,
        }
    }
}

/// The PEM blocks at `x5u`, leaf first. Any defect is `untrusted-certificate`.
fn load_chain(text: &str) -> Result<Vec<Cert>, Reject> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = vec![];
    let mut body: Option<String> = None;
    for line in text.split('\n') {
        match (&mut body, line.strip_suffix('\r').unwrap_or(line)) {
            (None, l) if l == BEGIN => body = Some(String::new()),
            (Some(_), l) if l == END => {
                let b = body.take().unwrap_or_default();
                let der = PADDED.decode(b).map_err(|_| UNTRUSTED)?;
                out.push(Cert::parse(&der).ok_or(UNTRUSTED)?);
            }
            (Some(b), l) => b.extend(l.chars().filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))),
            (None, _) => {}
        }
    }
    if body.is_some() || out.is_empty() {
        return Err(UNTRUSTED);
    }
    Ok(out)
}

/// Find a path that passes step 2: the chain up to the first anchor, or else the whole chain plus each qualifying
/// issuing anchor in trust-list order, the first whose path passes every check.
fn find_path(chain: Vec<Cert>, anchors: &[Cert], now: i64) -> Result<Vec<Cert>, Reject> {
    let anchor_ders: HashSet<&[u8]> = anchors.iter().map(|a| a.der.as_slice()).collect();
    let mut path = vec![];
    for c in chain {
        let is_anchor = anchor_ders.contains(c.der.as_slice());
        path.push(c);
        if is_anchor {
            check_path(&path, now)?;
            return Ok(path);
        }
    }
    let last = path.last().ok_or(UNTRUSTED)?;
    let qualifying: Vec<&Cert> = anchors.iter().filter(|a| a.subject == last.issuer && last.signed_by(a)).collect();
    for a in qualifying {
        path.push(Cert::parse(&a.der).ok_or(UNTRUSTED)?);
        if check_path(&path, now).is_ok() {
            return Ok(path);
        }
        path.pop();
    }
    Err(UNTRUSTED)
}

/// Step 2's per-path checks: links, algorithms, validity, extensions, CA rules, path length, leaf usage.
fn check_path(path: &[Cert], now: i64) -> Result<(), Reject> {
    let links = path.windows(2).all(|w| w[0].issuer == w[1].subject && w[0].signed_by(&w[1]));
    let each = path.iter().enumerate().all(|(p, c)| {
        let base = c.alg_ok && c.key.is_some() && c.not_before <= now && now <= c.not_after && !c.unknown_critical;
        let issuer_ok = p == 0
            || matches!(c.ca, Some((true, pl)) if pl.is_none_or(|l| (p as u64) - 1 <= l as u64))
                && c.ku.is_none_or(|(_, kcs)| kcs);
        base && issuer_ok
    });
    let leaf_ok = path[0].ku.is_none_or(|(ds, _)| ds);
    if links && each && leaf_ok {
        Ok(())
    } else {
        Err(UNTRUSTED)
    }
}

/// Verify a binding for `did`, in the N§3.4 order: the first failing step gives the reason.
///
/// Spec: N§3.4 (steps 1–8), N§3.1, N§3.2, N§3.3.
pub fn verify(binding: &str, did: &str, did_document: &Value, now: i64, policy: &Policy) -> Result<Verified, Reject> {
    // 1. malformed
    let b = parse_binding(binding)?;
    let p = &b.payload;
    // 2. untrusted-certificate
    let x5u = b.header["x5u"].as_str().unwrap_or_default();
    let text = policy.certificates.get(x5u).and_then(Value::as_str).ok_or(UNTRUSTED)?;
    let chain = load_chain(text)?;
    // An anchor that does not parse is ignored (README `trust_anchors`).
    let anchors: Vec<Cert> = policy.trust_anchors.iter().filter_map(|d| Cert::parse(d)).collect();
    let path = find_path(chain, &anchors, now)?;
    // 3. signature: raw r‖s, 0 < r, s < n (Signature::from_slice refuses the rest)
    let sig = (b.signature.len() == 64).then(|| Signature::from_slice(&b.signature).ok()).flatten();
    let key = path[0].key.as_ref().ok_or(UNTRUSTED)?;
    if !sig.is_some_and(|s| key.verify(&b.signing_input, &s).is_ok()) {
        return Err(Reject("signature"));
    }
    // 4. not-authorized-for-tn: the leaf's list, and every other list on the path (N§3.2 "Nested coverage")
    let tn = p["tn"].as_str().unwrap_or_default();
    let d = &tn[1..];
    let covered = |c: &Cert| c.tnauth.as_ref().is_none_or(|l| covers(l, d, &policy.spc_numbers));
    if path[0].tnauth.is_none() || !path.iter().all(covered) {
        return Err(Reject("not-authorized-for-tn"));
    }
    // 5. time (spec-gap 110: 7 days; the §12.9 300 s tolerance)
    let (iat, exp) = (p["iat"].as_i64().unwrap_or_default(), p["exp"].as_i64().unwrap_or_default());
    if exp - iat > LIFETIME_MAX {
        return Err(Reject("lifetime-too-long"));
    }
    if iat > now + IAT_TOLERANCE {
        return Err(Reject("not-yet-valid"));
    }
    if now >= exp {
        return Err(Reject("expired"));
    }
    // 6. did-mismatch
    let bound = p["did"].as_str().unwrap_or_default();
    if bound != did {
        return Err(Reject("did-mismatch"));
    }
    // 7. not-claimed-by-did (N§3.3)
    let claim = json!(format!("tel:{tn}"));
    let claimed = did_document.get("id") == Some(&json!(did))
        && did_document.get("alsoKnownAs").and_then(Value::as_array).is_some_and(|a| a.contains(&claim));
    if !did_document.is_object() || !claimed {
        return Err(Reject("not-claimed-by-did"));
    }
    // 8. status, by policy (§18.3)
    if policy.require_status {
        let answer = p.get("status").and_then(Value::as_str).and_then(|u| policy.status.get(u)).and_then(Value::as_str);
        match answer {
            Some("good") => {}
            Some("revoked") => return Err(Reject("revoked")),
            _ => return Err(Reject("status-unavailable")), // no answer, or one that is neither: fail closed
        }
    }
    Ok(Verified { tn: tn.to_string(), did: bound.to_string(), expires: exp, attested_by: path[0].attested_by.clone() })
}

/// Run one `tn-binding` vector: `{outcome: verified, …}` or `{outcome: rejected, reason}`.
///
/// Spec: none (infrastructure) — the README `tn-binding` vector contract around [`verify`].
pub fn run_vector(v: &Value) -> Value {
    let (c, i) = (&v["context"], &v["input"]);
    let map = |k: &str| c[k].as_object().cloned().unwrap_or_default();
    let anchors = c["trust_anchors"].as_array().map(|a| a.iter().filter_map(|x| PADDED.decode(x.as_str()?).ok()).collect());
    let policy = Policy {
        trust_anchors: anchors.unwrap_or_default(),
        certificates: map("certificates"),
        spc_numbers: map("spc_numbers"),
        require_status: c["require_status"].as_bool().unwrap_or(false),
        status: map("status"),
    };
    let r = verify(
        i["binding"].as_str().unwrap_or_default(),
        i["did"].as_str().unwrap_or_default(),
        &i["did_document"],
        i["now"].as_i64().unwrap_or_default(),
        &policy,
    );
    match r {
        Ok(ok) => json!({"outcome": "verified", "tn": ok.tn, "did": ok.did, "expires": ok.expires, "attested_by": ok.attested_by}),
        Err(Reject(reason)) => json!({"outcome": "rejected", "reason": reason}),
    }
}
