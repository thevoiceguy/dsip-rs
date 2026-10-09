//! `dsip-number` — the DSIP Number Attestation Profile (draft `tn-binding/0.1`,
//! `v0.11/dsip-number-attestation-profile-v0.11-draft.md`, cited `N§n`). Pure: no network.
//!
//! Spec: sections owned by this crate — N§3.1 (the binding's format — [`parse_binding`]), N§3.2 (the STIR
//! certificate path and TNAuthList coverage — [`parse_tnauth`], [`covers`]), N§3.4 (the order of the checks —
//! [`verify`]), N§4 ([`check_claim`]), N§5 ([`identity_change`]), N§6–N§7 ([`store`], [`select`]), and the
//! gateway's side — N§4.1 ([`assert_number`]: a bound number carried to the PSTN under the gateway's STIR
//! certificate), N§6.1 ([`route`]: a dialled number to the DSIP identity it reaches), G§5 ([`verify_passport`]: a
//! PSTN caller's SHAKEN PASSporT, RFC 8224 §6.2).
//!
//! Impl (spec-gap 110): certificates are checked at the verification time, not at `iat`; every TNAuthList on the
//! path must cover the number; `iat` may be up to 300 s ahead of the clock; E.164 only. Every rule is pinned by
//! `impl/vectors/tn-binding/`; the Python reference is `impl/tools/dsipvec/tnbinding.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::HashSet;

use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use std::collections::BTreeMap;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey as _;
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

impl Policy {
    /// Read a policy from its JSON form, the shape of a `tn-binding` vector's context: `trust_anchors` (padded base64
    /// DER; an entry that is not is ignored), `certificates`, `spc_numbers`, `require_status`, `status`.
    ///
    /// Spec: none (infrastructure) — the README `tn-binding` context.
    pub fn from_json(c: &Value) -> Policy {
        let map = |k: &str| c[k].as_object().cloned().unwrap_or_default();
        let anchors = c["trust_anchors"].as_array().into_iter().flatten().filter_map(|x| PADDED.decode(x.as_str()?).ok());
        Policy {
            trust_anchors: anchors.collect(),
            certificates: map("certificates"),
            spc_numbers: map("spc_numbers"),
            require_status: c["require_status"].as_bool().unwrap_or(false),
            status: map("status"),
        }
    }
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

/// Step 2: the path from what `x5u` serves to a trust anchor, checked at `now`.
fn cert_path(x5u: Option<&str>, now: i64, policy: &Policy) -> Result<Vec<Cert>, Reject> {
    let text = x5u.and_then(|u| policy.certificates.get(u)).and_then(Value::as_str).ok_or(UNTRUSTED)?;
    let chain = load_chain(text)?;
    // An anchor that does not parse is ignored (README `trust_anchors`).
    let anchors: Vec<Cert> = policy.trust_anchors.iter().filter_map(|d| Cert::parse(d)).collect();
    find_path(chain, &anchors, now)
}

/// Step 3: the leaf key verifies the raw r‖s signature (0 < r, s < n: `Signature::from_slice` refuses the rest)
/// over the signing input.
fn check_signature(path: &[Cert], signing_input: &[u8], signature: &[u8]) -> Result<(), Reject> {
    let sig = (signature.len() == 64).then(|| Signature::from_slice(signature).ok()).flatten();
    let key = path[0].key.as_ref().ok_or(UNTRUSTED)?;
    if sig.is_some_and(|s| key.verify(signing_input, &s).is_ok()) {
        Ok(())
    } else {
        Err(Reject("signature"))
    }
}

/// Step 4: the leaf has a TNAuthList, and every TNAuthList on the path covers `d` (the number without its `+`;
/// N§3.2 "Nested coverage").
fn check_coverage(path: &[Cert], d: &str, policy: &Policy) -> Result<(), Reject> {
    let covered = |c: &Cert| c.tnauth.as_ref().is_none_or(|l| covers(l, d, &policy.spc_numbers));
    if path[0].tnauth.is_none() || !path.iter().all(covered) {
        return Err(Reject("not-authorized-for-tn"));
    }
    Ok(())
}

/// Steps 1–5: everything a party can check without resolving the DID — what a `dsip-node` checks before it stores
/// (README `check: "store"`). Returns the parsed binding and who attested it.
///
/// Spec: N§3.4 steps 1–5, N§6 (route 1).
pub fn verify_offline(binding: &str, now: i64, policy: &Policy) -> Result<(Binding, Option<String>), Reject> {
    // 1. malformed
    let b = parse_binding(binding)?;
    let p = &b.payload;
    // 2. untrusted-certificate
    let path = cert_path(b.header["x5u"].as_str(), now, policy)?;
    // 3. signature
    check_signature(&path, &b.signing_input, &b.signature)?;
    // 4. not-authorized-for-tn
    let tn = p["tn"].as_str().unwrap_or_default();
    check_coverage(&path, &tn[1..], policy)?;
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
    let attested_by = path[0].attested_by.clone();
    Ok((b, attested_by))
}

/// Verify a binding for `did`, in the N§3.4 order: the first failing step gives the reason.
///
/// Spec: N§3.4 (steps 1–8), N§3.1, N§3.2, N§3.3.
pub fn verify(binding: &str, did: &str, did_document: &Value, now: i64, policy: &Policy) -> Result<Verified, Reject> {
    let (b, attested_by) = verify_offline(binding, now, policy)?;
    let p = &b.payload;
    let tn = p["tn"].as_str().unwrap_or_default();
    let exp = p["exp"].as_i64().unwrap_or_default();
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
    Ok(Verified { tn: tn.to_string(), did: bound.to_string(), expires: exp, attested_by })
}

/// How many bindings a node holds per number (README `check: "store"`).
pub const HELD_MAX: usize = 4;

/// A node's answer to `PUT /dsip/v1/tn/<tn>` (N§6 route 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    /// Stored: the new held set, newest `iat` first, then by binding text.
    Stored(Vec<String>),
    /// Not stored: `same`, `older` or `full`.
    Kept(&'static str),
    /// Refused: `bad-number`, a step 1–5 reason, or `tn-mismatch`.
    Rejected(&'static str),
}

fn payload_of(binding: &str) -> Value {
    binding.split('.').nth(1).and_then(|p| B64U.decode(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn iat_of(binding: &str) -> i64 {
    payload_of(binding)["iat"].as_i64().unwrap_or_default()
}

fn held_order(mut held: Vec<String>) -> Vec<String> {
    held.sort_by(|a, b| iat_of(b).cmp(&iat_of(a)).then_with(|| a.as_bytes().cmp(b.as_bytes())));
    held
}

/// The held bindings still live at `now` (`now < exp`), in their order.
///
/// Spec: N§6 (route 1: a node serves the unexpired held set).
pub fn live(held: &[String], now: i64) -> Vec<String> {
    held.iter().filter(|h| held_payload(h).is_some_and(|p| p["exp"].as_i64().is_some_and(|e| now < e))).cloned().collect()
}

/// A held entry's payload, when it reads: three segments, the second an I-JSON object with a string `did` and integer
/// `iat` and `exp`. The header and signature are not looked at; an entry that does not read is dropped.
fn held_payload(h: &str) -> Option<Value> {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let p = json_object(&b64u(parts[1]).ok()?).ok()?;
    let ok = p.get("did").is_some_and(Value::is_string) && p.get("iat").is_some_and(Value::is_i64) && p.get("exp").is_some_and(Value::is_i64);
    ok.then_some(Value::Object(p))
}

/// A node's verify-before-store for a number binding: steps 1–5 (a node resolves no DIDs), the path's number, then
/// at most [`HELD_MAX`] live bindings per number, one per DID, the newest kept.
///
/// Spec: N§6 (route 1); Impl (spec-gap 110 H): the set rules are the README's `check: "store"`.
pub fn store(tn: &str, binding: &str, held: &[String], now: i64, policy: &Policy) -> StoreOutcome {
    if !is_tn(tn) {
        return StoreOutcome::Rejected("bad-number");
    }
    let (b, _) = match verify_offline(binding, now, policy) {
        Ok(v) => v,
        Err(Reject(r)) => return StoreOutcome::Rejected(r),
    };
    if b.payload["tn"].as_str() != Some(tn) {
        return StoreOutcome::Rejected("tn-mismatch");
    }
    let (did, iat) = (b.payload["did"].as_str().unwrap_or_default(), b.payload["iat"].as_i64().unwrap_or_default());
    let live = live(held, now);
    let without = |x: &str| live.iter().filter(|h| h.as_str() != x).cloned().chain([binding.to_string()]).collect();
    if let Some(h) = live.iter().find(|h| payload_of(h)["did"].as_str() == Some(did)) {
        return if h == binding {
            StoreOutcome::Kept("same")
        } else if iat > iat_of(h) {
            StoreOutcome::Stored(held_order(without(h)))
        } else {
            StoreOutcome::Kept("older")
        };
    }
    if live.len() < HELD_MAX {
        return StoreOutcome::Stored(held_order(without("")));
    }
    let low = live.iter().map(|h| iat_of(h)).min().unwrap_or_default();
    let victim = live.iter().filter(|h| iat_of(h) == low).max_by(|a, b| a.as_bytes().cmp(b.as_bytes())).cloned().unwrap_or_default();
    if iat > low {
        StoreOutcome::Stored(held_order(without(&victim)))
    } else {
        StoreOutcome::Kept("full")
    }
}

/// The number's DID, chosen from the bindings a lookup returned (N§6, N§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The winner's DID.
    pub did: String,
    /// Who attested the winner.
    pub attested_by: Option<String>,
    /// The winner's `iat`.
    pub issued: i64,
    /// Other DIDs that also hold verified bindings for the number, sorted: a port in progress, or a hijack.
    pub others: Vec<String>,
}

/// Verify every returned binding fully, each against its own DID and that DID's document, and pick the winner:
/// the greatest `iat`, then the smallest binding text.
///
/// Spec: N§6, N§7 (two verified bindings: the newer `iat` wins, and the client says so).
pub fn select(tn: &str, bindings: &[Value], documents: &Map<String, Value>, now: i64, policy: &Policy) -> Option<Selected> {
    let mut verified: Vec<(i64, &str, Verified)> = vec![];
    for b in bindings.iter().filter_map(Value::as_str) {
        let p = payload_of(b);
        let Some(did) = p["did"].as_str() else { continue };
        let doc = documents.get(did).cloned().unwrap_or(Value::Null);
        if let Ok(v) = verify(b, did, &doc, now, policy) {
            if v.tn == tn {
                verified.push((p["iat"].as_i64().unwrap_or_default(), b, v));
            }
        }
    }
    let (issued, _, win) = verified.iter().min_by(|x, y| y.0.cmp(&x.0).then_with(|| x.1.as_bytes().cmp(y.1.as_bytes())))?.clone();
    let mut others: Vec<String> = verified.iter().map(|v| v.2.did.clone()).filter(|d| *d != win.did).collect();
    others.sort();
    others.dedup();
    Some(Selected { did: win.did, attested_by: win.attested_by, issued, others })
}

/// What a client does with a `tel` claim carrying a binding (N§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Not a `tel` claim with a `binding`: not this rule's (a gateway's G§5 claim renders through `dsip_core::trust`).
    Ignored,
    /// Verified: the line to show (§18.1), the binding's `iat` and `exp`.
    Attested {
        /// `<tn> · number attested by <issuer> for this identity`.
        line: String,
        /// The binding's `iat`.
        issued: i64,
        /// The binding's `exp`.
        expires: i64,
        /// Who attested it (the N§3.4 `attested_by`), for the N§5 warning.
        attested_by: Option<String>,
    },
    /// Dropped: the reason, and `<number> (unverified)` when the claimed number is E.164 (§18.2).
    Dropped {
        /// The first failing step's reason, `malformed` for a non-string binding, or `number-mismatch`.
        reason: &'static str,
        /// What may still be shown, marked.
        line: Option<String>,
    },
}

/// Check a `tel` claim from an invite's `identity.claims` against the envelope's verified signing identity.
///
/// Spec: N§4 (the claim, its rendering, a failed claim dropped), §18.1, §18.2.
pub fn check_claim(claim: &Value, identity: &str, did_document: &Value, now: i64, policy: &Policy) -> ClaimOutcome {
    // A string `verifier` makes it a gateway's claim (G§5), rendered by dsip_core::trust, even with a `binding`.
    let is_binding_claim = claim.get("type").and_then(Value::as_str) == Some("tel")
        && claim.get("binding").is_some()
        && !claim.get("verifier").is_some_and(Value::is_string);
    if !is_binding_claim {
        return ClaimOutcome::Ignored;
    }
    let number = claim.get("number").and_then(Value::as_str);
    let line = number.filter(|n| is_tn(n)).map(|n| format!("{n} (unverified)"));
    let Some(binding) = claim["binding"].as_str() else {
        return ClaimOutcome::Dropped { reason: "malformed", line };
    };
    match verify(binding, identity, did_document, now, policy) {
        Err(Reject(reason)) => ClaimOutcome::Dropped { reason, line },
        Ok(v) if number != Some(v.tn.as_str()) => ClaimOutcome::Dropped { reason: "number-mismatch", line },
        Ok(v) => {
            let by = v.attested_by.as_ref().map(|b| format!(" by {b}")).unwrap_or_default();
            let issued = parse_binding(binding).ok().and_then(|b| b.payload["iat"].as_i64()).unwrap_or_default();
            let line = format!("{} · number attested{by} for this identity", v.tn);
            ClaimOutcome::Attested { line, issued, expires: v.expires, attested_by: v.attested_by }
        }
    }
}

/// A stored contact: a name, the DID the user knows them by, and their numbers (E.164).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The name the user gave them.
    pub name: String,
    /// Their DID.
    pub did: String,
    /// Their numbers.
    pub numbers: Vec<String>,
}

/// N§5: when a verified number now belongs to another identity than the stored contact listing it, the warning to
/// show; `None` when no contact lists it or one listing it has the attested DID.
///
/// Spec: N§5.
pub fn identity_change(contacts: &[Contact], tn: &str, did: &str, attested_by: Option<&str>, issued: i64) -> Option<String> {
    let listing: Vec<&Contact> = contacts.iter().filter(|c| c.numbers.iter().any(|n| n == tn)).collect();
    if listing.iter().any(|c| c.did == did) {
        return None;
    }
    let c = listing.first()?;
    let by = attested_by.map(|b| format!(" by {b}")).unwrap_or_default();
    Some(format!(
        "{tn} now belongs to a different identity (number attested{by} since {}). Your contact \"{}\" is {}.",
        utc_date(issued),
        c.name,
        c.did
    ))
}

/// `YYYY-MM-DD` for Unix seconds, UTC (proleptic Gregorian; Howard Hinnant's civil-from-days).
fn utc_date(t: i64) -> String {
    let z = t.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

// --- gateways: a PSTN caller's PASSporT, a dialled number's identity, a bound number toward the PSTN ----------

/// RFC 8224 §6.2.1's freshness window for a PASSporT's `iat`, seconds (README `check: "passport"` rule 7).
pub const PASSPORT_FRESH: i64 = 60;

/// A number's canonical form (RFC 8224 §8.3 as the README pins it): a leading `+` and the visual separators `-`,
/// `.`, `(`, `)` and SP removed, leaving 1 to 15 digits. `None` when nothing matchable remains.
///
/// Spec: G§5 (`orig` must match the SIP `From`), RFC 8224 §8.3.
pub fn canonical_number(s: &str) -> Option<String> {
    let t: String = s.strip_prefix('+').unwrap_or(s).chars().filter(|c| !matches!(c, '-' | '.' | '(' | ')' | ' ')).collect();
    ((1..=15).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit())).then_some(t)
}

/// What a gateway learned from an inbound INVITE's `Identity` header: the facts the G§5 `tel` claim carries.
///
/// Spec: G§5 (`attestation` is the level of a verified header, `none` when absent; `verified` only when the
/// signature and chain verified and `orig` matches the `From`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportOutcome {
    /// `A`, `B` or `C`, or `none` when no PASSporT was accepted.
    pub attest: String,
    /// Whether it verified in full.
    pub verified: bool,
    /// Why not, when it did not (README `check: "passport"`; local, never on the wire).
    pub reason: Option<&'static str>,
}

/// An `Identity` header value split into its token, its parameters (names lower-cased) and the `info` URI.
fn parse_identity_header(value: &str) -> Result<(String, BTreeMap<String, String>, String), Reject> {
    let mut parts = value.split(';');
    let token = parts.next().unwrap_or_default().trim_matches([' ', '\t']).to_string();
    let mut params = BTreeMap::new();
    for part in parts {
        let (n, v) = part.split_once('=').ok_or(MALFORMED)?;
        let (n, v) = (n.trim_matches([' ', '\t']).to_ascii_lowercase(), v.trim_matches([' ', '\t']).to_string());
        if n.is_empty() || v.is_empty() || params.insert(n, v).is_some() {
            return Err(MALFORMED);
        }
    }
    let info = params.get("info").ok_or(MALFORMED)?;
    let uri = info.strip_prefix('<').and_then(|i| i.strip_suffix('>')).ok_or(MALFORMED)?.to_string();
    Ok((token, params, uri))
}

/// A SHAKEN PASSporT token (README `check: "passport"` rule 4): three segments, I-JSON objects, the header and
/// payload members RFC 8225 and RFC 8588 require.
fn parse_passport(token: &str) -> Result<Binding, Reject> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return Err(MALFORMED);
    }
    let header = json_object(&b64u(parts[0])?)?;
    let payload = json_object(&b64u(parts[1])?)?;
    let signature = b64u(parts[2])?;
    let x5u_ok = header.get("x5u").and_then(Value::as_str).is_some_and(|u| u.starts_with("https://"));
    if header.get("alg") != Some(&json!("ES256")) || header.get("typ") != Some(&json!("passport"))
        || header.get("ppt") != Some(&json!("shaken")) || !x5u_ok
    {
        return Err(MALFORMED);
    }
    let number = |v: Option<&Value>| v.and_then(Value::as_str).and_then(canonical_number).is_some();
    let attest_ok = matches!(payload.get("attest").and_then(Value::as_str), Some("A" | "B" | "C"));
    let orig_ok = payload.get("orig").is_some_and(|o| o.is_object() && number(o.get("tn")));
    let dest_ok = payload.get("dest").is_some_and(|d| {
        d.is_object() && d.get("tn").and_then(Value::as_array).is_some_and(|a| !a.is_empty() && a.iter().all(|t| number(Some(t))))
    });
    if !attest_ok || !orig_ok || !dest_ok || !int(payload.get("iat")).is_some_and(|i| i >= 0) {
        return Err(MALFORMED);
    }
    Ok(Binding { header, payload, signing_input: format!("{}.{}", parts[0], parts[1]).into_bytes(), signature })
}

/// Verify the `Identity` header of an inbound SIP INVITE: the facts behind the gateway's G§5 `tel` claim.
///
/// Spec: G§5, N§4.1 (inbound), RFC 8224 §6.2, RFC 8588. Impl (spec-gap 110 I): the README `check: "passport"`
/// order — absent, malformed parameters, unsupported `alg`/`ppt`, malformed token, `orig` against the `From`
/// (discarded whole, G§5), then with the level kept: `dest`, freshness (60 s), `x5u` against `info`, the certificate
/// path, the signature, and TNAuthList coverage for `A` only (`B` and `C` attest no authority over the number).
pub fn verify_passport(identity: Option<&str>, from_tn: &str, to_tn: &str, now: i64, policy: &Policy) -> PassportOutcome {
    let none = |reason| PassportOutcome { attest: "none".into(), verified: false, reason: Some(reason) };
    let Some(value) = identity else { return none("no-identity-header") };
    let Ok((token, params, info)) = parse_identity_header(value) else { return none("malformed") };
    if params.get("alg").is_some_and(|a| a != "ES256") || params.get("ppt").is_some_and(|p| p != "shaken") {
        return none("unsupported"); // RFC 8224 §6.2.3: a header the verifier cannot process is ignored
    }
    let Ok(pp) = parse_passport(&token) else { return none("malformed") };
    let orig = canonical_number(pp.payload["orig"]["tn"].as_str().unwrap_or_default()).unwrap_or_default();
    if canonical_number(from_tn).as_deref() != Some(orig.as_str()) {
        return none("orig-mismatch"); // G§5: it attests some other call
    }
    let attest = pp.payload["attest"].as_str().unwrap_or_default().to_string();
    let un = |reason| PassportOutcome { attest: attest.clone(), verified: false, reason: Some(reason) };
    let to = canonical_number(to_tn);
    let dests = pp.payload["dest"]["tn"].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(canonical_number);
    if !dests.into_iter().any(|d| Some(d) == to) {
        return un("dest-mismatch");
    }
    if (now - int(pp.payload.get("iat")).unwrap_or_default()).abs() > PASSPORT_FRESH {
        return un("stale");
    }
    if pp.header["x5u"].as_str() != Some(info.as_str()) {
        return un("x5u-mismatch");
    }
    let checks = || -> Result<(), Reject> {
        let path = cert_path(pp.header["x5u"].as_str(), now, policy)?;
        check_signature(&path, &pp.signing_input, &pp.signature)?;
        if attest == "A" {
            check_coverage(&path, &orig, policy)?;
        }
        Ok(())
    };
    match checks() {
        Ok(()) => PassportOutcome { attest, verified: true, reason: None },
        Err(Reject(r)) => un(r),
    }
}

/// Where an inbound PSTN call to a number goes (N§6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The operator's own table named it.
    Configured(String),
    /// The N§6 lookup found a verified binding (N§7 chose among several).
    Binding(Selected),
    /// Nowhere: the gateway refuses `identity.unknown` (404, Q.850 cause 1; G§4.2).
    None,
}

/// Resolve a dialled number to the DSIP identity to invite: the operator's table first, then the bindings an N§6
/// route 1 lookup returned (`select`), else nothing.
///
/// Spec: N§6.1, G§3.2. Impl (spec-gap 110 I): the table is the operator's statement about its own trunk, and a
/// verified binding never overrides it; `to_tn` must be E.164 for the lookup.
pub fn route(to_tn: &str, configured: &Value, bindings: &[Value], documents: &Map<String, Value>, now: i64, policy: &Policy) -> Route {
    if let Some(did) = configured.get(to_tn).and_then(Value::as_str) {
        return Route::Configured(did.to_string());
    }
    if is_tn(to_tn) {
        if let Some(s) = select(to_tn, bindings, documents, now, policy) {
            return Route::Binding(s);
        }
    }
    Route::None
}

/// The gateway's own STIR certificate: the `x5u` its chain is served at, and the leaf's private key (PKCS#8 PEM).
///
/// Spec: N§4.1 (an RFC 9060 delegate certificate normally, G§11 path c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCert {
    /// Where the chain is served; the PASSporT's `x5u` and the `Identity` header's `info`.
    pub x5u: String,
    /// The leaf's private key, a PKCS#8 PEM.
    pub key_pem: String,
}

impl GatewayCert {
    /// From a `tn-binding` context's `gateway` member: `None` unless it is an object with string `x5u` and `key`.
    ///
    /// Spec: none (infrastructure) — the README `check: "assert"` context.
    pub fn from_json(v: &Value) -> Option<GatewayCert> {
        let (x5u, key) = (v.get("x5u")?.as_str()?, v.get("key")?.as_str()?);
        Some(GatewayCert { x5u: x5u.to_string(), key_pem: key.to_string() })
    }
}

/// A signed SHAKEN PASSporT: the decoded header and claims, and the compact JWS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passport {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The claims.
    pub claims: Map<String, Value>,
    /// The compact JWS.
    pub token: String,
}

impl Passport {
    /// The RFC 8224 `Identity` header value: `<token>;info=<x5u>;alg=ES256;ppt=shaken`.
    pub fn identity_header(&self) -> String {
        format!("{};info=<{}>;alg=ES256;ppt=shaken", self.token, self.header["x5u"].as_str().unwrap_or_default())
    }
}

/// What a gateway presents toward the PSTN for a DSIP caller (N§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The SIP `From` user: the caller's attested number, or `None` for the gateway's own identity.
    pub from: Option<String>,
    /// The PASSporT, when the gateway may sign one.
    pub passport: Option<Passport>,
    /// Why there is no PASSporT (README `check: "assert"`): G§7's `identity-not-assertable`.
    pub reason: Option<&'static str>,
}

fn sorted_json(m: &Map<String, Value>) -> Vec<u8> {
    // RFC 8225 §9: members in lexicographic order, no whitespace (nested objects here have one member each)
    let b: BTreeMap<&String, &Value> = m.iter().collect();
    serde_json::to_vec(&b).unwrap_or_default()
}

/// Carry a DSIP caller's bound number to the PSTN: the first attested `tel` claim gives the `From`, and the gateway
/// signs a SHAKEN PASSporT (`attest: A`) when its own certificate chains, covers the number, and matches its key.
///
/// Spec: N§4 ("a gateway … may assert the `From` number only under a STIR certificate that covers it"), N§4.1,
/// G§7 (`identity-not-assertable` otherwise), G§11 path (c). Impl (spec-gap 110 A and I): the README
/// `check: "assert"` order — the claim, `bad-destination`, `no-certificate`, `untrusted-certificate`,
/// `not-authorized-for-tn`, `key-mismatch`; an attested number is presented unsigned (path b) when the gateway cannot
/// sign; the level is `A` only, never `B`.
#[allow(clippy::too_many_arguments)]
pub fn assert_number(
    claims: &[Value],
    identity: &str,
    did_document: &Value,
    to_tn: &str,
    now: i64,
    origid: &str,
    policy: &Policy,
    gateway: Option<&GatewayCert>,
) -> Assertion {
    let (mut number, mut dropped) = (None, None);
    for c in claims {
        match check_claim(c, identity, did_document, now, policy) {
            ClaimOutcome::Attested { .. } => {
                number = c["number"].as_str().map(String::from);
                break;
            }
            ClaimOutcome::Dropped { reason, .. } => dropped = dropped.or(Some(reason)),
            ClaimOutcome::Ignored => {}
        }
    }
    let Some(number) = number else {
        return Assertion { from: None, passport: None, reason: Some(dropped.unwrap_or("no-binding")) };
    };
    let no = |reason| Assertion { from: Some(number.clone()), passport: None, reason: Some(reason) };
    if !is_tn(to_tn) {
        return no("bad-destination");
    }
    let Some(gw) = gateway else { return no("no-certificate") };
    let Ok(secret) = p256::SecretKey::from_pkcs8_pem(&gw.key_pem) else { return no("no-certificate") };
    let path = match cert_path(Some(&gw.x5u), now, policy) {
        Ok(p) => p,
        Err(Reject(r)) => return no(r),
    };
    if let Err(Reject(r)) = check_coverage(&path, &number[1..], policy) {
        return no(r);
    }
    let signing = SigningKey::from(&secret);
    if path[0].key.as_ref() != Some(signing.verifying_key()) {
        return no("key-mismatch");
    }
    let header = json!({"alg": "ES256", "ppt": "shaken", "typ": "passport", "x5u": gw.x5u});
    let claims = json!({"attest": "A", "dest": {"tn": [&to_tn[1..]]}, "iat": now, "orig": {"tn": &number[1..]}, "origid": origid});
    let (header, claims) = (header.as_object().cloned().unwrap_or_default(), claims.as_object().cloned().unwrap_or_default());
    let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let si = format!("{}.{}", enc(&sorted_json(&header)), enc(&sorted_json(&claims)));
    let sig: Signature = signing.sign(si.as_bytes()); // RFC 6979 nonces: the same input signs the same way
    let token = format!("{si}.{}", enc(&sig.to_bytes()));
    Assertion { from: Some(number), passport: Some(Passport { header, claims, token }), reason: None }
}


/// Run one `tn-binding` vector: `{outcome: verified, …}` or `{outcome: rejected, reason}`.
///
/// Spec: none (infrastructure) — the README `tn-binding` vector contract around [`verify`].
pub fn run_vector(v: &Value) -> Value {
    let (c, i) = (&v["context"], &v["input"]);
    if i["check"] == "contact" {
        let contacts: Vec<Contact> = i["contacts"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| Contact {
                name: c["name"].as_str().unwrap_or_default().to_string(),
                did: c["did"].as_str().unwrap_or_default().to_string(),
                numbers: c["numbers"].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(String::from)).collect(),
            })
            .collect();
        let a = &i["attested"];
        let w = identity_change(
            &contacts,
            a["tn"].as_str().unwrap_or_default(),
            a["did"].as_str().unwrap_or_default(),
            a["attested_by"].as_str(),
            a["issued"].as_i64().unwrap_or_default(),
        );
        return json!(w);
    }
    let policy = Policy::from_json(c);
    if i["check"] == "store" {
        let held: Vec<String> = i["held"].as_array().into_iter().flatten().filter_map(|h| h.as_str().map(String::from)).collect();
        let tn = i["tn"].as_str().unwrap_or_default();
        return match store(tn, i["binding"].as_str().unwrap_or_default(), &held, i["now"].as_i64().unwrap_or_default(), &policy) {
            StoreOutcome::Stored(h) => json!({"outcome": "stored", "held": h}),
            StoreOutcome::Kept(r) => json!({"outcome": "kept", "reason": r}),
            StoreOutcome::Rejected(r) => json!({"outcome": "rejected", "reason": r}),
        };
    }
    if i["check"] == "select" {
        let bindings = i["bindings"].as_array().cloned().unwrap_or_default();
        let docs = i["documents"].as_object().cloned().unwrap_or_default();
        let tn = i["tn"].as_str().unwrap_or_default();
        return match select(tn, &bindings, &docs, i["now"].as_i64().unwrap_or_default(), &policy) {
            None => json!({"outcome": "none"}),
            Some(s) => json!({"outcome": "found", "did": s.did, "attested_by": s.attested_by, "issued": s.issued, "others": s.others}),
        };
    }
    if i["check"] == "claim" {
        let ident = i["identity"].as_str().unwrap_or_default();
        return match check_claim(&i["claim"], ident, &i["did_document"], i["now"].as_i64().unwrap_or_default(), &policy) {
            ClaimOutcome::Ignored => json!({"outcome": "ignored"}),
            ClaimOutcome::Attested { line, issued, expires, .. } => {
                json!({"outcome": "attested", "line": line, "issued": issued, "expires": expires})
            }
            ClaimOutcome::Dropped { reason, line } => json!({"outcome": "dropped", "reason": reason, "line": line}),
        };
    }
    if i["check"] == "passport" {
        let (from, to) = (i["from_tn"].as_str().unwrap_or_default(), i["to_tn"].as_str().unwrap_or_default());
        let o = verify_passport(i["identity"].as_str(), from, to, i["now"].as_i64().unwrap_or_default(), &policy);
        return match o.reason {
            None => json!({"attest": o.attest, "verified": true}),
            Some(r) => json!({"attest": o.attest, "verified": false, "reason": r}),
        };
    }
    if i["check"] == "route" {
        let bindings = i["bindings"].as_array().cloned().unwrap_or_default();
        let docs = i["documents"].as_object().cloned().unwrap_or_default();
        let to = i["to_tn"].as_str().unwrap_or_default();
        return match route(to, &i["configured"], &bindings, &docs, i["now"].as_i64().unwrap_or_default(), &policy) {
            Route::Configured(did) => json!({"outcome": "configured", "did": did}),
            Route::Binding(s) => json!({"outcome": "binding", "did": s.did, "attested_by": s.attested_by, "issued": s.issued, "others": s.others}),
            Route::None => json!({"outcome": "none"}),
        };
    }
    if i["check"] == "assert" {
        let claims = i["claims"].as_array().cloned().unwrap_or_default();
        let gw = GatewayCert::from_json(&c["gateway"]);
        let a = assert_number(
            &claims,
            i["identity"].as_str().unwrap_or_default(),
            &i["did_document"],
            i["to_tn"].as_str().unwrap_or_default(),
            i["now"].as_i64().unwrap_or_default(),
            i["origid"].as_str().unwrap_or_default(),
            &policy,
            gw.as_ref(),
        );
        let passport = a.passport.map(|p| json!({"header": p.header, "claims": p.claims}));
        return match a.reason {
            None => json!({"from": a.from, "passport": passport, "assertable": true}),
            Some(r) => json!({"from": a.from, "passport": passport, "assertable": false, "reason": r}),
        };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The suite pins the signing input, not the signature; this pins that what `assert_number` signs is what
    /// `verify_passport` accepts (the far end of `demos/number-gateway-demo.sh`).
    #[test]
    fn asserted_passport_verifies_at_the_far_end() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/tn-binding/");
        let v: Value = serde_json::from_slice(&std::fs::read(format!("{dir}assert-signed.json")).unwrap()).unwrap();
        let (c, i) = (&v["context"], &v["input"]);
        let policy = Policy::from_json(c);
        let gw = GatewayCert::from_json(&c["gateway"]).unwrap();
        let claims = i["claims"].as_array().cloned().unwrap();
        let now = i["now"].as_i64().unwrap();
        let a = assert_number(&claims, i["identity"].as_str().unwrap(), &i["did_document"], i["to_tn"].as_str().unwrap(), now, "x", &policy, Some(&gw));
        let p = a.passport.expect("signed");
        assert_eq!(a.from.as_deref(), Some("+15551234567"));
        let o = verify_passport(Some(&p.identity_header()), "+15551234567", i["to_tn"].as_str().unwrap(), now, &policy);
        assert_eq!(o, PassportOutcome { attest: "A".into(), verified: true, reason: None });
        // and the same input signs the same way (RFC 6979), so the token is reproducible
        let again = assert_number(&claims, i["identity"].as_str().unwrap(), &i["did_document"], i["to_tn"].as_str().unwrap(), now, "x", &policy, Some(&gw));
        assert_eq!(again.passport.unwrap().token, p.token);
    }
}
