//! `dsip-kt` — the Alias Transparency Profile's building blocks (draft `alias-transparency/0.1`,
//! `v0.9/dsip-alias-transparency-profile-v0.9-draft.md`, cited `T§n`): KEYTRANS (draft-ietf-keytrans-protocol)
//! structures for suite `KT_128_SHA256_Ed25519` and contact-monitoring mode.
//!
//! Spec: sections owned by this crate — T§2 (suite 0x0002, mode 1, `validate_key`), T§3 (alias normalization),
//! T§5 (VrfInput, the VRF index — [`ecvrf_verify`], commitments, prefix and log tree hashing, the Configuration and
//! tree heads, the implicit search tree and binary ladder).
//!
//! Impl (spec-gap 104): ASCII-only alias normalization; VRF verification with `validate_key`; only suite 0x0002 and
//! mode 1 are accepted. Pinned by `impl/vectors/alias-transparency/`; the Python reference is
//! `impl/tools/dsipvec/kt.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};

/// The commitment key `Kc` (KEYTRANS §17.1): the 16 raw bytes.
pub const KC: [u8; 16] = [0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5];
const SUITE: u8 = 0x03; // ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5)

/// Decode a point per RFC 8032 §5.1.3: the encoding must be canonical (dalek accepts a non-canonical `y` and an
/// `x = 0` with the sign bit set, so the point is re-encoded and compared).
fn decode_point(b: &[u8]) -> Option<EdwardsPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    let p = CompressedEdwardsY(arr).decompress()?;
    (p.compress().0 == arr).then_some(p)
}

/// RFC 9381 §5.4.5 `validate_key`, list form: refuse the low-order encodings (sign bit ignored).
fn validate_key(pk: &[u8]) -> bool {
    let mut y = [0u8; 32];
    y.copy_from_slice(&pk[..32]);
    y[31] &= 0x7f;
    let p = |hex_le: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex::decode(hex_le).unwrap_or_default());
        out
    };
    // 0, 1, BAD_Y2, p − BAD_Y2, p − 1, p, p + 1 (RFC 9381 §5.4.5), little-endian
    let bad = [
        [0u8; 32],
        { let mut o = [0u8; 32]; o[0] = 1; o },
        p("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        p("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        p("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        p("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        p("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];
    !bad.contains(&y)
}

/// RFC 9381 §5.4.1.1 encode_to_curve, try-and-increment, salt = the public key's encoding.
fn encode_to_curve(salt: &[u8], alpha: &[u8]) -> Option<EdwardsPoint> {
    // the counter is one byte: exhausting it gives no point (README `alias-transparency`)
    for ctr in 0..=255u8 {
        let mut h = Sha512::new();
        h.update([SUITE, 0x01]);
        h.update(salt);
        h.update(alpha);
        h.update([ctr, 0x00]);
        let d = h.finalize();
        if let Some(p) = decode_point(&d[..32]) {
            let p = p.mul_by_cofactor();
            if !p.is_identity() {
                return Some(p);
            }
        }
    }
    None
}

fn challenge(points: &[&EdwardsPoint]) -> [u8; 16] {
    let mut h = Sha512::new();
    h.update([SUITE, 0x02]);
    for p in points {
        h.update(p.compress().0);
    }
    h.update([0x00]);
    let d = h.finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&d[..16]);
    c
}

/// ECVRF-EDWARDS25519-SHA512-TAI verification with `validate_key = TRUE`: the 64-byte `beta`, or `None`.
///
/// Spec: T§2 (RFC 9381 §5.3, §5.2, §5.4.4, §5.4.5).
pub fn ecvrf_verify(pk: &[u8], alpha: &[u8], pi: &[u8]) -> Option<[u8; 64]> {
    if pk.len() != 32 || pi.len() != 80 {
        return None;
    }
    let y = decode_point(pk)?;
    if !validate_key(pk) {
        return None;
    }
    let gamma = decode_point(&pi[..32])?;
    let mut c16 = [0u8; 32];
    c16[..16].copy_from_slice(&pi[32..48]);
    let c = Scalar::from_bytes_mod_order(c16);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(pi[48..80].try_into().ok()?))?; // s < q
    let hp = encode_to_curve(pk, alpha)?;
    let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-c), &y, &s);
    let v = hp * s - gamma * c;
    if challenge(&[&y, &hp, &gamma, &u, &v]) != pi[32..48] {
        return None;
    }
    let mut h = Sha512::new();
    h.update([SUITE, 0x03]);
    h.update(gamma.mul_by_cofactor().compress().0);
    h.update([0x00]);
    let mut beta = [0u8; 64];
    beta.copy_from_slice(&h.finalize());
    let _ = ED25519_BASEPOINT_POINT;
    Some(beta)
}

/// `VrfInput { opaque label<0..2^8-1>; uint32 version; }`.
///
/// Spec: T§5 item 1.
pub fn vrf_input(label: &[u8], version: u64) -> Option<Vec<u8>> {
    if label.len() > 255 || version > u32::MAX as u64 {
        return None;
    }
    let mut out = vec![label.len() as u8];
    out.extend_from_slice(label);
    out.extend_from_slice(&(version as u32).to_be_bytes());
    Some(out)
}

/// The KEYTRANS commitment for contact-monitoring mode (empty update suffix).
///
/// Spec: T§5 item 3.
pub fn commitment(opening: &[u8], label: &[u8], version: u32, value: &[u8]) -> Option<[u8; 32]> {
    if opening.len() != 16 || label.len() > 255 {
        return None;
    }
    let mut m = Hmac::<Sha256>::new_from_slice(&KC).ok()?;
    m.update(opening);
    m.update(&[label.len() as u8]);
    m.update(label);
    m.update(&version.to_be_bytes());
    m.update(&(value.len() as u32).to_be_bytes());
    m.update(value);
    Some(m.finalize().into_bytes().into())
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A prefix-tree parent; an absent child is 32 zero bytes.
///
/// Spec: T§5 item 4.
pub fn prefix_parent(left: Option<&[u8; 32]>, right: Option<&[u8; 32]>) -> [u8; 32] {
    let z = [0u8; 32];
    sha(&[&[0x03], left.unwrap_or(&z), right.unwrap_or(&z)])
}

fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i / 8] >> (7 - i % 8)) & 1
}

/// The prefix-tree root of distinct leaves `(index, commitment)`: each leaf only as deep as it must be.
///
/// Spec: T§5 item 4.
pub fn prefix_root(leaves: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
    if leaves.len() == 1 {
        return sha(&[&[0x02], &leaves[0].0, &leaves[0].1]);
    }
    let (l, r): (Vec<_>, Vec<_>) = leaves.iter().partition(|(k, _)| bit(k, depth) == 0);
    let side = |v: &Vec<([u8; 32], [u8; 32])>| (!v.is_empty()).then(|| prefix_root(v, depth + 1));
    prefix_parent(side(&l).as_ref(), side(&r).as_ref())
}

/// The log-tree root of `LogEntry` leaves (`uint64` ms timestamp ‖ prefix root): left-balanced, hashContent tags.
///
/// Spec: T§5 item 5.
pub fn log_root(entries: &[(u64, [u8; 32])]) -> [u8; 32] {
    fn go(leaves: &[[u8; 32]]) -> ([u8; 32], bool) {
        if leaves.len() == 1 {
            return (leaves[0], true);
        }
        let k = 1usize << (usize::BITS - 1 - (leaves.len() - 1).leading_zeros());
        let ((lv, ll), (rv, rl)) = (go(&leaves[..k]), go(&leaves[k..]));
        let tag = |leaf: bool| if leaf { [0u8] } else { [1u8] };
        (sha(&[&tag(ll), &lv, &tag(rl), &rv]), false)
    }
    let leaves: Vec<[u8; 32]> = entries.iter().map(|(t, p)| sha(&[&t.to_be_bytes(), p])).collect();
    go(&leaves).0
}

/// A parsed, accepted mode-1 Configuration (KEYTRANS §11.2).
#[derive(Debug, Clone)]
pub struct Configuration {
    /// Ed25519 key that signs tree heads.
    pub signature_public_key: [u8; 32],
    /// ECVRF public key.
    pub vrf_public_key: [u8; 32],
    /// ms the rightmost timestamp may be ahead of the client's clock.
    pub max_ahead: u64,
    /// ms it may be behind.
    pub max_behind: u64,
    /// The reasonable monitoring window, ms.
    pub reasonable_monitoring_window: u64,
    /// The maximum lifetime of a version, ms, if any.
    pub maximum_lifetime: Option<u64>,
}

/// Parse a Configuration and apply T§2: `Err` is `unsupported-suite`, `unsupported-mode` or `malformed`.
///
/// Spec: T§2, T§5 item 6.
pub fn parse_configuration(b: &[u8]) -> Result<Configuration, &'static str> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        let out = b.get(pos..pos + n).ok_or("malformed")?;
        pos += n;
        Ok(out)
    };
    let suite = u16::from_be_bytes(take(2)?.try_into().map_err(|_| "malformed")?);
    let mode = take(1)?[0];
    if suite != 2 {
        return Err("unsupported-suite");
    }
    if mode != 1 {
        return Err("unsupported-mode");
    }
    // the KEYTRANS editors' copy: mode 1 carries no leaf_public_key (spec-gap 104)
    let mut keys = [[0u8; 32]; 2];
    for k in keys.iter_mut() {
        let len = u16::from_be_bytes(take(2)?.try_into().map_err(|_| "malformed")?) as usize;
        let key = take(len)?;
        *k = key.try_into().map_err(|_| "malformed")?;
    }
    let mut u64s = [0u64; 3];
    for v in u64s.iter_mut() {
        *v = u64::from_be_bytes(take(8)?.try_into().map_err(|_| "malformed")?);
    }
    let life = match take(1)?[0] {
        0 => None,
        1 => Some(u64::from_be_bytes(take(8)?.try_into().map_err(|_| "malformed")?)),
        _ => return Err("malformed"),
    };
    if pos != b.len() {
        return Err("malformed");
    }
    // durations above 2^53−1 ms are refused, so they stay exact as JSON numbers
    const MAX_SAFE: u64 = (1 << 53) - 1;
    if u64s.iter().chain(life.iter()).any(|v| *v > MAX_SAFE) {
        return Err("malformed");
    }
    Ok(Configuration {
        signature_public_key: keys[0],
        vrf_public_key: keys[1],
        max_ahead: u64s[0],
        max_behind: u64s[1],
        reasonable_monitoring_window: u64s[2],
        maximum_lifetime: life,
    })
}

/// Verify a tree head's Ed25519 signature over `TreeHeadTBS { Configuration; uint64 tree_size; root }`.
///
/// Spec: T§5 item 7.
pub fn tree_head_valid(config: &[u8], tree_size: u64, root: &[u8], signature: &[u8]) -> Result<bool, &'static str> {
    let cfg = parse_configuration(config)?;
    let mut tbs = config.to_vec();
    tbs.extend_from_slice(&tree_size.to_be_bytes());
    tbs.extend_from_slice(root);
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(&cfg.signature_public_key), Signature::from_slice(signature)) else {
        return Ok(false);
    };
    Ok(key.verify(&tbs, &sig).is_ok())
}

/// Normalize an alias (`local@domain`), or `None` when it is not one.
///
/// Spec: T§3. Impl (spec-gap 104): ASCII only; split at the last `@`; the domain lowercased.
pub fn normalize_alias(a: &str) -> Option<String> {
    let (local, domain) = a.rsplit_once('@')?;
    if local.is_empty() || !local.chars().all(|c| ('\u{21}'..='\u{7e}').contains(&c) && c != '@') {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let ldh = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if labels.len() < 2 || !labels.iter().all(ldh) {
        return None;
    }
    let out = format!("{local}@{}", domain.to_ascii_lowercase());
    (out.len() <= 255).then_some(out)
}

fn level(x: u64) -> u32 {
    x.trailing_ones()
}

/// The implicit binary search tree over `n` log entries: its root and frontier.
///
/// Spec: T§5 item 8 (KEYTRANS §4.1, Appendix A).
pub fn search_tree(n: u64) -> (u64, Vec<u64>) {
    let root = (1u64 << (63 - n.leading_zeros())) - 1;
    let left = |x: u64| x ^ (1 << (level(x) - 1));
    let mut out = vec![root];
    while *out.last().unwrap_or(&0) != n - 1 {
        let mut x = *out.last().unwrap_or(&0) ^ (3 << (level(*out.last().unwrap_or(&0)) - 1));
        while x >= n {
            x = left(x);
        }
        out.push(x);
    }
    (root, out)
}

/// The base binary ladder for a target version.
///
/// Spec: T§5 item 8 (KEYTRANS §5).
pub fn base_ladder(t: u64) -> Vec<u64> {
    let mut out = vec![];
    loop {
        let v = (1u64 << out.len()) - 1;
        out.push(v);
        if v > t {
            break;
        }
    }
    let (mut lo, mut hi) = (out[out.len() - 2], out[out.len() - 1]);
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        out.push(mid);
        if mid <= t {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    out
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or("")).unwrap_or_default()
}

fn arr32(v: &Value) -> Option<[u8; 32]> {
    h(v).try_into().ok()
}

/// Run an `alias-transparency/` vector.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    let label = i["label"].as_str().unwrap_or("").as_bytes();
    match i["check"].as_str().unwrap_or("") {
        "alias" => match normalize_alias(i["alias"].as_str().unwrap_or("")) {
            Some(l) => json!({"label": l}),
            None => json!({"error": "not-an-alias"}),
        },
        "vrf-input" => match vrf_input(label, i["version"].as_u64().unwrap_or(u64::MAX)) {
            Some(b) => json!({"bytes": hex::encode(b)}),
            None => json!({"error": "vrf-input"}),
        },
        "vrf-verify" => match ecvrf_verify(&h(&i["public_key"]), &h(&i["alpha"]), &h(&i["proof"])) {
            Some(beta) => json!({"valid": true, "beta": hex::encode(beta)}),
            None => json!({"valid": false, "beta": null}),
        },
        "index" => {
            let Some(alpha) = vrf_input(label, i["version"].as_u64().unwrap_or(u64::MAX)) else {
                return json!({"error": "vrf-input"});
            };
            match ecvrf_verify(&h(&i["public_key"]), &alpha, &h(&i["proof"])) {
                Some(beta) => json!({"index": hex::encode(&beta[..32])}),
                None => json!({"error": "vrf-invalid"}),
            }
        }
        "commitment" => {
            let value = i["value"].as_str().unwrap_or("").as_bytes();
            let opening = h(&i["opening"]);
            if opening.len() != 16 {
                return json!({"error": "opening"});
            }
            let Some(version) = i["version"].as_u64().and_then(|v| u32::try_from(v).ok()).filter(|_| label.len() <= 255) else {
                return json!({"error": "label"});
            };
            match commitment(&opening, label, version, value) {
                Some(c) => json!({"commitment": hex::encode(c)}),
                None => json!({"error": "label"}),
            }
        }
        "commitment-raw" => {
            let Ok(mut m) = Hmac::<Sha256>::new_from_slice(&KC) else { return json!({"error": "hmac"}) };
            m.update(&h(&i["opening"]));
            m.update(&h(&i["body"]));
            json!({"commitment": hex::encode(m.finalize().into_bytes())})
        }
        "prefix-root" => {
            let leaves: Option<Vec<([u8; 32], [u8; 32])>> =
                i["leaves"].as_array().into_iter().flatten().map(|x| Some((arr32(&x["index"])?, arr32(&x["commitment"])?))).collect();
            let Some(leaves) = leaves.filter(|l| !l.is_empty()) else { return json!({"error": "malformed"}) };
            let mut keys: Vec<[u8; 32]> = leaves.iter().map(|l| l.0).collect();
            keys.sort();
            keys.dedup();
            if keys.len() != leaves.len() {
                return json!({"error": "malformed"});
            }
            json!({"root": hex::encode(prefix_root(&leaves, 0))})
        }
        "prefix-parent" => {
            let (l, r) = (arr32(&i["left"]), arr32(&i["right"]));
            json!({"hash": hex::encode(prefix_parent(l.as_ref(), r.as_ref()))})
        }
        "log-root" => {
            let entries: Vec<(u64, [u8; 32])> = i["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| (e["timestamp"].as_u64().unwrap_or(0), arr32(&e["prefix_root"]).unwrap_or([0; 32])))
                .collect();
            if entries.is_empty() {
                return json!({"error": "malformed"});
            }
            json!({"root": hex::encode(log_root(&entries))})
        }
        "configuration" => {
            let c = &i["config"];
            let mut b = vec![];
            b.extend_from_slice(&(c["ciphersuite"].as_u64().unwrap_or(0) as u16).to_be_bytes());
            b.push(c["mode"].as_u64().unwrap_or(0) as u8);
            for k in ["signature_public_key", "vrf_public_key"] {
                let key = h(&c[k]);
                b.extend_from_slice(&(key.len() as u16).to_be_bytes());
                b.extend_from_slice(&key);
            }
            for k in ["max_ahead", "max_behind", "reasonable_monitoring_window"] {
                b.extend_from_slice(&c[k].as_u64().unwrap_or(0).to_be_bytes());
            }
            match c["maximum_lifetime"].as_u64() {
                Some(l) => {
                    b.push(1);
                    b.extend_from_slice(&l.to_be_bytes());
                }
                None => b.push(0),
            }
            json!({"bytes": hex::encode(b)})
        }
        "configuration-accept" => match parse_configuration(&h(&i["bytes"])) {
            Ok(c) => json!({"config": {"signature_public_key": hex::encode(c.signature_public_key),
                "vrf_public_key": hex::encode(c.vrf_public_key),
                "max_ahead": c.max_ahead, "max_behind": c.max_behind,
                "reasonable_monitoring_window": c.reasonable_monitoring_window, "maximum_lifetime": c.maximum_lifetime}}),
            Err(e) => json!({"error": e}),
        },
        "tree-head" => match tree_head_valid(&h(&i["configuration"]), i["tree_size"].as_u64().unwrap_or(0), &h(&i["root"]), &h(&i["signature"])) {
            Ok(valid) => json!({"valid": valid}),
            Err(e) => json!({"error": e}),
        },
        "search-tree" => {
            let (root, frontier) = search_tree(i["n"].as_u64().unwrap_or(1).max(1));
            json!({"root": root, "frontier": frontier})
        }
        "ladder" => json!({"ladder": base_ladder(i["version"].as_u64().unwrap_or(0))}),
        other => json!({"error": format!("unknown check {other}")}),
    }
}
