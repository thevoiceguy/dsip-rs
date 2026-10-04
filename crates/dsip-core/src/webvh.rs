//! `did:webvh` v1.0 resolution: verify a DID log and return the latest document.
//!
//! Spec: §7.2, §8.1, §8.4 (v0.9; spec-gap 101) and the did:webvh v1.0 method specification
//! (DIF Ratified, <https://identity.foundation/didwebvh/v1.0/>).
//!
//! The check order and reason tokens are the suite's contract (`impl/vectors/README.md`, kind
//! `did-webvh`), so that three implementations report the same reason for a log with more than
//! one fault.
//!
//! Impl (spec-gap 101): any invalid entry rejects the whole log (fail closed); a resolver caches
//! the highest verified versionId per DID and rejects a log that does not reach it (`rollback`)
//! or holds a different entry there (`fork`); only method version `did:webvh:1.0` is supported;
//! an entry key beyond the five the method lists is refused. JCS (RFC 8785) is used only inside
//! this method's own hashes and proofs — never on a DSIP envelope, whose signature covers the
//! bytes as sent (§10.2).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const MH_SHA256: [u8; 2] = [0x12, 0x20];
const ED25519_PUB: [u8; 2] = [0xed, 0x01];
const METHOD: &str = "did:webvh:1.0";
const ENTRY_KEYS: [&str; 5] = ["parameters", "proof", "state", "versionId", "versionTime"];
const PARAMS: [&str; 9] = ["method", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "portable", "deactivated", "ttl"];
/// did:webvh §Read: a resolver SHOULD tolerate at most 5 minutes of clock skew.
const FUTURE_TOLERANCE_S: i64 = 300;

/// A resolution failure: one reason token from the README `did-webvh` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject(pub &'static str);

type R<T> = Result<T, Reject>;

/// RFC 8785 for the values these logs hold. A non-integer number is refused (`log-malformed`).
///
/// Impl: object keys are sorted by UTF-16 code units; strings use serde_json's escaping, which is
/// RFC 8785's (`\b \f \n \r \t`, other controls as lowercase `\u00xx`, nothing else escaped).
pub fn jcs(v: &Value) -> R<Vec<u8>> {
    fn enc(v: &Value, out: &mut String) -> R<()> {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) if n.is_i64() || n.is_u64() => out.push_str(&n.to_string()),
            Value::Number(_) => return Err(Reject("log-malformed")),
            Value::String(s) => out.push_str(&serde_json::to_string(s).map_err(|_| Reject("log-malformed"))?),
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    enc(x, out)?;
                }
                out.push(']');
            }
            Value::Object(o) => {
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).map_err(|_| Reject("log-malformed"))?);
                    out.push(':');
                    enc(&o[k], out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut s = String::new();
    enc(v, &mut s)?;
    Ok(s.into_bytes())
}

/// The largest integer I-JSON allows (RFC 7493 §2.2): 2^53 − 1.
const MAX_SAFE: i64 = (1 << 53) - 1;

/// Parse I-JSON (RFC 7493), which did:webvh's JCS assumes: no duplicate member names, no lone surrogates
/// (serde_json already refuses those), every number an integer within ±(2^53−1). `None` otherwise.
pub fn ijson(text: &str) -> Option<Value> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    struct Seed;
    impl<'de> DeserializeSeed<'de> for Seed {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(Seed)
        }
    }
    impl<'de> Visitor<'de> for Seed {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("I-JSON")
        }
        fn visit_bool<E: Error>(self, b: bool) -> Result<Value, E> {
            Ok(Value::Bool(b))
        }
        fn visit_i64<E: Error>(self, n: i64) -> Result<Value, E> {
            if (-MAX_SAFE..=MAX_SAFE).contains(&n) { Ok(json!(n)) } else { Err(E::custom("integer out of range")) }
        }
        fn visit_u64<E: Error>(self, n: u64) -> Result<Value, E> {
            if n <= MAX_SAFE as u64 { Ok(json!(n)) } else { Err(E::custom("integer out of range")) }
        }
        fn visit_f64<E: Error>(self, x: f64) -> Result<Value, E> {
            // After the lexical check, a float here is `-0` (or an integer beyond u64/i64, which I-JSON refuses).
            if x == 0.0 { Ok(json!(0)) } else { Err(E::custom("integer out of range")) }
        }
        fn visit_str<E: Error>(self, s: &str) -> Result<Value, E> {
            Ok(Value::String(s.to_string()))
        }
        fn visit_string<E: Error>(self, s: String) -> Result<Value, E> {
            Ok(Value::String(s))
        }
        fn visit_unit<E: Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut v = vec![];
            while let Some(x) = a.next_element_seed(Seed)? {
                v.push(x);
            }
            Ok(Value::Array(v))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut m = Map::new();
            while let Some(k) = a.next_key::<String>()? {
                let v = a.next_value_seed(Seed)?;
                if m.insert(k, v).is_some() {
                    return Err(A::Error::custom("duplicate member name"));
                }
            }
            Ok(Value::Object(m))
        }
    }
    if has_fraction_or_exponent(text) {
        return None;
    }
    let mut d = serde_json::Deserializer::from_str(text);
    let v = Seed.deserialize(&mut d).ok()?;
    d.end().ok()?;
    Some(v)
}

/// Does any number outside a string carry a fraction or an exponent? I-JSON integers here are written without either.
fn has_fraction_or_exponent(text: &str) -> bool {
    let (mut in_str, mut esc, mut in_num) = (false, false, false);
    for c in text.chars() {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => (in_str, in_num) = (true, false),
            '-' | '0'..='9' => in_num = true,
            '.' | 'e' | 'E' if in_num => return true,
            _ => in_num = false,
        }
    }
    false
}

/// `base58btc(0x12 0x20 ‖ sha256(data))`, without a multibase prefix.
pub fn mh_b58(data: &[u8]) -> String {
    let mut raw = MH_SHA256.to_vec();
    raw.extend_from_slice(&Sha256::digest(data));
    bs58::encode(raw).into_string()
}

fn is_b58(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
}

fn is_mh(s: &str) -> bool {
    is_b58(s) && bs58::decode(s).into_vec().is_ok_and(|r| r.len() == 34 && r[..2] == MH_SHA256)
}

fn multikey_pub(mk: &str) -> Option<[u8; 32]> {
    let body = mk.strip_prefix('z').filter(|b| is_b58(b))?;
    let raw = bs58::decode(body).into_vec().ok()?;
    (raw.len() == 34 && raw[..2] == ED25519_PUB).then(|| raw[2..].try_into().ok()).flatten()
}

/// `versionTime` → nanoseconds since the epoch, or `None` unless `YYYY-MM-DDTHH:MM:SS[.f{1,9}](Z|+00:00)`.
fn parse_time(s: &str) -> Option<i128> {
    let (main, zone_ok) = if let Some(m) = s.strip_suffix('Z') { (m, true) } else { (s.strip_suffix("+00:00")?, true) };
    if !zone_ok || main.len() < 19 {
        return None;
    }
    let (dt, frac) = main.split_at(19);
    let b = dt.as_bytes();
    let pos_ok = b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':';
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        dt.get(r.clone()).filter(|x| x.bytes().all(|c| c.is_ascii_digit())).and_then(|x| x.parse().ok())
    };
    let (y, mo, d, h, mi, se) = (digits(0..4)?, digits(5..7)?, digits(8..10)?, digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let nanos: i128 = match frac.strip_prefix('.') {
        None if frac.is_empty() => 0,
        Some(f) if (1..=9).contains(&f.len()) && f.bytes().all(|c| c.is_ascii_digit()) => format!("{f:0<9}").parse().ok()?,
        _ => return None,
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !pos_ok || !(1..=12).contains(&mo) || d < 1 || d > dim[(mo - 1) as usize] || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) as i128) * 1_000_000_000 + nanos)
}

/// Validate a did:webvh DID (method spec §Method-Specific Identifier) and return its SCID.
///
/// Impl (spec-gap 101): the domain is ASCII LDH labels (an IDN in its `xn--` form); percent-encoding in the
/// domain other than the `%3A` port separator is refused.
pub fn check_did(did: &str) -> R<&str> {
    let bad = Reject("invalid-did");
    let rest = did.strip_prefix("did:webvh:").ok_or(bad.clone())?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 2 {
        return Err(bad);
    }
    let (scid, domain, path) = (parts[0], parts[1], &parts[2..]);
    if scid.len() != 46 || !is_b58(scid) {
        return Err(bad);
    }
    let (host, port) = match domain.split_once("%3A") {
        Some((h, p)) => (h, Some(p)),
        None => (domain, None),
    };
    if let Some(p) = port {
        let ok = (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
        if !ok {
            return Err(bad);
        }
    }
    let labels: Vec<&str> = host.split('.').collect();
    let ldh = |l: &&str| (1..=63).contains(&l.len()) && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    if labels.len() < 2 || !labels.iter().all(ldh) || labels.iter().all(|l| l.bytes().all(|c| c.is_ascii_digit())) {
        return Err(bad);
    }
    for seg in path {
        let b = seg.as_bytes();
        let mut dec = Vec::new();
        let mut i = 0;
        if b.is_empty() {
            return Err(bad);
        }
        while i < b.len() {
            if b[i] == b'%' {
                let hex = seg.get(i + 1..i + 3).filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit())).ok_or(bad.clone())?;
                dec.push(u8::from_str_radix(hex, 16).map_err(|_| bad.clone())?);
                i += 3;
            } else if b[i].is_ascii_alphanumeric() || b"._~-".contains(&b[i]) {
                dec.push(b[i]);
                i += 1;
            } else {
                return Err(bad);
            }
        }
        // decoded bytes must be UTF-8; `char::is_whitespace` is exactly Unicode White_Space (README step 1)
        let d = String::from_utf8(dec).map_err(|_| bad.clone())?;
        let edge_ws = d.chars().next().is_some_and(char::is_whitespace) || d.chars().last().is_some_and(char::is_whitespace);
        if d == "." || d == ".." || d.contains(['/', '\\', '\0']) || edge_ws {
            return Err(bad);
        }
    }
    Ok(scid)
}

/// eddsa-jcs-2022 signing input: `sha256(JCS(proof without proofValue)) ‖ sha256(JCS(document))`.
pub fn proof_input(document: &Value, proof: &Map<String, Value>) -> R<Vec<u8>> {
    let mut cfg = proof.clone();
    cfg.remove("proofValue");
    let mut out = Sha256::digest(jcs(&Value::Object(cfg))?).to_vec();
    out.extend_from_slice(&Sha256::digest(jcs(document)?));
    Ok(out)
}

fn vm_multikey(proof: &Value) -> Option<String> {
    let vm = proof.get("verificationMethod")?.as_str()?;
    let (body, frag) = vm.strip_prefix("did:key:")?.split_once('#')?;
    (body == frag && body.starts_with('z') && is_b58(&body[1..])).then(|| body.to_string())
}

fn proof_ok(document: &Value, proof: &Value, public: &[u8; 32]) -> bool {
    let Some(p) = proof.as_object() else { return false };
    if p.get("type") != Some(&json!("DataIntegrityProof"))
        || p.get("cryptosuite") != Some(&json!("eddsa-jcs-2022"))
        || p.get("proofPurpose") != Some(&json!("assertionMethod"))
    {
        return false;
    }
    let Some(pv) = p.get("proofValue").and_then(Value::as_str).and_then(|v| v.strip_prefix('z')).filter(|b| is_b58(b)) else {
        return false;
    };
    let (Ok(sig), Ok(input), Ok(key)) = (bs58::decode(pv).into_vec(), proof_input(document, p), VerifyingKey::from_bytes(public)) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else { return false };
    key.verify(&input, &sig).is_ok()
}

fn string_list(v: &Value) -> Option<Vec<String>> {
    v.as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
}

/// Allowed keys and types, first-entry rules (did:webvh §Parameters).
fn check_params(p: &Value, n: usize) -> R<()> {
    let bad = Err(Reject("parameters"));
    let Some(o) = p.as_object() else { return bad };
    if o.keys().any(|k| !PARAMS.contains(&k.as_str())) {
        return bad;
    }
    if n == 1 && !["method", "scid", "updateKeys"].iter().all(|k| o.contains_key(*k)) {
        return bad;
    }
    if n > 1 && o.contains_key("scid") {
        return bad;
    }
    if o.get("method").is_some_and(|m| m != METHOD) || o.get("scid").is_some_and(|s| !s.as_str().is_some_and(is_mh)) {
        return bad;
    }
    for k in ["updateKeys", "nextKeyHashes", "watchers"] {
        if o.get(k).is_some_and(|v| string_list(v).is_none()) {
            return bad;
        }
    }
    if o.get("updateKeys").and_then(string_list).is_some_and(|ks| !ks.iter().all(|k| multikey_pub(k).is_some())) {
        return bad;
    }
    if ["portable", "deactivated"].iter().any(|k| o.get(*k).is_some_and(|v| !v.is_boolean())) {
        return bad;
    }
    if o.get("ttl").is_some_and(|t| !t.as_u64().is_some_and(|t| t <= 1 << 31)) {
        return bad;
    }
    if n > 1 && o.get("portable") == Some(&Value::Bool(true)) {
        return bad;
    }
    if let Some(w) = o.get("witness") {
        let Some(wo) = w.as_object() else { return bad };
        if !wo.is_empty() {
            let ids: Option<Vec<&str>> = wo.get("witnesses").and_then(Value::as_array).map(|a| a.iter().map(|x| x.get("id").and_then(Value::as_str).unwrap_or("")).collect());
            let Some(ids) = ids else { return bad };
            let distinct: BTreeSet<&str> = ids.iter().copied().collect();
            let keys_ok = ids.iter().all(|i| i.strip_prefix("did:key:").and_then(multikey_pub).is_some());
            let t = wo.get("threshold").and_then(Value::as_u64);
            let shape = wo.len() == 2 && wo.contains_key("threshold") && wo.contains_key("witnesses");
            if !shape || ids.is_empty() || distinct.len() != ids.len() || !keys_ok || !t.is_some_and(|t| t >= 1 && t as usize <= ids.len()) {
                return bad;
            }
        }
    }
    Ok(())
}

fn without_proof(e: &Map<String, Value>) -> Map<String, Value> {
    let mut m = e.clone();
    m.remove("proof");
    m
}

/// Resolve `did` from its log text (README `did-webvh` contract): `resolved`, `deactivated` or `rejected`.
pub fn resolve(did: &str, log: &str, witness: Option<&str>, cache: Option<&str>, now: i64) -> Value {
    match resolve_inner(did, log, witness, cache, now) {
        Ok(v) => v,
        Err(Reject(reason)) => json!({"outcome": "rejected", "reason": reason}),
    }
}

fn resolve_inner(did: &str, log: &str, witness: Option<&str>, cache: Option<&str>, now: i64) -> R<Value> {
    let scid_did = check_did(did)?.to_string();
    let mut lines: Vec<&str> = log.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.is_empty() {
        return Err(Reject("log-malformed"));
    }
    let defaults = json!({"nextKeyHashes": [], "witness": {}, "watchers": [], "portable": false, "deactivated": false, "ttl": 3600});
    let mut active: Map<String, Value> = Map::new();
    let mut entries: Vec<Map<String, Value>> = vec![];
    let (mut prev_vid, mut prev_time, mut prev_id, mut scid): (Option<String>, Option<i128>, Option<String>, String) = (None, None, None, String::new());
    let mut witness_due: Vec<(usize, Value)> = vec![];
    for (i, line) in lines.iter().enumerate() {
        let n = i + 1;
        // 3. structure
        let e: Value = ijson(line).ok_or(Reject("log-malformed"))?;
        let Some(e) = e.as_object().cloned() else { return Err(Reject("log-malformed")) };
        let keys: BTreeSet<&str> = e.keys().map(String::as_str).collect();
        if keys != ENTRY_KEYS.iter().copied().collect()
            || !e["state"].is_object()
            || !e["proof"].as_array().is_some_and(|a| !a.is_empty())
            || !e["versionId"].is_string()
        {
            return Err(Reject("log-malformed"));
        }
        // 4. versionId
        let vid = e["versionId"].as_str().unwrap_or("").to_string();
        let (num, hash) = vid.split_once('-').ok_or(Reject("version-number"))?;
        let num_ok = !num.is_empty() && !num.starts_with('0') && num.bytes().all(|c| c.is_ascii_digit()) && num.parse::<usize>().ok() == Some(n);
        if !num_ok || !is_b58(hash) {
            return Err(Reject("version-number"));
        }
        if !is_mh(hash) {
            return Err(Reject("entry-hash"));
        }
        // 5. versionTime
        let t = e["versionTime"].as_str().and_then(parse_time).ok_or(Reject("version-time"))?;
        if prev_time.is_some_and(|p| t <= p) || t > ((now + FUTURE_TOLERANCE_S) as i128) * 1_000_000_000 {
            return Err(Reject("version-time"));
        }
        // 6. parameters
        if n > 1 && active.get("deactivated") == Some(&Value::Bool(true)) {
            return Err(Reject("after-deactivation"));
        }
        let p = &e["parameters"];
        check_params(p, n)?;
        let prev = active.clone();
        if n == 1 {
            active = defaults.as_object().cloned().unwrap_or_default();
        }
        for (k, v) in p.as_object().into_iter().flatten() {
            active.insert(k.clone(), v.clone());
        }
        // 7. SCID
        if n == 1 {
            scid = p["scid"].as_str().unwrap_or("").to_string();
            let mut pre = without_proof(&e);
            pre.insert("versionId".into(), json!("{SCID}"));
            let text = serde_json::to_string(&Value::Object(pre)).map_err(|_| Reject("log-malformed"))?.replace(&scid, "{SCID}");
            let back: Value = serde_json::from_str(&text).map_err(|_| Reject("scid"))?;
            if mh_b58(&jcs(&back)?) != scid {
                return Err(Reject("scid"));
            }
        }
        // 8. entryHash
        let mut h = without_proof(&e);
        h.insert("versionId".into(), json!(if n == 1 { scid.clone() } else { prev_vid.clone().unwrap_or_default() }));
        if mh_b58(&jcs(&Value::Object(h))?) != hash {
            return Err(Reject("entry-hash"));
        }
        // 9. pre-rotation
        let prerot = n > 1 && prev.get("nextKeyHashes").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
        if prerot {
            let po = p.as_object().cloned().unwrap_or_default();
            if !po.contains_key("updateKeys") || !po.contains_key("nextKeyHashes") {
                return Err(Reject("pre-rotation"));
            }
            let committed = string_list(&prev["nextKeyHashes"]).unwrap_or_default();
            let keys = string_list(&p["updateKeys"]).unwrap_or_default();
            if !keys.iter().all(|k| committed.contains(&mh_b58(k.as_bytes()))) {
                return Err(Reject("pre-rotation"));
            }
        }
        // 10. proofs
        let keys = string_list(if n == 1 || prerot { &p["updateKeys"] } else { &prev["updateKeys"] }).unwrap_or_default();
        let doc = Value::Object(without_proof(&e));
        let mut authorized = false;
        for pr in e["proof"].as_array().into_iter().flatten() {
            let mk = vm_multikey(pr).ok_or(Reject("proof"))?;
            if !keys.contains(&mk) {
                continue;
            }
            let public = multikey_pub(&mk).ok_or(Reject("proof"))?;
            if !proof_ok(&doc, pr, &public) {
                return Err(Reject("proof"));
            }
            authorized = true;
        }
        if !authorized {
            return Err(Reject("unauthorized-key"));
        }
        // 11. state.id
        let sid = e["state"].get("id").and_then(Value::as_str).ok_or(Reject("identity"))?.to_string();
        let sid_scid = check_did(&sid).map_err(|_| Reject("identity"))?;
        if sid_scid != scid {
            return Err(Reject("identity"));
        }
        if let Some(prev_id) = &prev_id {
            if &sid != prev_id {
                let portable = active.get("portable") == Some(&Value::Bool(true));
                let aka = e["state"].get("alsoKnownAs").and_then(string_list).unwrap_or_default();
                if !portable || !aka.contains(prev_id) {
                    return Err(Reject("identity"));
                }
            }
        }
        // witness requirement for this entry
        let prev_witness_empty = prev.get("witness").is_none_or(|w| w.as_object().is_some_and(Map::is_empty));
        let wcfg = if n == 1 || prev_witness_empty { active["witness"].clone() } else { prev["witness"].clone() };
        if wcfg.as_object().is_some_and(|w| !w.is_empty()) {
            witness_due.push((i, wcfg));
        }
        prev_vid = Some(vid);
        prev_time = Some(t);
        prev_id = Some(sid);
        entries.push(e);
    }
    // 12. the requested DID
    if scid_did != scid || !entries.iter().any(|e| e["state"]["id"] == json!(did)) {
        return Err(Reject("identity"));
    }
    // 13. witnesses
    if !witness_due.is_empty() {
        let records: Value = witness.and_then(ijson).ok_or(Reject("witness"))?;
        let vids: Vec<&str> = entries.iter().map(|e| e["versionId"].as_str().unwrap_or("")).collect();
        let mut approvals: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for rec in records.as_array().into_iter().flatten() {
            let Some(j) = rec.get("versionId").and_then(Value::as_str).and_then(|v| vids.iter().position(|x| *x == v)) else { continue };
            let doc = json!({"versionId": vids[j]});
            for pr in rec.get("proof").and_then(Value::as_array).into_iter().flatten() {
                if let Some(mk) = vm_multikey(pr) {
                    if multikey_pub(&mk).is_some_and(|k| proof_ok(&doc, pr, &k)) {
                        approvals.entry(j).or_default().insert(format!("did:key:{mk}"));
                    }
                }
            }
        }
        for (i, cfg) in &witness_due {
            let ids: BTreeSet<String> = cfg["witnesses"].as_array().into_iter().flatten().filter_map(|x| x["id"].as_str().map(String::from)).collect();
            let got: BTreeSet<&String> = approvals.range(i..).flat_map(|(_, s)| s.iter()).filter(|s| ids.contains(*s)).collect();
            if (got.len() as u64) < cfg["threshold"].as_u64().unwrap_or(u64::MAX) {
                return Err(Reject("witness"));
            }
        }
    }
    // 14. cache: rollback, fork
    let last = entries.last().cloned().unwrap_or_default();
    // a cache value not of the form `<n>-<…>` with n ≥ 1 is treated as absent (README step 14)
    let cache = cache.and_then(|c| {
        let (num, rest) = c.split_once('-')?;
        let ok = !rest.is_empty() && !num.starts_with('0') && !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit());
        num.parse::<usize>().ok().filter(|_| ok).map(|k| (k, c))
    });
    if let Some((k, c)) = cache {
        if entries.len() < k {
            return Err(Reject("rollback"));
        }
        if entries[k - 1]["versionId"] != json!(c) {
            return Err(Reject("fork"));
        }
    }
    if active.get("deactivated") == Some(&Value::Bool(true)) {
        return Ok(json!({"outcome": "deactivated", "versionId": last["versionId"], "cache": last["versionId"]}));
    }
    Ok(json!({"outcome": "resolved", "versionId": last["versionId"], "versionTime": last["versionTime"],
              "document": last["state"], "ttl": active["ttl"], "cache": last["versionId"]}))
}

/// Run a `did-webvh/` vector.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    resolve(
        i["did"].as_str().unwrap_or(""),
        i["log"].as_str().unwrap_or(""),
        i["witness"].as_str(),
        i["cache"]["versionId"].as_str(),
        i["now"].as_i64().unwrap_or(0),
    )
}
