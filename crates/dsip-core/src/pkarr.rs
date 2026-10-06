//! Reachability hints on Pkarr: a `did:key` identity's `_dsip` TXT records, published as a BEP 44 mutable item
//! signed by the identity key, read offline into a hint of the hints tier.
//!
//! Spec: §8.1 (hints are never authority), §8.3 (the conflict rule), §8.5; DHT Reachability Hints Profile §9 (v0.9,
//! spec-gap 105). The step order and reason tokens are the suite's contract (`impl/vectors/README.md`, kind `pkarr`).
//!
//! Impl (spec-gap 105): DSIP adds the checks Pkarr omits — a timestamp no later than now + 300 s, canonical
//! z-base-32, only `_dsip.<z32>` records used, a signed expiry of ts + the smallest TTL (each ≤ 3600 s) — and
//! resolves conflicts by §8.3 rather than Pkarr's "larger packet wins".

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

const ZB32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
const FUTURE_TOLERANCE_S: i64 = 300;
const MAX_TTL: u32 = 3600;

/// A rejection reason token (README `pkarr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject(pub &'static str);

/// A hint read from a payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Hint {
    /// The publishing identity.
    pub subject: String,
    /// The signed timestamp, µs: the BEP 44 `seq`.
    pub seq: u64,
    /// ⌊seq / 10⁶⌋.
    pub issued_at: i64,
    /// `issued_at` + the smallest `_dsip` TTL.
    pub expires_at: i64,
    /// `{uri, bindings[, service]}` per record, in record order.
    pub endpoints: Vec<Value>,
}

/// z-base-32 of 32 bytes: 52 characters, most significant bit first.
///
/// Spec: DHT Hints Profile §9.
pub fn z32_encode(b: &[u8; 32]) -> String {
    let mut out = String::with_capacity(52);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in b {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZB32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZB32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode a 52-character z-base-32 key; the 4 padding bits must be zero.
///
/// Spec: DHT Hints Profile §9. Impl (spec-gap 105): non-canonical encodings are refused (Pkarr accepts 16 per key).
pub fn z32_decode(s: &str) -> Result<[u8; 32], Reject> {
    if s.len() != 52 {
        return Err(Reject("malformed"));
    }
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut i) = (0u32, 0, 0usize);
    for c in s.bytes() {
        let v = ZB32.iter().position(|&z| z == c).ok_or(Reject("malformed"))? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if i < 32 {
                out[i] = (acc >> bits) as u8;
            }
            i += 1;
        }
        acc &= (1 << bits) - 1;
    }
    if acc != 0 {
        return Err(Reject("non-canonical"));
    }
    Ok(out)
}

/// BEP 44's signed buffer: `[4:salt<n>:<salt>]3:seqi<seq>e1:v<n>:<value>`.
///
/// Spec: §8.5 (BEP 44 mutable items).
pub fn bep44_signable(seq: u64, value: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    if !salt.is_empty() {
        out.extend_from_slice(format!("4:salt{}:", salt.len()).as_bytes());
        out.extend_from_slice(salt);
    }
    out.extend_from_slice(format!("3:seqi{seq}e1:v{}:", value.len()).as_bytes());
    out.extend_from_slice(value);
    out
}

fn verify(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (VerifyingKey::from_bytes(key), Signature::from_slice(sig)) else { return false };
    k.verify(msg, &s).is_ok()
}

/// A name at `off`: its ASCII-lowercased labels, and the offset after it. A compression pointer must point before
/// the start of the name segment it appears in.
fn name(pkt: &[u8], mut off: usize) -> Result<(Vec<Vec<u8>>, usize), Reject> {
    let bad = Reject("malformed");
    let (mut labels, mut end, mut start): (Vec<&[u8]>, Option<usize>, usize) = (vec![], None, off);
    loop {
        let n = *pkt.get(off).ok_or(bad.clone())?;
        if n & 0xC0 == 0xC0 {
            let lo = *pkt.get(off + 1).ok_or(bad.clone())?;
            let ptr = (((n & 0x3F) as usize) << 8) | lo as usize;
            if ptr >= start {
                return Err(bad);
            }
            end.get_or_insert(off + 2);
            off = ptr;
            start = ptr;
            continue;
        }
        if n & 0xC0 != 0 {
            return Err(bad);
        }
        if n == 0 {
            return Ok((labels.iter().map(|l| l.to_ascii_lowercase()).collect(), end.unwrap_or(off + 1)));
        }
        let label = pkt.get(off + 1..off + 1 + n as usize).ok_or(bad.clone())?;
        labels.push(label);
        off += 1 + n as usize;
    }
}

type Answer = (Vec<Vec<u8>>, u16, u16, u32, Vec<u8>);

/// RFC 1035 message → its answer records; the message must end exactly where the last record does.
fn parse_dns(pkt: &[u8]) -> Result<Vec<Answer>, Reject> {
    let bad = Reject("malformed");
    if pkt.len() < 12 {
        return Err(bad);
    }
    let u16_at = |o: usize| -> Result<u16, Reject> { Ok(u16::from_be_bytes(pkt.get(o..o + 2).ok_or(Reject("malformed"))?.try_into().map_err(|_| Reject("malformed"))?)) };
    let (qd, an, ns, ar) = (u16_at(4)?, u16_at(6)?, u16_at(8)?, u16_at(10)?);
    let mut off = 12;
    for _ in 0..qd {
        off = name(pkt, off)?.1 + 4;
    }
    let mut answers = vec![];
    for i in 0..(an as usize + ns as usize + ar as usize) {
        let (nm, o) = name(pkt, off)?;
        let hdr = pkt.get(o..o + 10).ok_or(bad.clone())?;
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rclass = u16::from_be_bytes([hdr[2], hdr[3]]);
        let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        let rdata = pkt.get(o + 10..o + 10 + rdlen).ok_or(bad.clone())?;
        if i < an as usize {
            answers.push((nm, rtype, rclass, ttl, rdata.to_vec()));
        }
        off = o + 10 + rdlen;
    }
    if off != pkt.len() {
        return Err(bad);
    }
    Ok(answers)
}

/// One `_dsip` TXT record → `{uri, bindings[, service]}`: its framing is checked before its content.
fn endpoint(rdata: &[u8]) -> Result<Value, Reject> {
    let mut strings = vec![];
    let mut i = 0;
    while i < rdata.len() {
        let n = rdata[i] as usize;
        strings.push(rdata.get(i + 1..i + 1 + n).ok_or(Reject("malformed"))?);
        i += 1 + n;
    }
    let (mut uris, mut bindings, mut svcs) = (vec![], vec![], vec![]);
    for s in strings {
        let t = std::str::from_utf8(s).map_err(|_| Reject("bad-endpoint"))?;
        let (k, v) = t.split_once('=').ok_or(Reject("bad-endpoint"))?;
        match k {
            "uri" => uris.push(v.to_string()),
            "b" => bindings.push(v.to_string()),
            "svc" => svcs.push(v.to_string()),
            _ => {}
        }
    }
    if uris.len() != 1 || !uris[0].starts_with("wss://") || bindings.is_empty() || svcs.len() > 1 {
        return Err(Reject("bad-endpoint"));
    }
    let mut ep = json!({"uri": uris[0], "bindings": bindings});
    if let Some(s) = svcs.first() {
        ep["service"] = json!(s);
    }
    Ok(ep)
}

/// Read a relay payload (`signature ‖ ts ‖ dns`) for `did` at `now` (Unix seconds) into a hint.
///
/// Spec: §8.5; DHT Hints Profile §9.
pub fn read(did: &str, payload: &[u8], now: i64) -> Result<Hint, Reject> {
    let key = did
        .strip_prefix("did:key:")
        .filter(|s| s.starts_with('z'))
        .and_then(|_| crate::did::public_from_did_key(did))
        .ok_or(Reject("not-did-key"))?;
    if !(72..=1072).contains(&payload.len()) {
        return Err(Reject("malformed"));
    }
    let (sig, ts, dns) = (&payload[..64], u64::from_be_bytes(payload[64..72].try_into().map_err(|_| Reject("malformed"))?), &payload[72..]);
    if !verify(&key, &bep44_signable(ts, dns, b""), sig) {
        return Err(Reject("signature"));
    }
    if ts > (1u64 << 53) - 1 {
        // Impl: exact as a JSON number (BEP 44 allows up to 2^63−1)
        return Err(Reject("malformed"));
    }
    if ts as i128 > ((now + FUTURE_TOLERANCE_S) as i128) * 1_000_000 {
        return Err(Reject("future"));
    }
    let owner: Vec<Vec<u8>> = vec![b"_dsip".to_vec(), z32_encode(&key).into_bytes()];
    let (mut eps, mut ttls) = (vec![], vec![]);
    for (nm, rtype, rclass, ttl, rdata) in parse_dns(dns)? {
        if nm != owner || rtype != 16 || rclass != 1 {
            continue; // another record of this zone, or outside it: not DSIP's
        }
        eps.push(endpoint(&rdata)?);
        ttls.push(ttl);
    }
    if eps.is_empty() {
        return Err(Reject("no-endpoints"));
    }
    if ttls.iter().any(|t| *t > MAX_TTL) {
        return Err(Reject("ttl-too-long"));
    }
    let issued = (ts / 1_000_000) as i64;
    let expires = issued + *ttls.iter().min().unwrap_or(&0) as i64;
    if now >= expires {
        return Err(Reject("expired"));
    }
    Ok(Hint { subject: did.to_string(), seq: ts, issued_at: issued, expires_at: expires, endpoints: eps })
}

/// Whether a relay payload is signed by `key` (BEP 44, no salt); nothing else is checked.
///
/// Spec: DHT Hints Profile §9 — a publisher trusts a previous packet's timestamp and records only if it is its own.
pub fn verify_payload(key: &[u8; 32], payload: &[u8]) -> bool {
    payload.len() >= 72
        && verify(key, &bep44_signable(u64::from_be_bytes(payload[64..72].try_into().unwrap_or_default()), &payload[72..], b""), &payload[..64])
}

/// A publisher's endpoint: the relay URI, its bindings, and the optional service it stands in for.
#[derive(Debug, Clone)]
pub struct PublishEndpoint {
    /// `wss://…`.
    pub uri: String,
    /// One or more bindings, e.g. `ws/1.0`.
    pub bindings: Vec<String>,
    /// The `svc=` value, when given.
    pub service: Option<String>,
}

/// A DNS answer record kept from a previous packet: owner labels, type, TTL and rdata.
pub type ForeignRecord = (Vec<Vec<u8>>, u16, u32, Vec<u8>);

fn push_name_labels(out: &mut Vec<u8>, labels: &[Vec<u8>]) {
    for l in labels {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
}

/// RFC 3597 §4: the RFC 1035 types in which name compression may occur, as their rdata layout.
fn name_rdata(rtype: u16) -> Option<&'static [Part]> {
    const ONE: &[Part] = &[Part::Name];
    Some(match rtype {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 => ONE,
        6 => &[Part::Name, Part::Name, Part::Bytes(20)],
        14 => &[Part::Name, Part::Name],
        15 => &[Part::Bytes(2), Part::Name],
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Part {
    Name,
    Bytes(usize),
}

/// The name at `off` in uncompressed wire form, label bytes as given; its inline bytes must end by `limit`.
fn expand(pkt: &[u8], mut off: usize, limit: usize) -> Result<(Vec<u8>, usize), Reject> {
    let bad = || Reject("malformed");
    let (mut out, mut end, mut start) = (vec![], None, off);
    loop {
        let n = *pkt.get(off).ok_or_else(bad)?;
        if end.is_none() && off >= limit {
            return Err(bad());
        }
        if n & 0xC0 == 0xC0 {
            let lo = *pkt.get(off + 1).ok_or_else(bad)?;
            if end.is_none() && off + 1 >= limit {
                return Err(bad());
            }
            let ptr = (((n & 0x3F) as usize) << 8) | lo as usize;
            if ptr >= start {
                return Err(bad());
            }
            end.get_or_insert(off + 2);
            off = ptr;
            start = ptr;
            continue;
        }
        if n & 0xC0 != 0 {
            return Err(bad());
        }
        if n == 0 {
            out.push(0);
            let next = end.unwrap_or(off + 1);
            if next > limit {
                return Err(bad());
            }
            return Ok((out, next));
        }
        let stop = off + 1 + n as usize;
        if stop > pkt.len() || (end.is_none() && stop > limit) {
            return Err(bad());
        }
        out.extend_from_slice(&pkt[off..stop]);
        off = stop;
    }
}

fn labels_of(wire: &[u8]) -> Vec<Vec<u8>> {
    let (mut out, mut i) = (vec![], 0);
    while i < wire.len() && wire[i] != 0 {
        let n = wire[i] as usize;
        out.push(wire[i + 1..i + 1 + n].to_vec());
        i += 1 + n;
    }
    out
}

/// The records a publisher carries over from its previous packet's DNS message (DHT Hints Profile §9: one slot per
/// key, shared by every Pkarr use): every IN answer record not owned by `_dsip.<zone>`, with the names inside the
/// rdata of the RFC 1035 types RFC 3597 §4 lets compress expanded, and every other rdata kept as it is.
///
/// Spec: DHT Hints Profile §9 (publishing); `check: "carry"`; spec-gap 105 (decided: re-encode, never drop).
pub fn carry(zone: &str, dns: &[u8]) -> Result<Vec<ForeignRecord>, Reject> {
    let bad = || Reject("malformed");
    if dns.len() < 12 {
        return Err(bad());
    }
    let count = |k: usize| u16::from_be_bytes([dns[k], dns[k + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut off = 12;
    for _ in 0..qd {
        off = expand(dns, off, dns.len())?.1 + 4;
    }
    let mut dsip_owner = vec![5u8];
    dsip_owner.extend_from_slice(b"_dsip");
    dsip_owner.push(zone.len() as u8);
    dsip_owner.extend_from_slice(zone.as_bytes());
    dsip_owner.push(0);
    let mut keep = vec![];
    for i in 0..an + ns + ar {
        let (name, next) = expand(dns, off, dns.len())?;
        off = next;
        let h = dns.get(off..off + 10).ok_or_else(bad)?;
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let rclass = u16::from_be_bytes([h[2], h[3]]);
        let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let (rs, re) = (off + 10, off + 10 + rdlen);
        if re > dns.len() {
            return Err(bad());
        }
        off = re;
        if i >= an || rclass != 1 || name.eq_ignore_ascii_case(&dsip_owner) {
            continue;
        }
        let rdata = match name_rdata(rtype) {
            None => dns[rs..re].to_vec(),
            Some(parts) => {
                let (mut out, mut p) = (vec![], rs);
                for part in parts {
                    match *part {
                        Part::Name => {
                            let (w, n) = expand(dns, p, re)?;
                            out.extend(w);
                            p = n;
                        }
                        Part::Bytes(k) => {
                            if p + k > re {
                                return Err(bad());
                            }
                            out.extend_from_slice(&dns[p..p + k]);
                            p += k;
                        }
                    }
                }
                if p != re {
                    return Err(bad());
                }
                out
            }
        };
        keep.push((labels_of(&name), rtype, ttl, rdata));
    }
    if off != dns.len() {
        return Err(bad());
    }
    Ok(keep)
}

/// The records to carry from a previously published relay payload of this key (`signature ‖ ts ‖ dns`); none if it
/// does not parse. The caller has verified it under its own key.
///
/// Spec: DHT Hints Profile §9 (publishing).
pub fn foreign_records(key: &[u8; 32], payload: &[u8]) -> Vec<ForeignRecord> {
    payload.get(72..).and_then(|dns| carry(&z32_encode(key), dns).ok()).unwrap_or_default()
}

/// The timestamp to sign: the clock, or one above the previous packet's when that is not below the clock (a clock
/// stepped back — the one case signed ahead of the clock, since a lower `seq` is refused everywhere).
///
/// Spec: DHT Hints Profile §9 (publishing); `check: "next-ts"`; spec-gap 105.
pub fn next_ts(clock: u64, previous: Option<u64>) -> Option<u64> {
    let ts = previous.map_or(clock, |p| clock.max(p.saturating_add(1)));
    // above 2^53−1 every reader rejects it (`check: "hint"`): sign nothing
    (ts < (1u64 << 53)).then_some(ts)
}

/// Build and sign a relay payload (`signature ‖ ts ‖ dns`) publishing `endpoints` as `_dsip` TXT records with `ttl`
/// (≤ 3600), plus any `foreign` records kept from the previous packet. The DSIP owner name is written once and
/// pointed to (RFC 1035 compression), and the DNS message must stay within 996 bytes.
///
/// Spec: DHT Hints Profile §9 (publishing): signed by the identity key over BEP 44's buffer, no salt.
pub fn build_payload(
    key: &crate::keys::KeyPair,
    endpoints: &[PublishEndpoint],
    ttl: u32,
    ts: u64,
    foreign: &[ForeignRecord],
) -> Result<Vec<u8>, &'static str> {
    if endpoints.is_empty() || ttl > MAX_TTL {
        return Err("an endpoint and a TTL of at most 3600 s are required");
    }
    let mut dns = vec![0, 0, 0x80, 0, 0, 0];
    dns.extend_from_slice(&((endpoints.len() + foreign.len()) as u16).to_be_bytes());
    dns.extend_from_slice(&[0, 0, 0, 0]);
    let owner = [b"_dsip".to_vec(), z32_encode(&key.public()).into_bytes()];
    let owner_at = dns.len();
    for (i, ep) in endpoints.iter().enumerate() {
        if i == 0 {
            push_name_labels(&mut dns, &owner);
        } else {
            dns.extend_from_slice(&(0xC000u16 | owner_at as u16).to_be_bytes());
        }
        let mut rdata = vec![];
        let mut strings = vec![format!("uri={}", ep.uri)];
        strings.extend(ep.bindings.iter().map(|b| format!("b={b}")));
        if let Some(s) = &ep.service {
            strings.push(format!("svc={s}"));
        }
        for s in strings {
            if s.len() > 255 {
                return Err("a TXT string is longer than 255 bytes");
            }
            rdata.push(s.len() as u8);
            rdata.extend_from_slice(s.as_bytes());
        }
        dns.extend_from_slice(&16u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&ttl.to_be_bytes());
        dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        dns.extend_from_slice(&rdata);
    }
    for (labels, rtype, rttl, rdata) in foreign {
        push_name_labels(&mut dns, labels);
        dns.extend_from_slice(&rtype.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&rttl.to_be_bytes());
        dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        dns.extend_from_slice(rdata);
    }
    if dns.len() > 996 {
        return Err("the DNS message exceeds 996 bytes (BEP 44's 1000 once bencoded)");
    }
    let mut out = key.sign(&bep44_signable(ts, &dns, b"")).to_vec();
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&dns);
    Ok(out)
}

fn hexv(v: &Value) -> Vec<u8> {
    v.as_str().and_then(|s| (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect()).unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Run a `pkarr/` vector.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    let did = i["did"].as_str().unwrap_or("");
    let now = i["now"].as_i64().unwrap_or(0);
    let rejected = |r: Reject| json!({"outcome": "rejected", "reason": r.0});
    let hint_json = |h: Hint| {
        json!({"outcome": "hint", "subject": h.subject, "seq": h.seq, "issued_at": h.issued_at, "expires_at": h.expires_at,
               "endpoints": h.endpoints})
    };
    match i["check"].as_str().unwrap_or("") {
        "hint" => read(did, &hexv(&i["payload"]), now).map(hint_json).unwrap_or_else(rejected),
        "select" => {
            let new = match read(did, &hexv(&i["payload"]), now) {
                Ok(h) => h,
                Err(r) => return rejected(r),
            };
            let Ok(held) = read(did, &hexv(&i["held"]), now) else { return json!({"winner": "input", "conflict": "none"}) };
            match new.seq.cmp(&held.seq) {
                std::cmp::Ordering::Greater => json!({"winner": "input", "conflict": "newer-seq"}),
                std::cmp::Ordering::Less => json!({"winner": "held", "conflict": "older-seq"}),
                std::cmp::Ordering::Equal => {
                    let same = i["payload"] == i["held"];
                    json!({"winner": "held", "conflict": if same { "none" } else { "same-seq-live" }})
                }
            }
        }
        "bep44-signable" => json!({"bytes": hex(&bep44_signable(i["seq"].as_u64().unwrap_or(0), &hexv(&i["value"]), &hexv(&i["salt"])))}),
        "bep44-verify" => {
            let key: Option<[u8; 32]> = hexv(&i["public_key"]).try_into().ok();
            let msg = bep44_signable(i["seq"].as_u64().unwrap_or(0), &hexv(&i["value"]), &hexv(&i["salt"]));
            json!({"valid": key.is_some_and(|k| verify(&k, &msg, &hexv(&i["signature"])))})
        }
        "carry" => match carry(i["zone"].as_str().unwrap_or(""), &hexv(&i["dns"])) {
            Ok(keep) => json!({"keep": keep.iter().map(|(labels, t, ttl, rdata)| {
                let mut w = vec![];
                push_name_labels(&mut w, labels);
                json!({"name": hex(&w), "type": t, "ttl": ttl, "rdata": hex(rdata)})
            }).collect::<Vec<_>>()}),
            Err(_) => json!({"error": "malformed"}),
        },
        "next-ts" => match next_ts(i["clock"].as_u64().unwrap_or(0), i["previous"].as_u64()) {
            Some(ts) => json!({"ts": ts}),
            None => json!({"error": "exhausted"}),
        },
        "z32-encode" => match <[u8; 32]>::try_from(hexv(&i["key"])) {
            Ok(k) => json!({"z32": z32_encode(&k)}),
            Err(_) => rejected(Reject("malformed")),
        },
        "z32-decode" => z32_decode(i["z32"].as_str().unwrap_or("")).map(|k| json!({"key": hex(&k)})).unwrap_or_else(rejected),
        other => json!({"error": format!("unknown check {other}")}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn publish_then_read_round_trip_keeping_foreign_records() {
        let key = KeyPair::from_seed([7u8; 32]);
        let did = key.did();
        let ts = 1_790_000_000_000_000u64;
        let eps = [
            PublishEndpoint { uri: "wss://relay.example/dsip".into(), bindings: vec!["ws/1.0".into()], service: None },
            PublishEndpoint { uri: "wss://backup.example/dsip".into(), bindings: vec!["ws/1.0".into()], service: Some("DSIPSignaling".into()) },
        ];
        let foreign = vec![(vec![b"_iroh".to_vec(), z32_encode(&key.public()).into_bytes()], 16u16, 300u32, vec![5, b'h', b'e', b'l', b'l', b'o'])];
        let payload = build_payload(&key, &eps, 1800, ts, &foreign).unwrap();
        assert!(verify_payload(&key.public(), &payload));
        let hint = read(&did, &payload, 1_790_000_010).unwrap();
        assert_eq!(hint.seq, ts);
        assert_eq!(hint.expires_at, 1_790_000_000 + 1800);
        assert_eq!(hint.endpoints.len(), 2);
        assert_eq!(hint.endpoints[1]["service"], "DSIPSignaling");
        let kept = foreign_records(&key.public(), &payload);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].3, vec![5, b'h', b'e', b'l', b'l', b'o']);
        assert!(build_payload(&key, &eps, 7200, ts, &[]).is_err());
    }
}
