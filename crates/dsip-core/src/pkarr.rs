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
    let (key, ts, records) = open(did, payload, now)?;
    let owner: Vec<Vec<u8>> = vec![b"_dsip".to_vec(), z32_encode(&key).into_bytes()];
    let (mut eps, mut ttls) = (vec![], vec![]);
    for (nm, rtype, rclass, ttl, rdata) in records {
        if nm != owner || rtype != 16 || rclass != 1 {
            continue; // another record of this zone, or outside it: not DSIP's
        }
        eps.push(endpoint(&rdata)?);
        ttls.push(ttl);
    }
    finish_hint(did, ts, eps, ttls, now)
}

/// Steps 1–5 of `check: "hint"`: the DID's key, the timestamp and the parsed answer records.
fn open(did: &str, payload: &[u8], now: i64) -> Result<([u8; 32], u64, Vec<Answer>), Reject> {
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
    Ok((key, ts, parse_dns(dns)?))
}

fn finish_hint(did: &str, ts: u64, eps: Vec<Value>, ttls: Vec<u32>, now: i64) -> Result<Hint, Reject> {
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

fn strings(rdata: &[u8]) -> Result<Vec<&[u8]>, Reject> {
    let (mut out, mut i) = (vec![], 0);
    while i < rdata.len() {
        let n = rdata[i] as usize;
        out.push(rdata.get(i + 1..i + 1 + n).ok_or(Reject("malformed"))?);
        i += 1 + n;
    }
    Ok(out)
}

/// A pointer's TTL bound: 7 days (§9.1).
pub const POINTER_MAX_TTL: u32 = 604_800;

/// A multi-device identity's pointer (§9.1): the devices it lists, in record order, its `seq` and its expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pointer {
    /// The signed timestamp, µs.
    pub seq: u64,
    /// The timestamp's seconds plus the smallest `_dsip-devices` TTL.
    pub expires_at: i64,
    /// Listed device `did:key`s, a repeated one kept once.
    pub devices: Vec<String>,
}

/// Read an identity's pointer (`_dsip-devices` records signed by the identity key).
///
/// Spec: DHT Hints Profile §9.1; `check: "devices"`.
pub fn read_pointer(did: &str, payload: &[u8], now: i64) -> Result<Pointer, Reject> {
    let (key, ts, records) = open(did, payload, now)?;
    let owner: Vec<Vec<u8>> = vec![b"_dsip-devices".to_vec(), z32_encode(&key).into_bytes()];
    let (mut devices, mut ttls) = (Vec::<String>::new(), vec![]);
    for (nm, rtype, rclass, ttl, rdata) in records {
        if nm != owner || rtype != 16 || rclass != 1 {
            continue;
        }
        let vals: Vec<String> = strings(&rdata)?
            .into_iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .filter_map(|t| t.strip_prefix("dev=").map(String::from))
            .collect();
        if vals.len() != 1 || crate::did::public_from_did_key(&vals[0]).is_none() || !vals[0].starts_with("did:key:z") {
            return Err(Reject("bad-pointer"));
        }
        if !devices.contains(&vals[0]) {
            devices.push(vals[0].clone());
        }
        ttls.push(ttl);
    }
    if ttls.is_empty() {
        return Err(Reject("no-devices"));
    }
    if ttls.iter().any(|t| *t > POINTER_MAX_TTL) {
        return Err(Reject("ttl-too-long"));
    }
    let expires = (ts / 1_000_000) as i64 + *ttls.iter().min().unwrap_or(&0) as i64;
    if now >= expires {
        return Err(Reject("expired"));
    }
    Ok(Pointer { seq: ts, expires_at: expires, devices })
}

fn compact_envelope(s: &str) -> Option<crate::envelope::Envelope> {
    let parts: Vec<&str> = s.split('.').collect();
    let [p, b, g] = parts.as_slice() else { return None };
    Some(crate::envelope::Envelope { protected: p.to_string(), payload: b.to_string(), signature: g.to_string() })
}

/// One listed device resolved: its hint's endpoints and the expiry of the earlier of hint and delegation, or the
/// reason it does not count. `revocations` are compact `delegation-revocation` envelopes the reader holds.
///
/// Spec: DHT Hints Profile §9.1 (device hint, delegation record), §7.4 (the delegation verified).
pub fn read_device(did: &str, device: &str, payload: &[u8], now: i64, revocations: &[String]) -> Result<(Vec<Value>, i64), String> {
    let hint = read(device, payload, now).map_err(|r| r.0.to_string())?;
    let (dkey, _, records) = open(device, payload, now).map_err(|r| r.0.to_string())?;
    let owner: Vec<Vec<u8>> = vec![b"_dsip-delegation".to_vec(), z32_encode(&dkey).into_bytes()];
    let found: Vec<Vec<u8>> = records.into_iter().filter(|(n, t, c, _, _)| *n == owner && *t == 16 && *c == 1).map(|r| r.4).collect();
    let rdata = match found.as_slice() {
        [] => return Err("delegation-missing".into()),
        [one] => one,
        _ => return Err("delegation-invalid".into()),
    };
    let joined: Vec<u8> = strings(rdata).map_err(|_| "delegation-invalid".to_string())?.concat();
    let deleg = std::str::from_utf8(&joined).ok().and_then(compact_envelope).ok_or("delegation-invalid")?;
    let resolver = crate::did::StaticResolver::default();
    let mut ctx = crate::envelope::Context::new(now, &resolver);
    ctx.revocations = revocations.iter().filter_map(|r| compact_envelope(r)).collect();
    let v = crate::delegation::verify_delegation(&deleg, did, device, &ctx);
    if let Some(code) = v.code {
        return Err(serde_json::to_value(code).ok().and_then(|c| c.as_str().map(String::from)).unwrap_or_else(|| "delegation-invalid".into()));
    }
    let payload_json: Value = crate::b64::decode(&deleg.payload).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let dexp = payload_json["expires_at"].as_i64().unwrap_or(0);
    Ok((hint.endpoints, hint.expires_at.min(dexp)))
}

/// `check: "devices"`: an identity's pointer, then each listed device in order.
///
/// Spec: DHT Hints Profile §9.1.
pub fn devices(i: &Value) -> Value {
    let did = i["did"].as_str().unwrap_or("");
    let now = i["now"].as_i64().unwrap_or(0);
    let ptr = match read_pointer(did, &hexv(&i["payload"]), now) {
        Ok(p) => p,
        Err(r) => return json!({"outcome": "rejected", "reason": r.0}),
    };
    let revocations: Vec<String> = i["revocations"].as_array().into_iter().flatten().filter_map(|r| r.as_str().map(String::from)).collect();
    let out: Vec<Value> = ptr
        .devices
        .iter()
        .map(|dev| match i["devices"].get(dev).filter(|p| !p.is_null()) {
            None => json!({"device": dev, "outcome": "rejected", "reason": "unavailable"}),
            Some(p) => match read_device(did, dev, &hexv(p), now, &revocations) {
                Ok((eps, exp)) => json!({"device": dev, "outcome": "hint", "endpoints": eps, "expires_at": exp}),
                Err(reason) => json!({"device": dev, "outcome": "rejected", "reason": reason}),
            },
        })
        .collect();
    json!({"outcome": "devices", "seq": ptr.seq, "expires_at": ptr.expires_at, "devices": out})
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
    // §9.1: the publisher replaces its _dsip, _dsip-devices and _dsip-delegation records
    let owners: Vec<Vec<u8>> = [&b"_dsip"[..], b"_dsip-devices", b"_dsip-delegation"]
        .iter()
        .map(|lb| {
            let mut o = vec![lb.len() as u8];
            o.extend_from_slice(lb);
            o.push(zone.len() as u8);
            o.extend_from_slice(zone.as_bytes());
            o.push(0);
            o
        })
        .collect();
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
        if i >= an || rclass != 1 || owners.iter().any(|o| name.eq_ignore_ascii_case(o)) {
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

/// One record this publisher writes in its own zone: the first label (`_dsip`, `_dsip-devices`, `_dsip-delegation`),
/// the TXT character-strings, and the TTL.
type OwnRecord = (&'static [u8], Vec<Vec<u8>>, u32);

/// Build and sign a zone: `own` records under `<label>.<z32(key)>` (the zone label written once and pointed to, RFC
/// 1035 compression), then the `foreign` records carried over. The DNS message must stay within 996 bytes.
fn build_zone(key: &crate::keys::KeyPair, own: &[OwnRecord], ts: u64, foreign: &[ForeignRecord]) -> Result<Vec<u8>, &'static str> {
    let mut dns = vec![0, 0, 0x80, 0, 0, 0];
    dns.extend_from_slice(&((own.len() + foreign.len()) as u16).to_be_bytes());
    dns.extend_from_slice(&[0, 0, 0, 0]);
    let zone = z32_encode(&key.public()).into_bytes();
    let mut zone_at: Option<usize> = None;
    for (label, strings, ttl) in own {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label);
        match zone_at {
            Some(at) => dns.extend_from_slice(&(0xC000u16 | at as u16).to_be_bytes()),
            None => {
                zone_at = Some(dns.len());
                push_name_labels(&mut dns, std::slice::from_ref(&zone));
            }
        }
        let mut rdata = vec![];
        for st in strings {
            if st.len() > 255 {
                return Err("a TXT string is longer than 255 bytes");
            }
            rdata.push(st.len() as u8);
            rdata.extend_from_slice(st);
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

fn endpoint_records(endpoints: &[PublishEndpoint], ttl: u32) -> Vec<OwnRecord> {
    endpoints
        .iter()
        .map(|ep| {
            let mut strings = vec![format!("uri={}", ep.uri).into_bytes()];
            strings.extend(ep.bindings.iter().map(|b| format!("b={b}").into_bytes()));
            if let Some(svc) = &ep.service {
                strings.push(format!("svc={svc}").into_bytes());
            }
            (&b"_dsip"[..], strings, ttl)
        })
        .collect()
}

/// Build and sign a relay payload (`signature ‖ ts ‖ dns`) publishing `endpoints` as `_dsip` TXT records with `ttl`
/// (≤ 3600), plus any `foreign` records kept from the previous packet.
///
/// Spec: DHT Hints Profile §9 (publishing): signed by the identity key over BEP 44's buffer, no salt.
pub fn build_payload(key: &crate::keys::KeyPair, endpoints: &[PublishEndpoint], ttl: u32, ts: u64, foreign: &[ForeignRecord]) -> Result<Vec<u8>, &'static str> {
    if endpoints.is_empty() || ttl > MAX_TTL {
        return Err("an endpoint and a TTL of at most 3600 s are required");
    }
    build_zone(key, &endpoint_records(endpoints, ttl), ts, foreign)
}

/// Build and sign an identity's pointer: one `_dsip-devices` record per device (`dev=<did:key>`), `ttl` ≤ 604,800.
///
/// Spec: DHT Hints Profile §9.1 (pointer), signed by the identity key.
pub fn build_pointer_payload(identity: &crate::keys::KeyPair, devices: &[String], ttl: u32, ts: u64, foreign: &[ForeignRecord]) -> Result<Vec<u8>, &'static str> {
    if devices.is_empty() || ttl > POINTER_MAX_TTL {
        return Err("at least one device and a TTL of at most 604,800 s are required");
    }
    let own: Vec<OwnRecord> = devices.iter().map(|d| (&b"_dsip-devices"[..], vec![format!("dev={d}").into_bytes()], ttl)).collect();
    build_zone(identity, &own, ts, foreign)
}

/// Build and sign a device's zone: its `_dsip` endpoint records and its `_dsip-delegation` record (the compact
/// delegation split into 255-byte strings), all with `ttl` ≤ 3600.
///
/// Spec: DHT Hints Profile §9.1 (device hint), signed by the device key.
pub fn build_device_payload(
    device: &crate::keys::KeyPair,
    endpoints: &[PublishEndpoint],
    delegation: &str,
    ttl: u32,
    ts: u64,
    foreign: &[ForeignRecord],
) -> Result<Vec<u8>, &'static str> {
    if endpoints.is_empty() || ttl > MAX_TTL {
        return Err("an endpoint and a TTL of at most 3600 s are required");
    }
    let mut own = endpoint_records(endpoints, ttl);
    own.push((&b"_dsip-delegation"[..], delegation.as_bytes().chunks(255).map(<[u8]>::to_vec).collect(), ttl));
    build_zone(device, &own, ts, foreign)
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
        "devices" => devices(i),
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

    #[test]
    fn multi_device_pointer_and_device_zone_round_trip() {
        let identity = KeyPair::from_seed([1u8; 32]);
        let phone = KeyPair::from_seed([2u8; 32]);
        let (did, dev) = (identity.did(), phone.did());
        let now = 1_790_000_000i64;
        let ts = (now as u64 - 10) * 1_000_000;
        let deleg = crate::envelope::sign(
            &crate::delegation::delegation_payload(&did, &dev, now - 60, now + 7 * 86_400, &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"]),
            &identity,
            &identity.kid(),
        );
        let compact = format!("{}.{}.{}", deleg.protected, deleg.payload, deleg.signature);
        let ptr = build_pointer_payload(&identity, std::slice::from_ref(&dev), POINTER_MAX_TTL, ts, &[]).unwrap();
        let ep = PublishEndpoint { uri: "wss://relay.example/dsip".into(), bindings: vec!["ws/1.0".into()], service: None };
        let zone = build_device_payload(&phone, &[ep], &compact, 3600, ts, &[]).unwrap();
        assert!(zone.len() <= 1072, "a real delegation fits: {} bytes", zone.len());
        let out = devices(&json!({"did": did, "payload": hex(&ptr), "devices": {dev.clone(): hex(&zone)}, "now": now}));
        assert_eq!(out["outcome"], "devices", "{out}");
        assert_eq!(out["devices"][0]["outcome"], "hint", "{out}");
        assert_eq!(out["devices"][0]["endpoints"][0]["uri"], "wss://relay.example/dsip");
        // re-publishing carries nothing of its own records over
        assert!(carry(&z32_encode(&phone.public()), &zone[72..]).unwrap().is_empty());
    }
}
