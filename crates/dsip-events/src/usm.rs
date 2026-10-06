//! SNMPv3 with the User-based Security Model: a gateway's receiver, and the messages it sends back
//! (discovery and time-window Reports, the Response to an inform).
//!
//! Spec: E§3 (USM as RFC 3414 §3.2 orders it; RFC 7860 HMAC-SHA-2; RFC 3826 AES-128-CFB), E§2 (the
//! `usm` claim). The pipeline, its reason tokens and the BER rules are `impl/vectors/README.md`,
//! component `snmpv3`.
//!
//! Impl (spec-gap 103): `noAuthNoPriv` and DES are refused; a password user may omit its engine ID;
//! the first authenticated message from a trap engine seeds its time cache; only discovery and
//! time-window failures are reported.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const WINDOW: i64 = 150;
pub(crate) const MAX31: i64 = (1 << 31) - 1;
/// `usmStatsNotInTimeWindows.0`.
const NOT_IN_TIME_WINDOWS: &str = "1.3.6.1.6.3.15.1.1.2.0";
/// `usmStatsUnknownEngineIDs.0`.
const UNKNOWN_ENGINE_IDS: &str = "1.3.6.1.6.3.15.1.1.4.0";

/// An authentication protocol (E§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// HMAC-MD5-96 (RFC 3414).
    Md5,
    /// HMAC-SHA-96 (RFC 3414).
    Sha,
    /// HMAC-SHA-224, 128-bit MAC (RFC 7860).
    Sha224,
    /// HMAC-SHA-256, 192-bit MAC (RFC 7860).
    Sha256,
    /// HMAC-SHA-384, 256-bit MAC (RFC 7860).
    Sha384,
    /// HMAC-SHA-512, 384-bit MAC (RFC 7860).
    Sha512,
}

impl Auth {
    /// The protocol for a configuration token (`md5`, `sha`, `sha224`, `sha256`, `sha384`, `sha512`).
    pub fn parse(token: &str) -> Option<Auth> {
        Some(match token {
            "md5" => Auth::Md5,
            "sha" => Auth::Sha,
            "sha224" => Auth::Sha224,
            "sha256" => Auth::Sha256,
            "sha384" => Auth::Sha384,
            "sha512" => Auth::Sha512,
            _ => return None,
        })
    }

    /// The truncated MAC length carried in `msgAuthenticationParameters`.
    pub fn mac_len(self) -> usize {
        match self {
            Auth::Md5 | Auth::Sha => 12,
            Auth::Sha224 => 16,
            Auth::Sha256 => 24,
            Auth::Sha384 => 32,
            Auth::Sha512 => 48,
        }
    }

    fn hash(self, data: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest;
        macro_rules! h {
            ($t:ty) => {{
                let mut d = <$t>::new();
                for p in data {
                    d.update(p);
                }
                d.finalize().to_vec()
            }};
        }
        match self {
            Auth::Md5 => h!(md5::Md5),
            Auth::Sha => h!(sha1::Sha1),
            Auth::Sha224 => h!(sha2::Sha224),
            Auth::Sha256 => h!(sha2::Sha256),
            Auth::Sha384 => h!(sha2::Sha384),
            Auth::Sha512 => h!(sha2::Sha512),
        }
    }

    /// HMAC over `data` with `key`, truncated to the MAC length.
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! m {
            ($t:ty) => {{
                let mut m = <Hmac<$t>>::new_from_slice(key).expect("HMAC takes any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        let mut out = match self {
            Auth::Md5 => m!(md5::Md5),
            Auth::Sha => m!(sha1::Sha1),
            Auth::Sha224 => m!(sha2::Sha224),
            Auth::Sha256 => m!(sha2::Sha256),
            Auth::Sha384 => m!(sha2::Sha384),
            Auth::Sha512 => m!(sha2::Sha512),
        };
        out.truncate(self.mac_len());
        out
    }

    /// RFC 3414 A.2 (RFC 7860 §9.3 for SHA-2): the password expanded to 1 MiB and hashed, then localized
    /// as `H(Ku ‖ engine ‖ Ku)`.
    ///
    /// Spec: E§3.
    pub fn localize(self, password: &[u8], engine: &[u8]) -> Vec<u8> {
        let mut rep = Vec::with_capacity(1_048_576);
        while rep.len() < 1_048_576 {
            let n = (1_048_576 - rep.len()).min(password.len());
            rep.extend_from_slice(&password[..n]);
        }
        let ku = self.hash(&[&rep]);
        self.hash(&[&ku, engine, &ku])
    }
}

/// AES-128-CFB (128-bit feedback), RFC 3826 §3.1.
pub fn aes_cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8], decrypt: bool) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let c = aes::Aes128::new(key.into());
    let mut fb = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = aes::Block::from(fb);
        c.encrypt_block(&mut ks);
        let o: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let cipher_bytes = if decrypt { chunk } else { &o[..] };
        fb[..cipher_bytes.len()].copy_from_slice(cipher_bytes);
        out.extend_from_slice(&o);
    }
    out
}

/// `check: "usm-key"`: the localized key and the AES-128 privacy key derived from it.
///
/// Spec: E§3.
pub fn usm_key(i: &Value) -> Value {
    let (Some(auth), Some(pw), Some(eid)) = (i["auth"].as_str().and_then(Auth::parse), i["password"].as_str(), i["engine_id"].as_str().and_then(unhex)) else {
        return json!({"error": "bad-input"});
    };
    if pw.is_empty() {
        return json!({"error": "bad-password"});
    }
    let k = auth.localize(pw.as_bytes(), &eid);
    json!({"auth_key": hex(&k), "priv_key": hex(&k[..16])})
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

// --- BER, strictly as the README states it ---------------------------------------------------------

pub(crate) struct Malformed;
pub(crate) type R<T> = Result<T, Malformed>;

pub(crate) struct Rd<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: usize,
    pub(crate) end: usize,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8], start: usize, end: usize) -> Self {
        Rd { b, pos: start, end }
    }

    /// (tag, content start, content end).
    pub(crate) fn next(&mut self) -> R<(u8, usize, usize)> {
        if self.pos + 2 > self.end {
            return Err(Malformed);
        }
        let tag = self.b[self.pos];
        if tag & 0x1f == 0x1f {
            return Err(Malformed);
        }
        let first = self.b[self.pos + 1];
        let mut off = self.pos + 2;
        let n = if first < 0x80 {
            first as usize
        } else {
            let k = (first & 0x7f) as usize;
            if k == 0 || k > 4 || off + k > self.end {
                return Err(Malformed);
            }
            let n = self.b[off..off + k].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
            off += k;
            n
        };
        if n > self.end - off {
            return Err(Malformed);
        }
        self.pos = off + n;
        Ok((tag, off, off + n))
    }

    pub(crate) fn expect(&mut self, tag: u8) -> R<(usize, usize)> {
        let (t, s, e) = self.next()?;
        if t != tag {
            return Err(Malformed);
        }
        Ok((s, e))
    }

    pub(crate) fn int(&mut self) -> R<i64> {
        let (s, e) = self.expect(0x02)?;
        ber_int(&self.b[s..e])
    }

    pub(crate) fn octets(&mut self) -> R<&'a [u8]> {
        let (s, e) = self.expect(0x04)?;
        Ok(&self.b[s..e])
    }

    pub(crate) fn done(&self) -> bool {
        self.pos >= self.end
    }

    pub(crate) fn finish(&self) -> R<()> {
        if self.done() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

fn ber_int(c: &[u8]) -> R<i64> {
    if c.is_empty() || c.len() > 8 {
        return Err(Malformed);
    }
    let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in c {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

fn ber_uint(c: &[u8]) -> R<u64> {
    if c.is_empty() || c.len() > 9 || (c.len() == 9 && c[0] != 0) {
        return Err(Malformed);
    }
    Ok(c.iter().fold(0u64, |a, &b| (a << 8) | b as u64))
}

/// Counter32, Gauge32, TimeTicks: unsigned, at most 2^32−1 (RFC 2578).
fn u32_value(c: &[u8]) -> R<u64> {
    let v = ber_uint(c)?;
    if v > u32::MAX as u64 {
        return Err(Malformed);
    }
    Ok(v)
}

pub(crate) fn ranged(v: i64, lo: i64, hi: i64) -> R<i64> {
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        Err(Malformed)
    }
}

/// A BER OBJECT IDENTIFIER's content, dotted (README: the first subidentifier X gives 0.X, 1.(X−40) or 2.(X−80)).
fn ber_oid(c: &[u8]) -> R<String> {
    if c.is_empty() || c[c.len() - 1] & 0x80 != 0 {
        return Err(Malformed);
    }
    let mut subs: Vec<u128> = vec![];
    let mut acc: u128 = 0;
    for &x in c {
        acc = acc.checked_shl(7).ok_or(Malformed)? | (x & 0x7f) as u128;
        if acc > u64::MAX as u128 {
            return Err(Malformed);
        }
        if x & 0x80 == 0 {
            subs.push(acc);
            acc = 0;
        }
    }
    let x = subs[0];
    let mut parts = if x < 40 { vec![0, x] } else if x < 80 { vec![1, x - 40] } else { vec![2, x - 80] };
    parts.extend_from_slice(&subs[1..]);
    Ok(parts.iter().map(u128::to_string).collect::<Vec<_>>().join("."))
}

fn printable(c: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(c).ok()?;
    if s.chars().any(|ch| (ch as u32) <= 0x1f || (0x7f..=0x9f).contains(&(ch as u32))) {
        return None;
    }
    Some(s)
}

fn ber_value(tag: u8, c: &[u8]) -> R<(&'static str, String)> {
    Ok(match tag {
        0x02 => ("Integer32", ranged(ber_int(c)?, -(1 << 31), MAX31)?.to_string()),
        0x04 => ("OCTET STRING", printable(c).map(String::from).unwrap_or_else(|| hex(c))),
        0x05 if c.is_empty() => ("NULL", String::new()),
        0x06 => ("OBJECT IDENTIFIER", ber_oid(c)?),
        0x40 => {
            if c.len() != 4 {
                return Err(Malformed);
            }
            ("IpAddress", c.iter().map(u8::to_string).collect::<Vec<_>>().join("."))
        }
        0x41 => ("Counter32", u32_value(c)?.to_string()),
        0x42 => ("Gauge32", u32_value(c)?.to_string()),
        0x43 => ("TimeTicks", u32_value(c)?.to_string()),
        0x46 => ("Counter64", ber_uint(c)?.to_string()),
        0x44 => ("Opaque", hex(c)),
        _ => return Err(Malformed),
    })
}

/// A decoded PDU: its tag, request id, and varbinds (README shape).
pub(crate) struct Pdu {
    pub(crate) tag: u8,
    pub(crate) request_id: i64,
    pub(crate) varbinds: Vec<Value>,
    /// The raw varbind-list SEQUENCE (tag, length and content), echoed in a Response.
    pub(crate) varbind_bytes: Vec<u8>,
}

pub(crate) fn scoped_content(b: &[u8], s: usize, e: usize) -> R<Pdu> {
    let mut q = Rd::new(b, s, e);
    q.octets()?;
    q.octets()?;
    let (tag, ps, pe) = q.next()?;
    q.finish()?;
    let mut p = Rd::new(b, ps, pe);
    let request_id = ranged(p.int()?, -(1 << 31), MAX31)?;
    p.int()?;
    p.int()?;
    let vl_start = p.pos;
    let (vs, ve) = p.expect(0x30)?;
    p.finish()?;
    let mut varbinds = vec![];
    let mut v = Rd::new(b, vs, ve);
    while !v.done() {
        let (bs, be) = v.expect(0x30)?;
        let mut one = Rd::new(b, bs, be);
        let (os, oe) = one.expect(0x06)?;
        let (t, cs, ce) = one.next()?;
        one.finish()?;
        let (typ, val) = ber_value(t, &b[cs..ce])?;
        varbinds.push(json!({"oid": ber_oid(&b[os..oe])?, "type": typ, "value": val}));
    }
    Ok(Pdu { tag, request_id, varbinds, varbind_bytes: b[vl_start..ve].to_vec() })
}

fn parse_scoped_pdu(b: &[u8]) -> R<Pdu> {
    let mut r = Rd::new(b, 0, b.len());
    let (s, e) = r.expect(0x30)?;
    r.finish()?;
    scoped_content(b, s, e)
}

struct Msg {
    msg_id: i64,
    auth: bool,
    priv_: bool,
    reportable: bool,
    model: i64,
    engine: Vec<u8>,
    boots: i64,
    time: i64,
    user: Vec<u8>,
    auth_span: (usize, usize),
    priv_params: Vec<u8>,
    encrypted: Option<Vec<u8>>,
    pdu: Option<Pdu>,
}

fn parse_v3(b: &[u8]) -> R<Msg> {
    let mut top = Rd::new(b, 0, b.len());
    let (ms, me) = top.expect(0x30)?;
    top.finish()?;
    let mut m = Rd::new(b, ms, me);
    if m.int()? != 3 {
        return Err(Malformed);
    }
    let (gs, ge) = m.expect(0x30)?;
    let mut g = Rd::new(b, gs, ge);
    let msg_id = ranged(g.int()?, 0, MAX31)?;
    ranged(g.int()?, 484, MAX31)?;
    let flags = g.octets()?;
    if flags.len() != 1 {
        return Err(Malformed);
    }
    let flags = flags[0];
    let model = ranged(g.int()?, 0, MAX31)?;
    g.finish()?;
    let (auth, priv_, reportable) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
    if priv_ && !auth {
        return Err(Malformed);
    }
    let (ps, pe) = m.expect(0x04)?;
    let mut sp = Rd::new(b, ps, pe);
    let (ss, se) = sp.expect(0x30)?;
    sp.finish()?;
    let mut u = Rd::new(b, ss, se);
    let engine = u.octets()?.to_vec();
    if !(engine.is_empty() || (5..=32).contains(&engine.len())) {
        return Err(Malformed);
    }
    let boots = ranged(u.int()?, 0, MAX31)?;
    let time = ranged(u.int()?, 0, MAX31)?;
    let user = u.octets()?.to_vec();
    if user.len() > 32 {
        return Err(Malformed);
    }
    let auth_span = u.expect(0x04)?;
    let priv_params = u.octets()?.to_vec();
    u.finish()?;
    let (encrypted, pdu) = if priv_ {
        (Some(m.octets()?.to_vec()), None)
    } else {
        let (s, e) = m.expect(0x30)?;
        (None, Some(scoped_content(b, s, e)?))
    };
    m.finish()?;
    Ok(Msg { msg_id, auth, priv_, reportable, model, engine, boots, time, user, auth_span, priv_params, encrypted, pdu })
}

// --- the receiver -----------------------------------------------------------------------------------

/// A configured USM user (README component `snmpv3`, `users`).
#[derive(Debug, Clone)]
pub struct User {
    /// The engine this user is for; `None` matches the name from any engine (passwords only).
    pub engine_id: Option<Vec<u8>>,
    /// The user name.
    pub user: String,
    /// The authentication protocol.
    pub auth: Auth,
    /// A key already localized for `engine_id`, or a password.
    pub auth_secret: Secret,
    /// The privacy (AES-128) secret, for `authPriv`.
    pub priv_secret: Option<Secret>,
}

/// A localized key or a password (localized with the message's engine ID).
#[derive(Debug, Clone)]
pub enum Secret {
    /// A localized key.
    Key(Vec<u8>),
    /// A password.
    Password(String),
}

impl User {
    /// From the vectors' JSON shape: `{engine_id, user, auth, auth_key|auth_password, priv, priv_key|priv_password}`.
    pub fn from_json(u: &Value) -> Option<User> {
        let secret = |k: &str, p: &str| match (u[k].as_str(), u[p].as_str()) {
            (Some(h), _) => unhex(h).map(Secret::Key),
            (None, Some(pw)) => Some(Secret::Password(pw.to_string())),
            _ => None,
        };
        Some(User {
            engine_id: match u["engine_id"].as_str() {
                Some(h) => Some(unhex(&h.to_lowercase())?),
                None => None,
            },
            user: u["user"].as_str()?.to_string(),
            auth: Auth::parse(u["auth"].as_str()?)?,
            auth_secret: secret("auth_key", "auth_password")?,
            priv_secret: if u["priv"] == "aes128" { Some(secret("priv_key", "priv_password")?) } else { None },
        })
    }

    fn keys(&self, engine: &[u8]) -> (Vec<u8>, Option<[u8; 16]>) {
        let ak = match &self.auth_secret {
            Secret::Key(k) => k.clone(),
            Secret::Password(p) => self.auth.localize(p.as_bytes(), engine),
        };
        let pk = self.priv_secret.as_ref().and_then(|s| {
            let k = match s {
                Secret::Key(k) => k.clone(),
                Secret::Password(p) => self.auth.localize(p.as_bytes(), engine),
            };
            k.get(..16).and_then(|x| x.try_into().ok())
        });
        (ak, pk)
    }
}

#[derive(Debug, Clone)]
struct Cached {
    boots: i64,
    time: i64,
    latest: i64,
    at: i64,
}

/// What a receiver decided about one datagram.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// An authenticated, timely notification.
    Accepted {
        /// `{"version": "v3", "varbinds", "inform"?: {"request_id"}}` — the shape [`crate::normalize_trap`] takes.
        trap: Value,
        /// `{"engine_id", "user", "level"}`.
        usm: Value,
        /// For an inform: the Response to send once the hub has stored its event (E§3).
        response: Option<Vec<u8>>,
    },
    /// Refused, with the README's reason token, and the Report to send back, if any.
    Refused {
        /// The reason token.
        reason: &'static str,
        /// A Report (discovery, or time synchronization), when the gateway answers.
        report: Option<Vec<u8>>,
    },
}

/// A gateway's USM receiver: its engine, its users, and the time cache of the engines that send it traps.
///
/// Spec: E§3 (RFC 3414 §3.2); README component `snmpv3`.
pub struct UsmReceiver {
    engine: Vec<u8>,
    boots: i64,
    time0: i64,
    start: i64,
    now: i64,
    users: Vec<User>,
    cache: BTreeMap<Vec<u8>, Cached>,
    counter_unknown_engine: u32,
    counter_not_in_window: u32,
    salt: u64,
}

impl UsmReceiver {
    /// A receiver whose engine is `engine` with `boots`, at engine time `time` at the local clock `now`.
    pub fn new(engine: Vec<u8>, boots: i64, time: i64, now: i64, users: Vec<User>) -> UsmReceiver {
        UsmReceiver {
            engine,
            boots,
            time0: time,
            start: now,
            now,
            users,
            cache: BTreeMap::new(),
            counter_unknown_engine: 0,
            counter_not_in_window: 0,
            salt: (now as u64) << 20,
        }
    }

    /// Advance the local clock to `now` (seconds).
    pub fn set_now(&mut self, now: i64) {
        self.now = now.max(self.now);
    }

    fn local_time(&self) -> i64 {
        self.time0 + (self.now - self.start)
    }

    fn find_user(&self, engine: &[u8], name: &[u8]) -> Option<&User> {
        let name = std::str::from_utf8(name).ok()?;
        self.users
            .iter()
            .find(|u| u.engine_id.as_deref() == Some(engine) && u.user == name)
            .or_else(|| self.users.iter().find(|u| u.engine_id.is_none() && u.user == name))
    }

    /// Check one datagram (README component `snmpv3`, steps 1–10).
    ///
    /// Spec: E§3.
    pub fn receive(&mut self, b: &[u8]) -> Verdict {
        let refused = |reason| Verdict::Refused { reason, report: None };
        let Ok(mut m) = parse_v3(b) else { return refused("malformed") };
        if m.model != 3 {
            return refused("unsupported-security-model");
        }
        if m.engine.is_empty() {
            // RFC 3414 §4: discovery
            let report = m.reportable.then(|| {
                self.counter_unknown_engine = self.counter_unknown_engine.wrapping_add(1);
                let rid = m.pdu.as_ref().map(|p| p.request_id).unwrap_or(0);
                self.report(m.msg_id, &m.user, None, rid, UNKNOWN_ENGINE_IDS, self.counter_unknown_engine)
            });
            return Verdict::Refused { reason: "unknown-engine-id", report };
        }
        let Some(user) = self.find_user(&m.engine, &m.user).cloned() else { return refused("unknown-user") };
        if !m.auth || (m.priv_ && user.priv_secret.is_none()) {
            return refused("unsupported-security-level");
        }
        let (ak, pk) = user.keys(&m.engine);
        let l = user.auth.mac_len();
        let (s, e) = m.auth_span;
        if e - s != l {
            return refused("wrong-digest");
        }
        let mut zeroed = b.to_vec();
        zeroed[s..e].fill(0);
        let mac = user.auth.mac(&ak, &zeroed);
        if !ct_eq(&mac, &b[s..e]) {
            return refused("wrong-digest");
        }
        let authoritative = m.engine == self.engine;
        if authoritative {
            if self.boots == MAX31 || m.boots != self.boots || (m.time - self.local_time()).abs() > WINDOW {
                let report = m.reportable.then(|| {
                    self.counter_not_in_window = self.counter_not_in_window.wrapping_add(1);
                    let rid = m.pdu.as_ref().map(|p| p.request_id).unwrap_or(0);
                    self.report(m.msg_id, &m.user, Some((user.auth, &ak)), rid, NOT_IN_TIME_WINDOWS, self.counter_not_in_window)
                });
                return Verdict::Refused { reason: "not-in-time-window", report };
            }
        } else {
            let now = self.now;
            let c = self.cache.entry(m.engine.clone()).or_insert(Cached { boots: m.boots, time: m.time, latest: m.time, at: now });
            if m.boots > c.boots || (m.boots == c.boots && m.time > c.latest) {
                *c = Cached { boots: m.boots, time: m.time, latest: m.time, at: now };
            }
            if c.boots == MAX31 || m.boots < c.boots || (m.boots == c.boots && m.time < c.time + (now - c.at) - WINDOW) {
                return refused("not-in-time-window");
            }
        }
        let pdu = if m.priv_ {
            let Some(pk) = pk else { return refused("unsupported-security-level") };
            if m.priv_params.len() != 8 {
                return refused("decryption-error");
            }
            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&(m.boots as u32).to_be_bytes());
            iv[4..8].copy_from_slice(&(m.time as u32).to_be_bytes());
            iv[8..].copy_from_slice(&m.priv_params);
            let plain = aes_cfb(&pk, &iv, m.encrypted.as_deref().unwrap_or_default(), true);
            match parse_scoped_pdu(&plain) {
                Ok(p) => p,
                Err(_) => return refused("decryption-error"),
            }
        } else {
            match m.pdu.take() {
                Some(p) => p,
                None => return refused("malformed"),
            }
        };
        if pdu.tag != 0xA7 && pdu.tag != 0xA6 {
            return refused("not-a-notification");
        }
        if (pdu.tag == 0xA7) == authoritative {
            return refused("engine-id-mismatch");
        }
        let mut trap = json!({"version": "v3", "varbinds": pdu.varbinds});
        let mut response = None;
        if pdu.tag == 0xA6 {
            trap["inform"] = json!({"request_id": pdu.request_id});
            response = Some(self.response(&m, &user, &ak, pk.as_ref(), &pdu));
        }
        let level = if m.priv_ { "authPriv" } else { "authNoPriv" };
        Verdict::Accepted { trap, usm: json!({"engine_id": hex(&m.engine), "user": user.user, "level": level}), response }
    }

    /// The README's `engines` snapshot.
    pub fn snapshot(&self) -> Value {
        Value::Array(
            self.cache
                .iter()
                .map(|(k, c)| json!({"engine_id": hex(k), "boots": c.boots, "time": c.time + (self.now - c.at), "latest": c.latest}))
                .collect(),
        )
    }

    fn next_salt(&mut self) -> [u8; 8] {
        self.salt = self.salt.wrapping_add(1);
        self.salt.to_be_bytes()
    }

    /// A whole SNMPv3 message from the gateway's engine: `flags` and the scoped PDU, authenticated (and encrypted)
    /// with the given keys.
    fn message(&mut self, msg_id: i64, user: &[u8], flags: u8, auth: Option<(Auth, &[u8])>, priv_key: Option<&[u8; 16]>, scoped: Vec<u8>) -> Vec<u8> {
        let (boots, time) = (self.boots, self.local_time());
        let mac_len = auth.map(|(a, _)| a.mac_len()).unwrap_or(0);
        let (salt, data) = match priv_key {
            Some(k) => {
                let salt = self.next_salt();
                let mut iv = [0u8; 16];
                iv[..4].copy_from_slice(&(boots as u32).to_be_bytes());
                iv[4..8].copy_from_slice(&(time as u32).to_be_bytes());
                iv[8..].copy_from_slice(&salt);
                (salt.to_vec(), tlv(0x04, &aes_cfb(k, &iv, &scoped, false)))
            }
            None => (vec![], scoped),
        };
        let mut sec_body = tlv(0x04, &self.engine);
        sec_body.extend(int(boots));
        sec_body.extend(int(time));
        sec_body.extend(tlv(0x04, user));
        sec_body.extend(tlv(0x04, &vec![0u8; mac_len]));
        let priv_tlv = tlv(0x04, &salt);
        sec_body.extend(&priv_tlv);
        let sec = tlv(0x30, &sec_body);
        let mut glob = int(msg_id);
        glob.extend(int(65507));
        glob.extend(tlv(0x04, &[flags]));
        glob.extend(int(3));
        let mut body = int(3);
        body.extend(tlv(0x30, &glob));
        let sec_wrapped = tlv(0x04, &sec);
        body.extend(&sec_wrapped);
        body.extend(&data);
        let mut msg = tlv(0x30, &body);
        if let Some((a, key)) = auth {
            // the authParams content ends where the privParams TLV, the last thing in sec, begins
            let sec_at = find(&msg, &sec).expect("sec is in msg");
            let at = sec_at + sec.len() - priv_tlv.len() - mac_len;
            let mac = a.mac(key, &msg);
            msg[at..at + mac_len].copy_from_slice(&mac);
        }
        msg
    }

    fn report(&mut self, msg_id: i64, user: &[u8], auth: Option<(Auth, &[u8])>, request_id: i64, oid: &str, counter: u32) -> Vec<u8> {
        let vb = tlv(0x30, &[oid_tlv(oid), tlv(0x41, &uint_body(counter as u64))].concat());
        let pdu = tlv(0xA8, &[int(request_id), int(0), int(0), tlv(0x30, &vb)].concat());
        let scoped = tlv(0x30, &[tlv(0x04, &self.engine), tlv(0x04, b""), pdu].concat());
        let flags = if auth.is_some() { 0x01 } else { 0x00 };
        self.message(msg_id, user, flags, auth, None, scoped)
    }

    fn response(&mut self, m: &Msg, user: &User, ak: &[u8], pk: Option<&[u8; 16]>, pdu: &Pdu) -> Vec<u8> {
        let body = [int(pdu.request_id), int(0), int(0), pdu.varbind_bytes.clone()].concat();
        let scoped = tlv(0x30, &[tlv(0x04, &self.engine), tlv(0x04, b""), tlv(0xA2, &body)].concat());
        let flags = if m.priv_ { 0x03 } else { 0x01 };
        let pk = if m.priv_ { pk } else { None };
        self.message(m.msg_id, &m.user, flags, Some((user.auth, ak)), pk, scoped)
    }

    /// Run a `snmpv3` trace step (`receive` or `advance`).
    pub fn step(&mut self, ev: &Value) -> Value {
        if let Some(r) = ev.get("receive") {
            let b = r["datagram"].as_str().and_then(unhex).unwrap_or_default();
            return json!([match self.receive(&b) {
                Verdict::Accepted { trap, usm, .. } => json!({"accepted": {"trap": trap, "usm": usm}}),
                Verdict::Refused { reason, report } => json!({"refused": {"reason": reason, "report": report.is_some()}}),
            }]);
        }
        if let Some(n) = ev["advance"].as_i64() {
            self.now += n;
        }
        json!([])
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | len.len() as u8);
        out.extend_from_slice(&len);
    }
    out.extend_from_slice(body);
    out
}

pub(crate) fn int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((bytes[i] == 0 && bytes[i + 1] & 0x80 == 0) || (bytes[i] == 0xff && bytes[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    tlv(0x02, &bytes[i..])
}

fn uint_body(v: u64) -> Vec<u8> {
    let mut b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    b
}

pub(crate) fn oid_tlv(oid: &str) -> Vec<u8> {
    let p: Vec<u64> = oid.split('.').filter_map(|x| x.parse().ok()).collect();
    let mut subs = vec![p[0] * 40 + p[1]];
    subs.extend_from_slice(&p[2..]);
    let mut out = vec![];
    for mut s in subs {
        let mut chunk = vec![(s & 0x7f) as u8];
        s >>= 7;
        while s > 0 {
            chunk.push(0x80 | (s & 0x7f) as u8);
            s >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    tlv(0x06, &out)
}

/// Whether a datagram is an SNMPv3 message (its outer SEQUENCE starts with `INTEGER 3`), so a gateway routes it
/// to [`UsmReceiver`] rather than the community decoder.
pub fn is_v3(b: &[u8]) -> bool {
    let mut top = Rd::new(b, 0, b.len());
    let Ok((s, e)) = top.expect(0x30) else { return false };
    matches!(Rd::new(b, s, e).int(), Ok(3))
}

/// Run a `component: "snmpv3"` trace.
pub fn run_trace(v: &Value) -> Value {
    let c = &v["context"];
    let users = c["users"].as_array().into_iter().flatten().filter_map(User::from_json).collect();
    let mut r = UsmReceiver::new(
        c["local"]["engine_id"].as_str().and_then(unhex).unwrap_or_default(),
        c["local"]["boots"].as_i64().unwrap_or(0),
        c["local"]["time"].as_i64().unwrap_or(0),
        c["now"].as_i64().unwrap_or(0),
        users,
    );
    Value::Array(
        v["input"]["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|st| json!({"emit": r.step(&st["event"]), "engines": r.snapshot()}))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3414_a3_keys() {
        let eid = unhex("000000000000000000000002").unwrap();
        assert_eq!(hex(&Auth::Md5.localize(b"maplesyrup", &eid)), "526f5eed9fcce26f8964c2930787d82b");
        assert_eq!(hex(&Auth::Sha.localize(b"maplesyrup", &eid)), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn response_round_trips_through_a_receiver_of_the_other_side() {
        // an inform to our engine, answered; the Response decodes and authenticates under the same key
        let engine = unhex("80001f8880aaaaaaaaaaaaaaaa").unwrap();
        let user = User {
            engine_id: None,
            user: "ops".into(),
            auth: Auth::Sha256,
            auth_secret: Secret::Password("auth-pass-1".into()),
            priv_secret: Some(Secret::Password("priv-pass-2".into())),
        };
        let mut gw = UsmReceiver::new(engine.clone(), 1, 500, 1_790_000_000, vec![user.clone()]);
        let (ak, pk) = user.keys(&engine);
        let vbs = tlv(0x30, &[tlv(0x30, &[oid_tlv("1.3.6.1.2.1.1.3.0"), tlv(0x43, &[1])].concat()),
                              tlv(0x30, &[oid_tlv("1.3.6.1.6.3.1.1.4.1.0"), oid_tlv("1.3.6.1.6.3.1.1.5.3")].concat())].concat());
        let scoped = tlv(0x30, &[tlv(0x04, &engine), tlv(0x04, b""), tlv(0xA6, &[int(77), int(0), int(0), vbs].concat())].concat());
        let inform = gw.message(9, b"ops", 0x07, Some((Auth::Sha256, &ak)), pk.as_ref(), scoped);
        let Verdict::Accepted { trap, response: Some(resp), .. } = gw.receive(&inform) else { panic!("inform refused") };
        assert_eq!(trap["inform"]["request_id"], 77);
        let m = parse_v3(&resp).ok().expect("response parses");
        assert!(m.auth && m.priv_ && !m.reportable);
        assert_eq!(m.msg_id, 9);
        let mut zeroed = resp.clone();
        zeroed[m.auth_span.0..m.auth_span.1].fill(0);
        assert_eq!(Auth::Sha256.mac(&ak, &zeroed), resp[m.auth_span.0..m.auth_span.1]);
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&(m.boots as u32).to_be_bytes());
        iv[4..8].copy_from_slice(&(m.time as u32).to_be_bytes());
        iv[8..].copy_from_slice(&m.priv_params);
        let pdu = parse_scoped_pdu(&aes_cfb(&pk.unwrap(), &iv, m.encrypted.as_deref().unwrap(), true)).ok().unwrap();
        assert_eq!((pdu.tag, pdu.request_id, pdu.varbinds.len()), (0xA2, 77, 2));
    }
}
