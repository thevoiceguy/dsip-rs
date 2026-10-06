//! Signed syslog (RFC 5848, syslog-sign): a gateway's collector. Messages from a configured signer are held until a
//! verified Signature Block lists their hash, or `hold_s` passes.
//!
//! Spec: E§3 (signed syslog, v0.10), E§2 (the `syslog-signed` basis and its `signed` claim). The exact rules are
//! `impl/vectors/README.md`, component `syslog-sign`.
//!
//! Impl: DSA verification is RustCrypto's `dsa`, which truncates the digest to q's length in bytes. That equals FIPS
//! 186's truncation for every q a signer can use with these versions (160, 224, 256 bits).

use base64::Engine as _;
use dsa::signature::hazmat::PrehashVerifier as _;
use dsa::{BigUint, Components, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha1::Digest as _;
use std::collections::{BTreeMap, HashMap, HashSet};

const SIG_PARAMS: [&str; 9] = ["VER", "RSID", "SG", "SPRI", "GBC", "FMN", "CNT", "HB", "SIGN"];
const CERT_PARAMS: [&str; 9] = ["VER", "RSID", "SG", "SPRI", "TPBL", "INDEX", "FLEN", "FRAG", "SIGN"];

/// A hash algorithm a supported version names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Alg {
    Sha1,
    Sha256,
}

impl Alg {
    fn of(ver: &str) -> Option<Alg> {
        match ver {
            "0111" => Some(Alg::Sha1),
            "0121" => Some(Alg::Sha256),
            _ => None,
        }
    }
    fn len(self) -> usize {
        match self {
            Alg::Sha1 => 20,
            Alg::Sha256 => 32,
        }
    }
    fn digest(self, b: &[u8]) -> Vec<u8> {
        match self {
            Alg::Sha1 => sha1::Sha1::digest(b).to_vec(),
            Alg::Sha256 => sha2::Sha256::digest(b).to_vec(),
        }
    }
}

struct Bad;

/// The fields one kind of block adds.
enum Fields {
    Sig { fmn: u64, hb: Vec<Vec<u8>> },
    Cert { index: u64, tpbl: u64, frag: Vec<u8> },
}

/// Padded standard base64, strictly.
fn b64(s: &str) -> Result<Vec<u8>, Bad> {
    if s.len() % 4 != 0 || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=') {
        return Err(Bad);
    }
    // RFC 4648 §3.5: non-zero unused bits in the last character are accepted
    const LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    LENIENT.decode(s).map_err(|_| Bad)
}

/// OpenPGP MPIs: a 2-byte bit count, then ⌈bits/8⌉ bytes. The count gives only the length.
fn mpis(b: &[u8]) -> Result<Vec<BigUint>, Bad> {
    let (mut out, mut i) = (vec![], 0);
    while i < b.len() {
        if i + 2 > b.len() {
            return Err(Bad);
        }
        let n = (u16::from_be_bytes([b[i], b[i + 1]]) as usize).div_ceil(8);
        if i + 2 + n > b.len() {
            return Err(Bad);
        }
        out.push(BigUint::from_bytes_be(&b[i + 2..i + 2 + n]));
        i += 2 + n;
    }
    Ok(out)
}

fn dec(s: &str, digits: usize, lo: u64, hi: Option<u64>) -> Result<u64, Bad> {
    let ok = !s.is_empty() && s.len() <= digits && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    let v: u64 = if ok { s.parse().map_err(|_| Bad)? } else { return Err(Bad) };
    if v < lo || hi.is_some_and(|h| v > h) {
        return Err(Bad);
    }
    Ok(v)
}

/// The index of the `]` closing the SD element that starts at `start`: outside quotes, honouring `\` escapes.
fn element_end(msg: &[u8], start: usize) -> Option<usize> {
    if msg.get(start) != Some(&b'[') {
        return None;
    }
    let (mut quoted, mut i) = (false, start + 1);
    while i < msg.len() {
        match msg[i] {
            b'\\' if quoted => {
                i += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            b']' if !quoted => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A configured signer (README component `syslog-sign`, `signers`).
struct Signer {
    kind: String,
    raw: Vec<u8>,
    sha256: String,
    key: VerifyingKey,
}

/// A signer's DSA key from its configured blob: a certificate's SubjectPublicKeyInfo (`C`) or four MPIs (`K`).
fn verifying_key(kind: &str, raw: &[u8]) -> Option<VerifyingKey> {
    if kind == "C" {
        use dsa::pkcs8::DecodePublicKey as _;
        use x509_parser::prelude::FromDer as _;
        let (_, c) = x509_parser::certificate::X509Certificate::from_der(raw).ok()?;
        return VerifyingKey::from_public_key_der(c.public_key().raw).ok();
    }
    let m = mpis(raw).ok()?;
    let [p, q, g, y] = <[BigUint; 4]>::try_from(m).ok()?;
    VerifyingKey::from_components(Components::from_components(p, q, g).ok()?, y).ok()
}

type Session = (String, String, String, u64); // hostname (lowercase), APP-NAME, PROCID, RSID
type Group = (Session, u64, u64); // session, SG, SPRI

struct Held {
    msg: Vec<u8>,
    sha256: String,
    due: i64,
}

struct Waiting {
    alg: Alg,
    hash: Vec<u8>,
    group: Group,
    number: u64,
    claim: Value,
    due: i64,
}

struct Frags {
    tpbl: u64,
    bytes: BTreeMap<u64, u8>,
}

/// A gateway's syslog-sign collector.
///
/// Spec: E§3 (signed syslog); README component `syslog-sign`.
pub struct Collector {
    now: i64,
    hold: i64,
    signers: HashMap<String, Signer>,
    held: Vec<Held>,
    waiting: Vec<Waiting>,
    frags: HashMap<Session, Frags>,
    sessions: HashMap<Session, Vec<u8>>,
    highest: HashMap<(String, String), u64>,
    authed: HashSet<(Group, u64)>,
}

/// What a step releases or reports.
///
/// Spec: E§3 (signed syslog); README component `syslog-sign` (emits).
#[derive(Debug, Clone)]
pub enum Out {
    /// A message to deposit, with its `signed` claim when a Signature Block verified it.
    Deposit {
        /// The whole syslog message.
        message: Vec<u8>,
        /// E§2's `signed` object, or `None`: deposit with the transport's basis.
        signed: Option<Value>,
    },
    /// A session was established: `{hostname, app_name, procid, rsid, key_sha256}`.
    Session(Value),
    /// A block was refused: `{block, reason}`.
    Refused(Value),
}

impl Out {
    /// The README's emit.
    pub fn to_json(&self) -> Value {
        match self {
            Out::Deposit { message, signed } => {
                json!({"deposit": {"sha256": hex(&sha2::Sha256::digest(message)), "signed": signed.clone().unwrap_or(Value::Null)}})
            }
            Out::Session(v) => json!({"session": v}),
            Out::Refused(v) => json!({"refused": v}),
        }
    }
}

/// One step's outputs.
pub type Emits = Vec<Out>;

fn field(sl: &Value, k: &str) -> String {
    sl[k].as_str().unwrap_or("").to_string()
}

impl Collector {
    /// A collector at `now`, holding for `hold_s`, with `signers` as `[{hostname, type, key}]` (key base64).
    pub fn new(now: i64, hold_s: i64, signers: &Value) -> Collector {
        let mut map = HashMap::new();
        for s in signers.as_array().into_iter().flatten() {
            let kind = s["type"].as_str().unwrap_or("").to_string();
            let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(s["key"].as_str().unwrap_or("")) else { continue };
            let Some(key) = verifying_key(&kind, &raw) else { continue };
            let sha256 = hex(&sha2::Sha256::digest(&raw));
            map.insert(s["hostname"].as_str().unwrap_or("").to_ascii_lowercase(), Signer { kind, raw, sha256, key });
        }
        Collector {
            now,
            hold: hold_s,
            signers: map,
            held: vec![],
            waiting: vec![],
            frags: HashMap::new(),
            sessions: HashMap::new(),
            highest: HashMap::new(),
            authed: HashSet::new(),
        }
    }

    /// Whether `hostname` is a configured signer's (so its messages are held).
    pub fn is_signer(&self, hostname: &str) -> bool {
        self.signers.contains_key(&hostname.to_ascii_lowercase())
    }

    /// The SHA-256 of each held message, in arrival order.
    pub fn held(&self) -> Vec<String> {
        self.held.iter().map(|h| h.sha256.clone()).collect()
    }

    /// How many signed hashes wait for their message.
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Receive one whole syslog message.
    pub fn receive(&mut self, msg: &[u8]) -> Emits {
        let unsigned = || vec![Out::Deposit { message: msg.to_vec(), signed: None }];
        let parsed = crate::syslog::parse_syslog(msg);
        let sl = &parsed["syslog"];
        if sl.is_null() || sl["format"] != "rfc5424" || sl["hostname"].is_null() {
            return unsigned();
        }
        let ids: Vec<&str> = sl["structured_data"].as_array().into_iter().flatten().filter_map(|e| e["id"].as_str()).collect();
        if let Some(kind) = ids.iter().find_map(|i| match *i {
            "ssign" => Some("ssign"),
            "ssign-cert" => Some("ssign-cert"),
            _ => None,
        }) {
            return self.block(msg, sl, kind);
        }
        if !self.is_signer(sl["hostname"].as_str().unwrap_or("")) {
            return unsigned();
        }
        if let Some(i) = self.waiting.iter().position(|w| w.alg.digest(msg) == w.hash) {
            let w = self.waiting.remove(i);
            self.authed.insert((w.group, w.number));
            return vec![Out::Deposit { message: msg.to_vec(), signed: Some(w.claim) }];
        }
        let sha256 = hex(&sha2::Sha256::digest(msg));
        self.held.push(Held { msg: msg.to_vec(), sha256, due: self.now + self.hold });
        vec![]
    }

    /// Advance the clock by `n` seconds: held messages now due are deposited unsigned; waiting hashes expire.
    pub fn advance(&mut self, n: i64) -> Emits {
        self.now += n;
        let now = self.now;
        let (due, keep): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held).into_iter().partition(|h| h.due <= now);
        self.held = keep;
        self.waiting.retain(|w| w.due > now);
        due.into_iter().map(|h| Out::Deposit { message: h.msg, signed: None }).collect()
    }

    fn block(&mut self, msg: &[u8], sl: &Value, kind: &'static str) -> Emits {
        let refused = |reason: &str| vec![Out::Refused(json!({"block": kind, "reason": reason}))];
        let sd = sl["structured_data"].as_array().cloned().unwrap_or_default();
        let names: &[&str] = if kind == "ssign-cert" { &CERT_PARAMS } else { &SIG_PARAMS };
        let parsed = (|| -> Result<_, Bad> {
            if sd.len() != 1 {
                return Err(Bad);
            }
            let params = sd[0]["params"].as_array().ok_or(Bad)?;
            if params.iter().map(|p| p["name"].as_str().unwrap_or("")).collect::<Vec<_>>() != names {
                return Err(Bad);
            }
            let v: HashMap<&str, &str> =
                params.iter().map(|p| (p["name"].as_str().unwrap_or(""), p["value"].as_str().unwrap_or(""))).collect();
            if v["VER"].len() != 4 {
                return Err(Bad);
            }
            let rsid = dec(v["RSID"], 10, 0, None)?;
            let sg = dec(v["SG"], 1, 0, Some(3))?;
            let spri = dec(v["SPRI"], 3, 0, Some(191))?;
            let rs = mpis(&b64(v["SIGN"])?)?;
            if rs.len() != 2 {
                return Err(Bad);
            }
            let extra = if kind == "ssign" {
                dec(v["GBC"], 10, 0, None)?;
                let fmn = dec(v["FMN"], 10, 1, None)?;
                let cnt = dec(v["CNT"], 2, 1, Some(99))?;
                let toks: Vec<&str> = v["HB"].split(' ').collect();
                if toks.len() as u64 != cnt || toks.contains(&"") {
                    return Err(Bad);
                }
                let hb = toks.iter().map(|t| b64(t)).collect::<Result<Vec<_>, _>>()?;
                if let Some(a) = Alg::of(v["VER"]) {
                    if hb.iter().any(|h| h.len() != a.len()) {
                        return Err(Bad);
                    }
                }
                Fields::Sig { fmn, hb }
            } else {
                let tpbl = dec(v["TPBL"], 8, 1, None)?;
                let index = dec(v["INDEX"], 8, 1, None)?;
                let flen = dec(v["FLEN"], 4, 1, None)?;
                let frag = v["FRAG"].as_bytes().to_vec();
                if frag.len() as u64 != flen || index + flen - 1 > tpbl {
                    return Err(Bad);
                }
                Fields::Cert { index, tpbl, frag }
            };
            Ok((v["VER"].to_string(), v["SIGN"].to_string(), rsid, sg, spri, rs, extra))
        })();
        let Ok((ver, sign, rsid, sg, spri, rs, extra)) = parsed else { return refused("malformed-block") };
        let Some(alg) = Alg::of(&ver) else { return refused("unsupported-version") };
        let host = field(sl, "hostname").to_ascii_lowercase();
        let Some(signer) = self.signers.get(&host) else { return refused("unknown-signer") };
        // the signed bytes: the message without ` SIGN="…"`, which ends just before the element's `]`
        let Some(start) = msg.iter().enumerate().filter(|(_, c)| **c == b' ').nth(5).map(|(i, _)| i + 1) else {
            return refused("malformed-block");
        };
        let Some(close) = element_end(msg, start) else { return refused("malformed-block") };
        let cut = format!(" SIGN=\"{sign}\"");
        if close < cut.len() || &msg[close - cut.len()..close] != cut.as_bytes() {
            return refused("malformed-block");
        }
        let signed = [&msg[..close - cut.len()], &msg[close..]].concat();
        let [r, s] = <[BigUint; 2]>::try_from(rs).unwrap_or_else(|_| unreachable!());
        let ok = Signature::from_components(r, s).ok().is_some_and(|sig| signer.key.verify_prehash(&alg.digest(&signed), &sig).is_ok());
        if !ok {
            return refused("bad-signature");
        }
        let (app, procid) = (field(sl, "app_name"), field(sl, "procid"));
        if rsid > 0 && rsid < self.highest.get(&(host.clone(), app.clone())).copied().unwrap_or(0) {
            return refused("old-session");
        }
        let session: Session = (host, app, procid, rsid);
        match extra {
            Fields::Cert { index, tpbl, frag } => self.cert(session, sl, index, tpbl, frag),
            Fields::Sig { fmn, hb } => self.sig(session, sl, sg, spri, fmn, hb, alg),
        }
    }

    fn cert(&mut self, session: Session, sl: &Value, index: u64, tpbl: u64, frag: Vec<u8>) -> Emits {
        let refused = |reason: &str| vec![Out::Refused(json!({"block": "ssign-cert", "reason": reason}))];
        let at = (index - 1) as usize;
        if let Some(pay) = self.sessions.get(&session) {
            if pay.len() as u64 == tpbl && pay.get(at..at + frag.len()) == Some(&frag[..]) {
                return vec![];
            }
            // a different payload for an established session: it ends, and assembly starts anew
            self.sessions.remove(&session);
            self.authed.retain(|(g, _)| g.0 != session);
            self.waiting.retain(|w| w.group.0 != session);
        }
        let st = self.frags.entry(session.clone()).or_insert_with(|| Frags { tpbl, bytes: BTreeMap::new() });
        if st.tpbl != tpbl || frag.iter().enumerate().any(|(i, c)| st.bytes.get(&(index - 1 + i as u64)).is_some_and(|x| x != c)) {
            return refused("fragment-mismatch");
        }
        for (i, c) in frag.iter().enumerate() {
            st.bytes.insert(index - 1 + i as u64, *c);
        }
        if (st.bytes.len() as u64) < st.tpbl {
            return vec![];
        }
        let payload: Vec<u8> = st.bytes.values().copied().collect();
        self.frags.remove(&session);
        let signer = &self.signers[&session.0];
        let parts: Vec<&[u8]> = payload.split(|c| *c == b' ').collect();
        let ok = parts.len() == 3
            && !parts[0].is_empty()
            && parts[1] == signer.kind.as_bytes()
            && std::str::from_utf8(parts[2]).ok().and_then(|t| b64(t).ok()).as_deref() == Some(&signer.raw[..]);
        if !ok {
            return refused("payload-mismatch");
        }
        let sha = signer.sha256.clone();
        self.sessions.insert(session.clone(), payload);
        let k = (session.0.clone(), session.1.clone());
        let h = self.highest.entry(k).or_insert(0);
        *h = (*h).max(session.3);
        vec![Out::Session(json!({"hostname": sl["hostname"], "app_name": sl["app_name"], "procid": sl["procid"],
                                 "rsid": session.3, "key_sha256": sha}))]
    }

    #[allow(clippy::too_many_arguments)]
    fn sig(&mut self, session: Session, sl: &Value, sg: u64, spri: u64, fmn: u64, hb: Vec<Vec<u8>>, alg: Alg) -> Emits {
        if !self.sessions.contains_key(&session) {
            return vec![Out::Refused(json!({"block": "ssign", "reason": "no-session"}))];
        }
        let key_sha = self.signers[&session.0].sha256.clone();
        let group: Group = (session.clone(), sg, spri);
        let mut out = vec![];
        for (i, h) in hb.into_iter().enumerate() {
            let n = fmn + i as u64;
            if self.authed.contains(&(group.clone(), n)) {
                continue;
            }
            let claim = json!({"hostname": sl["hostname"], "app_name": sl["app_name"], "procid": sl["procid"],
                               "rsid": session.3, "sg": sg, "spri": spri, "message_number": n, "key_sha256": key_sha});
            if let Some(j) = self.held.iter().position(|m| alg.digest(&m.msg) == h) {
                let m = self.held.remove(j);
                self.authed.insert((group.clone(), n));
                out.push(Out::Deposit { message: m.msg, signed: Some(claim) });
            } else if !self.waiting.iter().any(|w| w.group == group && w.number == n) {
                self.waiting.push(Waiting { alg, hash: h, group: group.clone(), number: n, claim, due: self.now + self.hold });
            }
        }
        out
    }
}

/// Run a `component: "syslog-sign"` trace.
pub fn run_trace(v: &Value) -> Value {
    let c = &v["context"];
    let mut col = Collector::new(c["now"].as_i64().unwrap_or(0), c["hold_s"].as_i64().unwrap_or(0), &c["signers"]);
    Value::Array(
        v["input"]["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|st| {
                let ev = &st["event"];
                let emit = match ev.get("receive") {
                    Some(r) => {
                        let m = r["message"].as_str().unwrap_or("");
                        let b: Vec<u8> = (0..m.len() / 2).filter_map(|i| u8::from_str_radix(&m[2 * i..2 * i + 2], 16).ok()).collect();
                        col.receive(&b)
                    }
                    None => col.advance(ev["advance"].as_i64().unwrap_or(0)),
                };
                json!({"emit": emit.iter().map(Out::to_json).collect::<Vec<_>>(), "held": col.held(), "waiting": col.waiting()})
            })
            .collect(),
    )
}
