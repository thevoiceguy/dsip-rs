//! SNMPv3 over TLS: RFC 6353's TLS Transport Model with RFC 5591's Transport Security Model. A gateway's
//! framing of the TLS stream, its check of each message, RFC 5343 discovery, the certificate-to-name table,
//! and the Responses it sends.
//!
//! Spec: E§3 (SNMPv3 over TLS, v0.10), E§2 (the `snmpv3-tls` basis and its `tsm` claim). The exact rules are
//! `impl/vectors/README.md`, `check: "tsm"`, `check: "tls-frames"` and `check: "tsm-name"`.

use crate::usm::{hex, int, oid_tlv, ranged, scoped_content, tlv, unhex, Malformed, Rd, MAX31};
use serde_json::{json, Value};

/// The largest message a gateway reads from a TLS stream, header included.
pub const TLS_MAX: usize = 65_536;
/// RFC 5343 §3.1: the localEngineID placeholder a discovering sender names.
const LOCAL_ENGINE_ID: [u8; 5] = [0x80, 0, 0, 0, 6];
/// `snmpEngineID.0`.
const SNMP_ENGINE_ID: &str = "1.3.6.1.6.3.10.2.1.1.0";

/// Whole messages split from the head of a TLS stream.
///
/// Spec: E§3 (framing).
#[derive(Debug, Default)]
pub struct Frames {
    /// The whole messages, in order.
    pub messages: Vec<Vec<u8>>,
    /// Bytes taken from the stream; the rest waits (or, with `close`, cannot be framed).
    pub consumed: usize,
    /// The stream cannot be framed past `consumed`: close the connection.
    pub close: bool,
}

/// Split a TLS byte stream into whole BER messages.
///
/// Spec: E§3 (framing); README `check: "tls-frames"`.
pub fn split_frames(stream: &[u8]) -> Frames {
    let mut f = Frames::default();
    loop {
        let rest = &stream[f.consumed..];
        if rest.len() < 2 {
            return f;
        }
        if rest[0] != 0x30 || rest[1] == 0x80 || rest[1] >= 0x85 {
            f.close = true;
            return f;
        }
        let (hdr, n) = if rest[1] < 0x80 {
            (2, rest[1] as usize)
        } else {
            let k = (rest[1] & 0x7f) as usize;
            if rest.len() < 2 + k {
                return f;
            }
            (2 + k, rest[2..2 + k].iter().fold(0usize, |a, &x| (a << 8) | x as usize))
        };
        if hdr + n > TLS_MAX {
            f.close = true;
            return f;
        }
        if rest.len() < hdr + n {
            return f;
        }
        f.messages.push(rest[..hdr + n].to_vec());
        f.consumed += hdr + n;
    }
}

/// What a message from a TLS connection is, once it passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A trap: deposit it.
    Trap,
    /// An inform: deposit it, then answer with [`Received::response`].
    Inform,
    /// RFC 5343 discovery: answer at once with [`Received::discovery_response`].
    Discovery,
}

/// A message that passed E§3's checks.
#[derive(Debug, Clone)]
pub struct Received {
    /// Trap, inform or discovery.
    pub kind: Kind,
    /// The PDU's request-id.
    pub request_id: i64,
    /// The varbinds, as `{oid, type, value}`.
    pub varbinds: Vec<Value>,
    msg_id: i64,
    flags: u8,
    context_engine: Vec<u8>,
    context_name: Vec<u8>,
    varbind_bytes: Vec<u8>,
}

/// Check one message from a TLS connection: `malformed`, `unsupported-security-model`, `not-a-notification`.
///
/// Spec: E§3 (each message, discovery); README `check: "tsm"`.
pub fn receive(b: &[u8]) -> Result<Received, &'static str> {
    let parsed = (|| -> Result<_, Malformed> {
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
        if flags & 2 != 0 && flags & 1 == 0 {
            return Err(Malformed);
        }
        m.octets()?; // securityParameters: any content, not read (RFC 5591 §5.2)
        let (s, e) = m.expect(0x30)?; // always a plaintext ScopedPDU under TSM
        let pdu = scoped_content(b, s, e)?;
        m.finish()?;
        let mut q = Rd::new(b, s, e);
        let context_engine = q.octets()?.to_vec();
        let context_name = q.octets()?.to_vec();
        Ok((msg_id, flags, model, pdu, context_engine, context_name))
    })();
    let Ok((msg_id, flags, model, pdu, context_engine, context_name)) = parsed else { return Err("malformed") };
    if model != 4 {
        return Err("unsupported-security-model");
    }
    let kind = match pdu.tag {
        0xA7 => Kind::Trap,
        0xA6 => Kind::Inform,
        0xA0 if context_engine == LOCAL_ENGINE_ID && pdu.varbinds.len() == 1 && pdu.varbinds[0]["oid"] == SNMP_ENGINE_ID => {
            Kind::Discovery
        }
        _ => return Err("not-a-notification"),
    };
    Ok(Received {
        kind,
        request_id: pdu.request_id,
        varbinds: pdu.varbinds,
        msg_id,
        flags,
        context_engine,
        context_name,
        varbind_bytes: pdu.varbind_bytes,
    })
}

impl Received {
    fn message(&self, context_engine: &[u8], varbind_list: &[u8]) -> Vec<u8> {
        let pdu = tlv(0xA2, &[int(self.request_id), int(0), int(0), varbind_list.to_vec()].concat());
        let scoped = tlv(0x30, &[tlv(0x04, context_engine), tlv(0x04, &self.context_name), pdu].concat());
        let glob = tlv(0x30, &[int(self.msg_id), int(65_507), tlv(0x04, &[self.flags & !0x04]), int(4)].concat());
        tlv(0x30, &[int(3), glob, tlv(0x04, &[]), scoped].concat())
    }

    /// The Response to an inform: its msgID, request-id, varbinds, contextEngineID and contextName, its flags
    /// without reportable, TSM, empty securityParameters.
    ///
    /// Spec: E§3 (the response to an inform).
    pub fn response(&self) -> Vec<u8> {
        self.message(&self.context_engine, &self.varbind_bytes)
    }

    /// The answer to RFC 5343 discovery: in the localEngineID context it was asked in, `snmpEngineID.0` set to the
    /// gateway's engine ID.
    ///
    /// Spec: E§3 (discovery).
    pub fn discovery_response(&self, engine_id: &[u8]) -> Vec<u8> {
        let vb = tlv(0x30, &tlv(0x30, &[oid_tlv(SNMP_ENGINE_ID), tlv(0x04, engine_id)].concat()));
        self.message(&self.context_engine, &vb)
    }
}

fn lower_ascii(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

fn san_name(san: &Value) -> Option<String> {
    let v = san["value"].as_str()?;
    match san["type"].as_str()? {
        "rfc822" => {
            let i = v.rfind('@')?;
            Some(format!("{}{}", &v[..=i], lower_ascii(&v[i + 1..])))
        }
        "dns" => Some(lower_ascii(v)),
        "ip" => {
            let a = unhex(v)?;
            match a.len() {
                4 => Some(a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")),
                16 => Some(hex(&a)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// RFC 6353's certificate-to-name table, as E§3 pins it: rows in ascending `id`, a row matching the presented
/// certificate or a CA in its verified path, the first map that yields 1–32 bytes of name.
///
/// Spec: E§3 (the security name); README `check: "tsm-name"`.
pub fn security_name(cert: &Value, table: &Value) -> Value {
    let mut fps: Vec<String> = vec![cert["sha256"].as_str().unwrap_or("").to_lowercase()];
    fps.extend(cert["chain"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_lowercase));
    let sans: Vec<&Value> = cert["san"].as_array().into_iter().flatten().collect();
    let mut rows: Vec<&Value> = table.as_array().into_iter().flatten().collect();
    rows.sort_by_key(|r| r["id"].as_i64().unwrap_or(i64::MAX));
    for row in rows {
        let Some(fp) = row["fingerprint"].as_str() else { continue };
        if !fps.contains(&fp.to_lowercase()) {
            continue;
        }
        let first = |types: &[&str]| sans.iter().find(|s| s["type"].as_str().is_some_and(|t| types.contains(&t))).copied();
        let name = match row["map"].as_str().unwrap_or("") {
            "specified" => row["data"].as_str().map(str::to_string),
            "san-rfc822" => first(&["rfc822"]).and_then(san_name),
            "san-dns" => first(&["dns"]).and_then(san_name),
            "san-ip" => first(&["ip"]).and_then(san_name),
            "san-any" => first(&["rfc822", "dns", "ip"]).and_then(san_name),
            "common-name" => cert["cn"].get(0).and_then(Value::as_str).map(str::to_string),
            _ => None,
        };
        if let Some(n) = name.filter(|n| (1..=32).contains(&n.len())) {
            return json!({"security_name": n, "row": row["id"]});
        }
    }
    json!({"error": "no-security-name"})
}

/// Run a `check: "tsm"`, `"tls-frames"` or `"tsm-name"` vector.
pub fn run_check(i: &Value) -> Value {
    match i["check"].as_str() {
        Some("tsm") => match receive(&unhex(i["message"].as_str().unwrap_or("")).unwrap_or_default()) {
            Err(reason) => json!({"refused": {"reason": reason}}),
            Ok(r) => match r.kind {
                Kind::Discovery => json!({"discovery": {"request_id": r.request_id}}),
                k => {
                    let mut trap = json!({"version": "v3", "varbinds": r.varbinds});
                    if k == Kind::Inform {
                        trap["inform"] = json!({"request_id": r.request_id});
                    }
                    json!({"accepted": {"trap": trap}})
                }
            },
        },
        Some("tls-frames") => {
            let s = unhex(i["stream"].as_str().unwrap_or("")).unwrap_or_default();
            let f = split_frames(&s);
            let mut out = json!({"messages": f.messages.iter().map(|m| hex(m)).collect::<Vec<_>>(), "pending": hex(&s[f.consumed..])});
            if f.close {
                out["close"] = json!(true);
            }
            out
        }
        _ => security_name(&i["certificate"], &i["table"]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_parse_back_as_tsm_messages() {
        // net-snmp's discovery request: the gateway's answer must itself be a well-formed TSM message
        let inform = unhex("3043020103301102043a39be96020300ffe304010402010404003029040580000000060400a01e02040a2c07100201000201003010300e060a2b060106030a020101000500");
        let r = receive(&inform.expect("hex")).expect("discovery");
        assert_eq!(r.kind, Kind::Discovery);
        let engine = [0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4];
        let resp = r.discovery_response(&engine);
        assert_eq!(receive(&resp).err(), Some("not-a-notification")); // a Response-PDU: well-formed, not a notification
        // RFC 3412: answered in the context asked (the localEngineID), the engine ID only in snmpEngineID.0 — net-snmp
        // discards a Response whose contextEngineID differs from its request's
        let find = |needle: &[u8]| resp.windows(needle.len()).position(|w| w == needle);
        assert!(find(&tlv(0x04, &LOCAL_ENGINE_ID)).is_some());
        let vb = tlv(0x30, &[oid_tlv(SNMP_ENGINE_ID), tlv(0x04, &engine)].concat());
        assert!(find(&vb).is_some());
        assert_eq!(find(&tlv(0x04, &engine)), find(&vb).map(|i| i + 2 + oid_tlv(SNMP_ENGINE_ID).len()));
    }
}
