//! Decoding received SNMPv1 and SNMPv2c notifications (BER) into the trap shape [`crate::normalize_trap`] takes.
//!
//! Spec: E§3 (a gateway receives traps on its LAN). RFC 1157 §4.1.6 (the v1 Trap-PDU), RFC 3416 §3 (PDUs, the
//! SNMPv2-Trap-PDU), RFC 3417 / X.690 (BER, the SMIv2 application types).
//!
//! Impl: community-based v1 and v2c traps only. InformRequest and SNMPv3 are refused for now: an inform must be
//! answered only after the hub's `accepted` (E§3), which this decoder alone cannot know.

use serde_json::{json, Value};

/// Why a datagram is not a trap this decoder handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotATrap(pub String);

fn bad(why: &str) -> NotATrap {
    NotATrap(why.to_string())
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), NotATrap> {
        let tag = *self.b.get(self.pos).ok_or(bad("truncated"))?;
        let first = *self.b.get(self.pos + 1).ok_or(bad("truncated"))?;
        let mut off = self.pos + 2;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(bad("unsupported length"));
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.b.get(off).ok_or(bad("truncated"))? as usize;
                off += 1;
            }
            l
        };
        let body = self.b.get(off..off + len).ok_or(bad("truncated"))?;
        self.pos = off + len;
        Ok((tag, body))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8], NotATrap> {
        let (t, body) = self.tlv()?;
        if t != tag {
            return Err(bad(&format!("expected tag {tag:#04x}, got {t:#04x}")));
        }
        Ok(body)
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

fn int(body: &[u8]) -> i64 {
    let mut v: i64 = if body.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
    for &b in body {
        v = (v << 8) | b as i64;
    }
    v
}

fn uint(body: &[u8]) -> u64 {
    body.iter().fold(0u64, |v, &b| (v << 8) | b as u64)
}

fn oid(body: &[u8]) -> Result<String, NotATrap> {
    let first = *body.first().ok_or(bad("empty OID"))?;
    let mut parts = vec![(first / 40).min(2) as u64, (first as u64).saturating_sub(40 * (first / 40).min(2) as u64)];
    let mut acc = 0u64;
    for &b in &body[1..] {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    Ok(parts.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

fn ip(body: &[u8]) -> Result<String, NotATrap> {
    if body.len() != 4 {
        return Err(bad("IpAddress is not 4 bytes"));
    }
    Ok(body.iter().map(u8::to_string).collect::<Vec<_>>().join("."))
}

/// A varbind value → `(type name, value as a string)`.
fn value(tag: u8, body: &[u8]) -> Result<(&'static str, String), NotATrap> {
    Ok(match tag {
        0x02 => ("Integer32", int(body).to_string()),
        0x04 => ("OCTET STRING", match std::str::from_utf8(body) {
            Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
            _ => body.iter().map(|b| format!("{b:02x}")).collect(),
        }),
        0x05 => ("NULL", String::new()),
        0x06 => ("OBJECT IDENTIFIER", oid(body)?),
        0x40 => ("IpAddress", ip(body)?),
        0x41 => ("Counter32", uint(body).to_string()),
        0x42 => ("Gauge32", uint(body).to_string()),
        0x43 => ("TimeTicks", uint(body).to_string()),
        0x46 => ("Counter64", uint(body).to_string()),
        0x44 => ("Opaque", body.iter().map(|b| format!("{b:02x}")).collect()),
        _ => return Err(bad(&format!("unsupported value type {tag:#04x}"))),
    })
}

fn varbinds(body: &[u8]) -> Result<Vec<Value>, NotATrap> {
    let mut r = Reader { b: body, pos: 0 };
    let mut out = vec![];
    while !r.done() {
        let vb = r.expect(0x30)?;
        let mut v = Reader { b: vb, pos: 0 };
        let name = oid(v.expect(0x06)?)?;
        let (tag, val) = v.tlv()?;
        let (typ, text) = value(tag, val)?;
        out.push(json!({"oid": name, "type": typ, "value": text}));
    }
    Ok(out)
}

/// Decode one SNMP datagram into the trap shape of the `device-events` `trap` check: `{version: "v1", enterprise,
/// agent_addr, generic, specific, timestamp, community, varbinds}` or `{version: "v2c", community, varbinds}`.
///
/// Spec: E§3.
pub fn decode_trap(datagram: &[u8]) -> Result<Value, NotATrap> {
    let mut top = Reader { b: datagram, pos: 0 };
    let msg = top.expect(0x30)?;
    let mut m = Reader { b: msg, pos: 0 };
    let version = int(m.expect(0x02)?);
    let community = String::from_utf8_lossy(m.expect(0x04)?).into_owned();
    let (pdu_tag, pdu) = m.tlv()?;
    let mut p = Reader { b: pdu, pos: 0 };
    match (version, pdu_tag) {
        (0, 0xA4) => {
            let enterprise = oid(p.expect(0x06)?)?;
            let agent = ip(p.expect(0x40)?)?;
            let generic = int(p.expect(0x02)?);
            let specific = int(p.expect(0x02)?);
            let timestamp = uint(p.expect(0x43)?);
            let vbs = varbinds(p.expect(0x30)?)?;
            Ok(json!({"version": "v1", "enterprise": enterprise, "agent_addr": agent, "generic": generic,
                      "specific": specific, "timestamp": timestamp, "community": community, "varbinds": vbs}))
        }
        (1, 0xA7) => {
            let _request_id = p.expect(0x02)?;
            let _error_status = p.expect(0x02)?;
            let _error_index = p.expect(0x02)?;
            let vbs = varbinds(p.expect(0x30)?)?;
            Ok(json!({"version": "v2c", "community": community, "varbinds": vbs}))
        }
        (1, 0xA6) => Err(bad("InformRequest: not handled yet (an inform is answered only after `accepted`, E§3)")),
        (3, _) => Err(bad("SNMPv3: not handled yet")),
        (v, t) => Err(bad(&format!("not a trap (version {v}, PDU {t:#04x})"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2c_linkdown_datagram() {
        // demos/snmp_trap.py v2c -:0 public 1234 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3=i:3
        let hex = "305202010104067075626c6963a745020101020100020100303a300e06082b06010201010300430204d23017060a2b06010603010104010006092b0601060301010503300f060a2b060102010202010103020103";
        let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let t = decode_trap(&bytes).unwrap();
        assert_eq!(t["version"], "v2c");
        assert_eq!(t["community"], "public");
        assert_eq!(t["varbinds"][0], json!({"oid": "1.3.6.1.2.1.1.3.0", "type": "TimeTicks", "value": "1234"}));
        assert_eq!(t["varbinds"][1]["value"], "1.3.6.1.6.3.1.1.5.3");
        assert_eq!(t["varbinds"][2], json!({"oid": "1.3.6.1.2.1.2.2.1.1.3", "type": "Integer32", "value": "3"}));
        let raw = crate::normalize_trap(&t);
        assert_eq!(raw["snmp"]["uptime"], 1234);
        assert_eq!(raw["snmp"]["trap_oid"], "1.3.6.1.6.3.1.1.5.3");
    }

    #[test]
    fn oid_and_integers() {
        assert_eq!(oid(&[0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x03]).unwrap(), "1.3.6.1.6.3.1.1.5.3");
        assert_eq!(oid(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0xce, 0x0f, 0x01]).unwrap(), "1.3.6.1.4.1.9999.1");
        assert_eq!(int(&[0xff]), -1);
        assert_eq!(int(&[0x00, 0x80]), 128);
    }
}
