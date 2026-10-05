//! Syslog (RFC 5424 and RFC 3164) parsed into `raw.syslog`, and syslog rules mapped to alarms.
//!
//! Spec: E§3 (a syslog message is carried as its fields; the severity table), E§4 (syslog rules). The
//! grammar is `impl/vectors/README.md`, `check: "syslog"`; the mapping is `check: "map"` for `raw.syslog`.
//!
//! Impl (spec-gap 103): RFC 3164 is accepted too, since most network equipment sends it; an unmatched
//! message the table maps to a severity raises `(source, syslog, app_name)`.

use serde_json::{json, Value};

const MONTHS: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

struct Malformed;

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn msg_text(b: &[u8]) -> String {
    text(b).trim_end_matches(['\r', '\n']).to_string()
}

/// A header token at `pos`: bytes 33–126 up to a space or the end; `-` alone is `null`.
fn token(b: &[u8], pos: usize, max: Option<usize>) -> Result<(Value, usize), Malformed> {
    let mut end = pos;
    while end < b.len() && b[end] != b' ' {
        if !(33..=126).contains(&b[end]) {
            return Err(Malformed);
        }
        end += 1;
    }
    let t = &b[pos..end];
    if t.is_empty() || max.is_some_and(|m| t.len() > m) {
        return Err(Malformed);
    }
    Ok((if t == b"-" { Value::Null } else { json!(text(t)) }, end))
}

fn sd_name(b: &[u8], pos: usize) -> Result<(String, usize), Malformed> {
    let mut end = pos;
    while end < b.len() && (33..=126).contains(&b[end]) && !b"= ]\"".contains(&b[end]) {
        end += 1;
    }
    if !(1..=32).contains(&(end - pos)) {
        return Err(Malformed);
    }
    Ok((text(&b[pos..end]), end))
}

fn parse_5424(b: &[u8], mut pos: usize, out: &mut serde_json::Map<String, Value>) -> Result<(), Malformed> {
    for (name, max) in [("timestamp", None), ("hostname", Some(255)), ("app_name", Some(48)), ("procid", Some(128)), ("msgid", Some(32))] {
        if b.get(pos) != Some(&b' ') {
            return Err(Malformed);
        }
        let (v, next) = token(b, pos + 1, max)?;
        out.insert(name.into(), v);
        pos = next;
    }
    if b.get(pos) != Some(&b' ') {
        return Err(Malformed);
    }
    pos += 1;
    let mut sd = vec![];
    if b.get(pos) == Some(&b'-') {
        pos += 1;
    } else {
        if b.get(pos) != Some(&b'[') {
            return Err(Malformed);
        }
        while b.get(pos) == Some(&b'[') {
            let (id, p) = sd_name(b, pos + 1)?;
            pos = p;
            let mut params = vec![];
            while b.get(pos) == Some(&b' ') {
                let (name, p) = sd_name(b, pos + 1)?;
                pos = p;
                if b.get(pos..pos + 2) != Some(b"=\"") {
                    return Err(Malformed);
                }
                pos += 2;
                let mut val = vec![];
                loop {
                    let c = *b.get(pos).ok_or(Malformed)?;
                    if c == b'\\' && pos + 1 < b.len() {
                        let n = b[pos + 1];
                        if b"\"\\]".contains(&n) {
                            val.push(n);
                        } else {
                            val.extend_from_slice(&[c, n]);
                        }
                        pos += 2;
                    } else if c == b'"' {
                        pos += 1;
                        break;
                    } else {
                        val.push(c);
                        pos += 1;
                    }
                }
                params.push(json!({"name": name, "value": text(&val)}));
            }
            if b.get(pos) != Some(&b']') {
                return Err(Malformed);
            }
            pos += 1;
            sd.push(json!({"id": id, "params": params}));
        }
    }
    out.insert("structured_data".into(), Value::Array(sd));
    let msg = if pos == b.len() {
        String::new()
    } else if b[pos] == b' ' {
        let m = &b[pos + 1..];
        msg_text(m.strip_prefix(b"\xef\xbb\xbf".as_slice()).unwrap_or(m))
    } else {
        return Err(Malformed);
    };
    out.insert("msg".into(), json!(msg));
    Ok(())
}

fn digit2(b: &[u8]) -> Option<u32> {
    (b.len() == 2 && b.iter().all(u8::is_ascii_digit)).then(|| (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32)
}

fn ts3164(b: &[u8]) -> bool {
    if b.len() < 16 || b[15] != b' ' || !MONTHS.contains(&&b[..3]) || b[3] != b' ' || b[6] != b' ' {
        return false;
    }
    let dd = &b[4..6];
    let day_ok = (dd[0] == b' ' && (b'1'..=b'9').contains(&dd[1])) || digit2(dd).is_some_and(|d| (10..=31).contains(&d));
    let t = &b[7..15];
    day_ok
        && t[2] == b':'
        && t[5] == b':'
        && digit2(&t[0..2]).is_some_and(|h| h <= 23)
        && digit2(&t[3..5]).is_some_and(|m| m <= 59)
        && digit2(&t[6..8]).is_some_and(|s| s <= 59)
}

fn parse_3164(rest: &[u8], out: &mut serde_json::Map<String, Value>) {
    out.insert("format".into(), json!("rfc3164"));
    let (mut ts, mut host, mut content) = (Value::Null, Value::Null, rest);
    if ts3164(rest) {
        ts = json!(text(&rest[..15]));
        let after = &rest[16..];
        let end = after.iter().position(|c| !(33..=126).contains(c)).unwrap_or(after.len());
        if end > 0 && after.get(end) == Some(&b' ') {
            host = json!(text(&after[..end]));
            content = &after[end + 1..];
        } else {
            content = after;
        }
    }
    let is_tag = |c: &u8| c.is_ascii_alphanumeric() || b"_.-/".contains(c);
    let run = content.iter().position(|c| !is_tag(c)).unwrap_or(content.len());
    let (mut app, mut pid, mut msg) = (Value::Null, Value::Null, content);
    if (1..=32).contains(&run) {
        let after = &content[run..];
        let rest_at = if after.first() == Some(&b':') {
            Some(run + 1)
        } else if after.first() == Some(&b'[') {
            let digits = after[1..].iter().take_while(|c| c.is_ascii_digit()).count();
            if (1..=10).contains(&digits) && after.get(1 + digits..3 + digits) == Some(b"]:") {
                pid = json!(text(&after[1..1 + digits]));
                Some(run + 3 + digits)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(at) = rest_at {
            app = json!(text(&content[..run]));
            msg = &content[at..];
            if msg.first() == Some(&b' ') {
                msg = &msg[1..];
            }
        }
    }
    for (k, v) in [("timestamp", ts), ("hostname", host), ("app_name", app), ("procid", pid), ("msgid", Value::Null)] {
        out.insert(k.into(), v);
    }
    out.insert("structured_data".into(), json!([]));
    out.insert("msg".into(), json!(msg_text(msg)));
}

/// `check: "syslog"`: one datagram → `{"syslog": {…}}` or `{"error": "malformed-syslog"}`.
///
/// Spec: E§3.
pub fn parse_syslog(b: &[u8]) -> Value {
    let bad = || json!({"error": "malformed-syslog"});
    if b.first() != Some(&b'<') {
        return bad();
    }
    let digits = b[1..].iter().take(4).take_while(|c| c.is_ascii_digit()).count();
    if !(1..=3).contains(&digits) || b.get(1 + digits) != Some(&b'>') || (digits > 1 && b[1] == b'0') {
        return bad();
    }
    let pri: u32 = b[1..1 + digits].iter().fold(0, |a, c| a * 10 + (c - b'0') as u32);
    if pri > 191 {
        return bad();
    }
    let at = 2 + digits;
    let mut out = serde_json::Map::new();
    out.insert("format".into(), Value::Null);
    out.insert("facility".into(), json!(pri / 8));
    out.insert("severity".into(), json!(pri % 8));
    let rest = &b[at..];
    let vlen = rest.iter().take(4).take_while(|c| c.is_ascii_digit()).count();
    let is_5424 = (1..=3).contains(&vlen) && rest[0] != b'0' && rest.get(vlen) == Some(&b' ');
    if is_5424 {
        if &rest[..vlen] != b"1" {
            return bad();
        }
        out.insert("format".into(), json!("rfc5424"));
        if parse_5424(b, at + vlen, &mut out).is_err() {
            return bad();
        }
    } else {
        parse_3164(rest, &mut out);
    }
    let keys = ["format", "facility", "severity", "timestamp", "hostname", "app_name", "procid", "msgid", "structured_data", "msg"];
    let ordered: serde_json::Map<String, Value> = keys.iter().map(|k| (k.to_string(), out[*k].clone())).collect();
    json!({"syslog": ordered})
}

/// `check: "map"` for `raw.syslog`: the first matching syslog rule, or the table's default (E§4).
///
/// Spec: E§4, E§3 (the severity table).
pub fn map_syslog(raw: &Value, rules: &Value, source: &str, table: &Value) -> Value {
    let sl = &raw["syslog"];
    let table_sev = || sl["severity"].as_i64().map(|s| crate::syslog_severity(s, table)).unwrap_or(Value::Null);
    for r in rules.as_array().into_iter().flatten() {
        let Some(want) = r.get("syslog").and_then(Value::as_object) else { continue };
        let mut ok = ["app_name", "msgid", "hostname"]
            .iter()
            .filter(|k| want.contains_key(**k))
            .all(|k| !sl[*k].is_null() && sl[*k] == want[*k]);
        if ok {
            if let Some(f) = want.get("facility") {
                ok = sl["facility"].as_i64().is_some() && sl["facility"].as_i64() == f.as_i64();
            }
        }
        if ok {
            if let Some(c) = want.get("msg_contains").and_then(Value::as_str) {
                ok = sl["msg"].as_str().is_some_and(|m| m.contains(c));
            }
        }
        if !ok {
            continue;
        }
        if r["action"] == "notify" {
            return json!({"notify": true});
        }
        let mut resource = source.to_string();
        if let (Some(id), Some(param)) = (r["resource_sd"]["id"].as_str(), r["resource_sd"]["param"].as_str()) {
            let el = sl["structured_data"].as_array().into_iter().flatten().find(|x| x["id"] == id);
            if let Some(p) = el.and_then(|e| e["params"].as_array()).into_iter().flatten().find(|p| p["name"] == param) {
                resource = format!("{source}/{}", p["value"].as_str().unwrap_or(""));
            }
        }
        if r["action"] == "clear" {
            return json!({"alarm": {"resource": resource, "type": r["type"], "qualifier": "", "severity": null, "cleared": true}});
        }
        let sev = if r["severity"].is_null() { table_sev() } else { r["severity"].clone() };
        if sev.is_null() {
            return json!({"notify": true});
        }
        return json!({"alarm": {"resource": resource, "type": r["type"], "qualifier": "", "severity": sev, "cleared": false}});
    }
    let sev = table_sev();
    if sev.is_null() {
        return json!({"notify": true});
    }
    let q = sl["app_name"].as_str().unwrap_or("");
    json!({"alarm": {"resource": source, "type": "syslog", "qualifier": q, "severity": sev, "cleared": false}})
}
