//! `dsip-events` — the rules of the DSIP Device Events Profile (draft `device-events/0.1`,
//! `v0.9/dsip-device-events-profile-v0.9-draft.md`, cited `E§n`). Pure: no SNMP stack, no network.
//!
//! Spec: sections owned by this crate — E§3 (a received notification becomes an event: RFC 3584 §3.1
//! translation, the community never carried, the syslog severity table — [`normalize_trap`],
//! [`syslog_severity`]), E§4 (the rule table — [`map_alarm`]), E§5 and E§6 (the alarm list and the
//! escalation trigger — [`AlarmList`]).
//!
//! Impl (spec-gap 103): a re-raise reopens the same alarm and resets its operator state; the syslog
//! default table; escalation is run by a member (the agent), never by a mailbox. Every rule is pinned
//! by `impl/vectors/device-events/`; the Python reference is `impl/tools/dsipvec/events.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde_json::{json, Value};

const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";
const SNMP_TRAP_ADDRESS: &str = "1.3.6.1.6.3.18.1.3.0";
const SNMP_TRAP_COMMUNITY: &str = "1.3.6.1.6.3.18.1.4.0";
const SNMP_TRAP_ENTERPRISE: &str = "1.3.6.1.6.3.1.1.4.3.0";
const SEVERITIES: [&str; 5] = ["indeterminate", "warning", "minor", "major", "critical"];
const SILENT: &str = "dsip-gateway-silent";

/// Severity order; a token outside the registry orders as `indeterminate`.
///
/// Spec: E§5 (registry-governed severities with fallback).
pub fn rank(severity: &str) -> usize {
    SEVERITIES.iter().position(|s| *s == severity).unwrap_or(0)
}

fn vb(oid: &str, typ: &str, value: &Value) -> Value {
    json!({"oid": oid, "type": typ, "value": value})
}

/// A received SNMP notification → the event's `raw.snmp`, or `{"error": "malformed-trap"}`.
///
/// Spec: E§3 — SNMPv1 per RFC 3584 §3.1 (the gateway is a proxy, so `snmpTrapAddress.0` and
/// `snmpTrapEnterprise.0` are appended when absent); SNMPv2c/v3 lift `sysUpTime.0` and `snmpTrapOID.0`
/// (RFC 3416 §4.2.6); `snmpTrapCommunity.0` is dropped in every case.
pub fn normalize_trap(t: &Value) -> Value {
    // varbinds: an array of {oid: string, type: string, value}; exactly those three members are carried
    let shape_ok = t["varbinds"].as_array().is_some_and(|a| {
        a.iter().all(|x| x["oid"].is_string() && x["type"].is_string() && x.as_object().is_some_and(|o| o.contains_key("value")))
    });
    if !shape_ok {
        return json!({"error": "malformed-trap"});
    }
    let mut vbs: Vec<Value> = t["varbinds"].as_array().into_iter().flatten().map(|x| vb(x["oid"].as_str().unwrap_or(""), x["type"].as_str().unwrap_or(""), &x["value"])).collect();
    let oid_of = |v: &Value| v["oid"].as_str().unwrap_or("").to_string();
    let (uptime, trap_oid) = match t["version"].as_str() {
        Some("v1") => {
            let int = |k: &str| t[k].as_i64().is_some();
            let fields_ok = t["enterprise"].is_string() && t["agent_addr"].is_string() && int("specific") && int("timestamp")
                && t["generic"].as_i64().is_some_and(|g| (0..=6).contains(&g));
            if !fields_ok {
                return json!({"error": "malformed-trap"});
            }
            let ent = t["enterprise"].as_str().unwrap_or("");
            let g = t["generic"].as_i64().unwrap_or(-1);
            let trap_oid = if g == 6 { format!("{ent}.0.{}", t["specific"]) } else { format!("1.3.6.1.6.3.1.1.5.{}", g + 1) };
            let present: Vec<String> = vbs.iter().map(oid_of).collect();
            if !present.iter().any(|o| o == SNMP_TRAP_ADDRESS) {
                vbs.push(vb(SNMP_TRAP_ADDRESS, "IpAddress", &t["agent_addr"]));
            }
            if !present.iter().any(|o| o == SNMP_TRAP_ENTERPRISE) {
                vbs.push(vb(SNMP_TRAP_ENTERPRISE, "OBJECT IDENTIFIER", &t["enterprise"]));
            }
            (t["timestamp"].clone(), json!(trap_oid))
        }
        Some("v2c" | "v3") => {
            if vbs.len() < 2 || oid_of(&vbs[0]) != SYS_UPTIME || oid_of(&vbs[1]) != SNMP_TRAP_OID {
                return json!({"error": "malformed-trap"});
            }
            let Some(uptime) = vbs[0]["value"].as_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).and_then(|s| s.parse::<i64>().ok()).filter(|n| *n < (1i64 << 53)).filter(|_| vbs[1]["value"].is_string()) else {
                return json!({"error": "malformed-trap"});
            };
            let uptime = Value::from(uptime);
            let trap_oid = vbs[1]["value"].clone();
            vbs.drain(..2);
            (uptime, trap_oid)
        }
        _ => return json!({"error": "malformed-trap"}),
    };
    // E§3: the community is a shared secret — never carried
    vbs.retain(|v| oid_of(v) != SNMP_TRAP_COMMUNITY);
    json!({"snmp": {"version": t["version"], "uptime": uptime, "trap_oid": trap_oid, "varbinds": vbs}})
}

/// RFC 5424 severity → alarm severity, or `None` (an event, not an alarm).
///
/// Spec: E§3. Impl (spec-gap 103): the default table 0–2 critical, 3 major, 4 warning, 5–7 none;
/// `table` (string keys) overrides it.
pub fn syslog_severity(severity: i64, table: &Value) -> Value {
    if let Some(v) = table.get(severity.to_string()) {
        return v.clone();
    }
    match severity {
        0..=2 => json!("critical"),
        3 => json!("major"),
        4 => json!("warning"),
        _ => Value::Null,
    }
}

/// The first matching rule → `{"alarm": …}`, otherwise `{"notify": true}`.
///
/// Spec: E§4 (a rule table shaped like RFC 3877's `alarmModelTable`).
pub fn map_alarm(raw: &Value, rules: &Value, source: &str) -> Value {
    let snmp = &raw["snmp"];
    let vbs = snmp["varbinds"].as_array().cloned().unwrap_or_default();
    let as_text = |v: &Value| v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
    for r in rules.as_array().into_iter().flatten() {
        if r["trap_oid"] != snmp["trap_oid"] {
            continue;
        }
        if let Some(want) = r.get("varbind") {
            if !vbs.iter().any(|x| x["oid"] == want["oid"] && as_text(&x["value"]) == as_text(&want["value"])) {
                continue;
            }
        }
        if r["action"] == "notify" {
            return json!({"notify": true});
        }
        let mut resource = source.to_string();
        if let Some(prefix) = r["resource_varbind"].as_str() {
            let dotted = format!("{prefix}.");
            if let Some(hit) = vbs.iter().find(|x| x["oid"].as_str().is_some_and(|o| o == prefix || o.starts_with(&dotted))) {
                resource = format!("{source}/{}", as_text(&hit["value"]));
            }
        }
        let cleared = r["action"] == "clear";
        let severity = if cleared { Value::Null } else { r["severity"].clone() };
        return json!({"alarm": {"resource": resource, "type": r["type"], "qualifier": "", "severity": severity, "cleared": cleared}});
    }
    json!({"notify": true})
}

type Key = (String, String, String);

#[derive(Clone)]
struct Alarm {
    severity: String,
    cleared: bool,
    operator: String,
    count: u64,
    due: Option<i64>,
    escalated: bool,
}

/// The alarm list every member of the alarm group computes from its ordered content; the escalation
/// agent also acts on its `escalate` emissions.
///
/// Spec: E§5 (raise, repeat, change, clear, reopen; operator state; gateway silence), E§6 (the trigger).
pub struct AlarmList {
    now: i64,
    policy: Option<(String, i64)>,
    alarms: BTreeMap<Key, Alarm>,
    gateways: BTreeMap<String, (i64, i64)>, // gateway → (interval_s, last heartbeat)
}

fn key_of(v: &Value) -> Key {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    (s("resource"), s("type"), s("qualifier"))
}

fn jkey(k: &Key) -> Value {
    json!([k.0, k.1, k.2])
}

impl AlarmList {
    /// A list from the trace context `{now, escalation?: {min_severity, after_s}}`.
    pub fn new(ctx: &Value) -> AlarmList {
        let policy = ctx.get("escalation").filter(|p| p.is_object()).map(|p| {
            (p["min_severity"].as_str().unwrap_or("").to_string(), p["after_s"].as_i64().unwrap_or(0))
        });
        AlarmList { now: ctx["now"].as_i64().unwrap_or(0), policy, alarms: BTreeMap::new(), gateways: BTreeMap::new() }
    }

    /// E§6: keep, start or cancel the escalation timer after any change.
    fn arm(&mut self, k: &Key) {
        let now = self.now;
        let Some(a) = self.alarms.get_mut(k) else { return };
        let eligible = self.policy.as_ref().is_some_and(|(min, _)| {
            !a.cleared && a.operator == "none" && !a.escalated && rank(&a.severity) >= rank(min)
        });
        if !eligible {
            a.due = None;
        } else if a.due.is_none() {
            a.due = Some(now + self.policy.as_ref().map(|p| p.1).unwrap_or(0));
        }
    }

    fn report(&mut self, r: &Value) -> Vec<Value> {
        let k = key_of(r);
        let cleared = r["cleared"] == json!(true);
        let severity = r["severity"].as_str().unwrap_or("").to_string();
        let Some(a) = self.alarms.get_mut(&k) else {
            if cleared {
                return vec![];
            }
            self.alarms.insert(k.clone(), Alarm { severity: severity.clone(), cleared: false, operator: "none".into(), count: 1, due: None, escalated: false });
            self.arm(&k);
            return vec![json!({"raised": {"key": jkey(&k), "severity": severity, "reopened": false}})];
        };
        a.count += 1;
        let out = if cleared {
            if a.cleared {
                return vec![];
            }
            a.cleared = true;
            json!({"cleared": {"key": jkey(&k)}})
        } else if a.cleared {
            // spec-gap 103: reopen the same alarm, operator state back to none, escalation re-armed
            a.cleared = false;
            a.severity = severity.clone();
            a.operator = "none".into();
            a.escalated = false;
            a.due = None;
            json!({"raised": {"key": jkey(&k), "severity": severity, "reopened": true}})
        } else if a.severity == severity {
            return vec![];
        } else {
            a.severity = severity.clone();
            json!({"changed": {"key": jkey(&k), "severity": severity}})
        };
        self.arm(&k);
        vec![out]
    }

    fn ack(&mut self, e: &Value) -> Vec<Value> {
        let k = key_of(&e["alarm"]);
        let state = e["state"].as_str().unwrap_or("").to_string();
        let Some(a) = self.alarms.get_mut(&k) else { return vec![] };
        if a.operator == "closed" || a.operator == state {
            return vec![];
        }
        a.operator = state.clone();
        self.arm(&k);
        vec![json!({"operator": {"key": jkey(&k), "state": state, "by": e["by"]}})]
    }

    fn silent_report(gateway: &str, cleared: bool) -> Value {
        json!({"resource": gateway, "type": SILENT, "qualifier": "", "severity": if cleared { Value::Null } else { json!("major") }, "cleared": cleared})
    }

    fn active(&self, k: &Key) -> bool {
        self.alarms.get(k).is_some_and(|a| !a.cleared)
    }

    fn heartbeat(&mut self, h: &Value) -> Vec<Value> {
        let g = h["gateway"].as_str().unwrap_or("").to_string();
        self.gateways.insert(g.clone(), (h["interval_s"].as_i64().unwrap_or(0), self.now));
        if self.active(&(g.clone(), SILENT.into(), String::new())) {
            return self.report(&Self::silent_report(&g, true));
        }
        vec![]
    }

    fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        let mut out = vec![];
        let gws: Vec<(String, (i64, i64))> = self.gateways.iter().map(|(g, v)| (g.clone(), *v)).collect();
        for (g, (interval, last)) in gws {
            if !self.active(&(g.clone(), SILENT.into(), String::new())) && self.now - last > 2 * interval {
                out.extend(self.report(&Self::silent_report(&g, false)));
            }
        }
        let mut due: Vec<(i64, Key)> = self.alarms.iter().filter_map(|(k, a)| a.due.filter(|d| *d <= self.now).map(|d| (d, k.clone()))).collect();
        due.sort();
        for (_, k) in due {
            if let Some(a) = self.alarms.get_mut(&k) {
                a.due = None;
                a.escalated = true;
                out.push(json!({"escalate": {"key": jkey(&k), "severity": a.severity}}));
            }
        }
        out
    }

    /// Apply one trace event: `report`, `ack`, `heartbeat` or `advance`. Returns the emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(r) = ev.get("report") {
            self.report(r)
        } else if let Some(a) = ev.get("ack") {
            self.ack(a)
        } else if let Some(h) = ev.get("heartbeat") {
            self.heartbeat(h)
        } else if let Some(n) = ev.get("advance").and_then(Value::as_i64) {
            self.advance(n)
        } else {
            vec![]
        }
    }

    /// The list, sorted by key, as the traces compare it.
    pub fn snapshot(&self) -> Value {
        Value::Array(
            self.alarms
                .iter()
                .map(|(k, a)| {
                    json!({"key": jkey(k), "severity": a.severity, "cleared": a.cleared, "operator": a.operator,
                           "count": a.count, "escalation_due": a.due})
                })
                .collect(),
        )
    }
}

/// Run a `device-events/` vector: a stateless check or an alarm-list trace.
pub fn run_vector(v: &Value) -> Value {
    let i = &v["input"];
    match i["check"].as_str() {
        Some("trap") => normalize_trap(&i["trap"]),
        Some("syslog-severity") => json!({"severity": syslog_severity(i["severity"].as_i64().unwrap_or(-1), &i["table"])}),
        Some("map") => map_alarm(&i["raw"], &i["rules"], i["source"].as_str().unwrap_or("")),
        Some(_) => json!({"error": "unknown check"}),
        None => {
            let mut m = AlarmList::new(&v["context"]);
            Value::Array(
                i["steps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|st| json!({"emit": m.step(&st["event"]), "alarms": m.snapshot()}))
                    .collect(),
            )
        }
    }
}
