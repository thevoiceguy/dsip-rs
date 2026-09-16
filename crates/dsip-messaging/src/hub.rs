//! The hub: per-group ordering authority and fan-out.
//!
//! Spec: M§6.5 (authenticate depositors, first valid commit per epoch wins, application messages
//! for the current or previous epoch, per-group `seq`, per-mailbox fan-out in `seq` order with
//! retry before later items), M§6.8 (external joins), M§7.3 (membership rules), M§9.3
//! (idempotent re-deposit), M§11.2 (ephemeral activity is forwarded, never sequenced).
//!
//! Impl: MLS is abstracted — a deposit event carries the epoch, a digest of the MLS bytes, and for
//! a commit its adds, removes, validity and whether it is external. Refusals without a
//! profile-specific token use `policy.blocked` (spec-gap 34 records the hub model).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};

/// Hub state for one group.
pub struct Hub {
    now: i64,
    kind: String,
    owner: Option<String>,
    epoch: i64,
    next_seq: i64,
    roster: BTreeMap<String, BTreeSet<String>>,
    digests: HashMap<String, i64>,
    seq_class: HashMap<i64, String>,
    pending: BTreeMap<String, Vec<i64>>,
    group_info: bool,
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

impl Hub {
    /// A hub from a vector `context`: `now`, `kind`, `owner`, `epoch`, `next_seq`, `roster`.
    pub fn new(ctx: &Value) -> Hub {
        let roster = ctx["roster"]
            .as_object()
            .map(|m| m.iter().map(|(i, d)| (i.clone(), d.as_array().into_iter().flatten().map(s).collect())).collect())
            .unwrap_or_default();
        Hub {
            now: ctx["now"].as_i64().unwrap_or(0),
            kind: ctx["kind"].as_str().unwrap_or("direct").to_string(),
            owner: ctx["owner"].as_str().map(String::from),
            epoch: ctx["epoch"].as_i64().unwrap_or(0),
            next_seq: ctx["next_seq"].as_i64().unwrap_or(1),
            roster,
            digests: HashMap::new(),
            seq_class: HashMap::new(),
            pending: BTreeMap::new(),
            group_info: false,
        }
    }

    /// Apply one event (`deposit`, `ack`, `advance`) and return what the hub emits.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(n) = ev.get("advance").and_then(Value::as_i64) {
            self.now += n;
            return vec![];
        }
        if let Some(a) = ev.get("ack") {
            return self.ack(&s(&a["identity"]), a["seq"].as_i64().unwrap_or(0));
        }
        self.deposit(&ev["deposit"])
    }

    fn error(d: &Value, reason: &str) -> Vec<Value> {
        vec![json!({"error": {"to": d["device"], "in_reply_to": d["id"], "reason": reason}})]
    }

    fn deposit(&mut self, d: &Value) -> Vec<Value> {
        let class = s(&d["class"]);
        let ident = s(&d["identity"]);
        if !matches!(class.as_str(), "handshake" | "application" | "ephemeral" | "group-info") {
            return Self::error(d, "mailbox.unsupported-class");
        }
        if class == "group-info" {
            // M§6.5 rule 6 / M§6.8: the hub keeps the latest GroupInfo so a returning device can
            // external-join, and forwards it to the members' mailboxes. Never sequenced.
            if !self.roster.contains_key(&ident) {
                return Self::error(d, "policy.blocked");
            }
            self.group_info = true;
            let mut out = vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"]}})];
            out.extend(self.roster.keys().map(|i| json!({"fanout": {"to": i, "class": "group-info"}})));
            return out;
        }
        if class == "ephemeral" {
            // M§11.2: never sequenced or stored; dropped once expired
            if d["expires_at"].as_i64().unwrap_or(0) < self.now {
                return vec![];
            }
            if !self.roster.contains_key(&ident) {
                return Self::error(d, "policy.blocked");
            }
            return self
                .roster
                .keys()
                .filter(|i| **i != ident)
                .map(|i| json!({"forward": {"to": i, "class": "ephemeral"}}))
                .collect();
        }
        let digest = s(&d["digest"]);
        if let Some(seq) = self.digests.get(&digest) {
            // M§9.3: same MLS bytes → original seq, no second fan-out
            return vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": seq, "duplicate": true}})];
        }
        let commit = d.get("commit");
        let external = commit.is_some_and(|c| c["external"].as_bool().unwrap_or(false));
        if external {
            // M§6.8
            let own_personal = self.kind == "personal" && self.owner.as_deref() == Some(ident.as_str());
            if !(self.roster.contains_key(&ident) || own_personal) {
                return Self::error(d, "policy.blocked");
            }
        } else if !self.roster.contains_key(&ident) {
            return Self::error(d, "policy.blocked"); // M§6.5 rule 1
        }
        let e = d["epoch"].as_i64().unwrap_or(i64::MIN);
        let targets: Vec<String> = self.roster.keys().cloned().collect();
        if class == "application" {
            if e != self.epoch && e != self.epoch - 1 {
                return Self::error(d, "mailbox.stale-epoch"); // M§6.5 rule 3
            }
            return self.sequence(d, &targets);
        }
        if e != self.epoch {
            // M§6.5 rule 2
            let conflict = commit.is_some() && e == self.epoch - 1;
            return Self::error(d, if conflict { "mailbox.commit-conflict" } else { "mailbox.stale-epoch" });
        }
        let Some(commit) = commit else {
            return self.sequence(d, &targets); // standalone proposal: sequenced, epoch unchanged
        };
        if !commit["valid"].as_bool().unwrap_or(true) {
            return Self::error(d, "policy.blocked");
        }
        let adds: Vec<&Value> = commit["adds"].as_array().into_iter().flatten().collect();
        let removes: Vec<&Value> = commit["removes"].as_array().into_iter().flatten().collect();
        // M§7.3: another member identity's devices are that identity's own business
        if adds.iter().any(|a| {
            let x = s(&a["identity"]);
            self.roster.contains_key(&x) && x != ident
        }) {
            return Self::error(d, "policy.blocked");
        }
        let mut by_ident: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
        for r in &removes {
            by_ident.entry(s(&r["identity"])).or_default().push(r);
        }
        for (x, rs) in &by_ident {
            if *x == ident {
                continue;
            }
            let removed: BTreeSet<String> = rs.iter().map(|r| s(&r["device"])).collect();
            let whole = self.roster.get(x).is_none_or(|devs| devs.is_subset(&removed));
            let lapsed = rs.iter().all(|r| r["delegation_valid"] == Value::Bool(false));
            if !(whole || lapsed) {
                return Self::error(d, "policy.blocked");
            }
        }
        let mut out = self.sequence(d, &targets);
        let before: BTreeSet<String> = self.roster.keys().cloned().collect();
        for r in &removes {
            let x = s(&r["identity"]);
            if let Some(devs) = self.roster.get_mut(&x) {
                devs.remove(&s(&r["device"]));
                if devs.is_empty() {
                    self.roster.remove(&x);
                }
            }
        }
        for a in &adds {
            self.roster.entry(s(&a["identity"])).or_default().insert(s(&a["device"]));
        }
        self.epoch += 1;
        if !external {
            // an external joiner joined by its own commit; welcomes go only to identities others added
            out.extend(
                self.roster.keys().filter(|i| !before.contains(*i)).map(|i| json!({"fanout": {"to": i, "class": "welcome"}})),
            );
        }
        out
    }

    fn sequence(&mut self, d: &Value, targets: &[String]) -> Vec<Value> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let class = s(&d["class"]);
        self.digests.insert(s(&d["digest"]), seq);
        self.seq_class.insert(seq, class.clone());
        let mut out = vec![json!({"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": seq}})];
        for i in targets {
            // M§6.5 rule 5: per-mailbox seq order; an unacknowledged item blocks later ones
            let q = self.pending.entry(i.clone()).or_default();
            q.push(seq);
            if q.len() == 1 {
                out.push(json!({"fanout": {"to": i, "seq": seq, "class": class}}));
            }
        }
        out
    }

    fn ack(&mut self, ident: &str, seq: i64) -> Vec<Value> {
        let Some(q) = self.pending.get_mut(ident) else { return vec![] };
        if q.first() != Some(&seq) {
            return vec![];
        }
        q.remove(0);
        match q.first() {
            Some(next) => vec![json!({"fanout": {"to": ident, "seq": next, "class": self.seq_class[next]}})],
            None => vec![],
        }
    }

    /// Snapshot compared by the vectors: epoch, next seq, roster, non-empty pending queues.
    pub fn snapshot(&self) -> Value {
        let roster: serde_json::Map<String, Value> =
            self.roster.iter().map(|(i, d)| (i.clone(), json!(d.iter().collect::<Vec<_>>()))).collect();
        let pending: serde_json::Map<String, Value> =
            self.pending.iter().filter(|(_, q)| !q.is_empty()).map(|(i, q)| (i.clone(), json!(q))).collect();
        json!({"epoch": self.epoch, "next_seq": self.next_seq, "roster": roster, "pending": pending,
               "group_info": self.group_info})
    }
}
