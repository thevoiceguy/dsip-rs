//! Candidate exchange state (one local description).
//!
//! Spec: B§4.2 (carriage in `info`, end marker exactly once), B§4.3 (local candidates are
//! buffered until ACTIVE and sent coalesced; remote candidates are buffered until the remote
//! description is applied, applied in order, dropped when the session ends), B§4.4 (only the
//! device party to the session may supply candidates; candidates after the peer's end marker
//! are ignored).

use serde_json::{json, Value};

/// The exchange for one local description.
#[derive(Debug, Default)]
pub struct CandidateExchange {
    peer: Option<String>,
    active: bool,
    remote_applied: bool,
    local_buf: usize,
    gathering_complete: bool,
    end_sent: bool,
    remote_buf: usize,
    remote_end: bool,
    ended: bool,
}

impl CandidateExchange {
    /// `peer` = the device party to the session (attribution, B§4.4); `None` = not enforced.
    pub fn new(peer: Option<&str>) -> Self {
        CandidateExchange { peer: peer.map(String::from), ..Default::default() }
    }

    /// Apply one event (vector vocabulary) and return the emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let mut out = vec![];
        if self.ended {
            return vec![json!({"ignore": "ended"})];
        }
        if ev.get("local_candidate").is_some() {
            if self.active {
                out.push(json!({"send_info": {"candidates": 1, "end_of_candidates": false}}));
            } else {
                self.local_buf += 1;
                out.push(json!({"buffer": "local", "n": self.local_buf}));
            }
        } else if ev.get("gathering_complete").is_some() {
            self.gathering_complete = true;
            if self.active && !self.end_sent {
                self.end_sent = true;
                out.push(json!({"send_info": {"candidates": 0, "end_of_candidates": true}}));
            }
        } else if ev.get("active").is_some() {
            self.active = true;
            let end = self.gathering_complete && !self.end_sent;
            if self.local_buf > 0 || end {
                out.push(json!({"send_info": {"candidates": self.local_buf, "end_of_candidates": end}}));
                self.local_buf = 0;
                self.end_sent = self.end_sent || end;
            }
        } else if ev.get("remote_description").is_some() {
            self.remote_applied = true;
            if self.remote_buf > 0 {
                out.push(json!({"apply": self.remote_buf}));
                self.remote_buf = 0;
            }
        } else if let Some(info) = ev.get("remote_info") {
            if let Some(peer) = &self.peer {
                if info.get("from").and_then(Value::as_str) != Some(peer.as_str()) {
                    return vec![json!({"ignore": "not-party"})];
                }
            }
            if self.remote_end {
                return vec![json!({"ignore": "after-end"})];
            }
            let n = info.get("candidates").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
            if n > 0 {
                if self.remote_applied {
                    out.push(json!({"apply": n}));
                } else {
                    self.remote_buf += n;
                    out.push(json!({"buffer": "remote", "n": self.remote_buf}));
                }
            }
            if info.get("end_of_candidates").and_then(Value::as_bool).unwrap_or(false) {
                self.remote_end = true;
                out.push(json!({"remote_end": true}));
            }
        } else if ev.get("session_end").is_some() {
            self.ended = true;
            let dropped = self.remote_buf + self.local_buf;
            if dropped > 0 {
                out.push(json!({"drop_buffered": dropped}));
                self.remote_buf = 0;
                self.local_buf = 0;
            }
        }
        out
    }
}
