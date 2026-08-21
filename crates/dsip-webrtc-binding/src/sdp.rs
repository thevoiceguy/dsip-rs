//! Minimal, tolerant SDP reader: `m=` sections and `a=` attributes; everything else is ignored.
//!
//! Spec: B§2.1/B§2.2 need only the section list, directions, `a=rtpmap`, `a=setup`,
//! `a=fingerprint`, `a=rtcp-mux`, `a=mid` and the ICE credentials; this is deliberately
//! not a full RFC 8866 parser.

/// One `m=` section with its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// `audio` | `video` | `application` | …
    pub kind: String,
    /// Port (0 = rejected section).
    pub port: u16,
    /// Transport profile, e.g. `UDP/TLS/RTP/SAVPF`.
    pub protocol: String,
    /// Format tokens (payload types).
    pub formats: Vec<String>,
    /// `(name, value)` attributes in order; property attributes have `None`.
    pub attrs: Vec<(String, Option<String>)>,
}

const DIRECTIONS: &[&str] = &["sendrecv", "sendonly", "recvonly", "inactive"];

impl Section {
    /// Values of a value attribute, in order.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.attrs.iter().filter(|(n, v)| n == name && v.is_some()).filter_map(|(_, v)| v.as_deref()).collect()
    }

    /// Whether a property or value attribute is present.
    pub fn has(&self, name: &str) -> bool {
        self.attrs.iter().any(|(n, _)| n == name)
    }

    /// The section's own direction attribute, if any.
    pub fn direction(&self) -> Option<&str> {
        self.attrs.iter().find(|(n, v)| v.is_none() && DIRECTIONS.contains(&n.as_str())).map(|(n, _)| n.as_str())
    }

    /// Encoding names from `a=rtpmap` (lower-cased).
    pub fn encodings(&self) -> Vec<String> {
        self.values("rtpmap")
            .iter()
            .filter_map(|v| v.split_once(' ').map(|(_, rest)| rest.split('/').next().unwrap_or("").to_ascii_lowercase()))
            .collect()
    }
}

/// A parsed description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    /// Session-level attributes.
    pub session_attrs: Vec<(String, Option<String>)>,
    /// Media sections in order.
    pub sections: Vec<Section>,
}

impl Sdp {
    /// A session-level value attribute.
    pub fn session_value(&self, name: &str) -> Option<&str> {
        self.session_attrs.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }

    /// A session-level direction attribute.
    pub fn session_direction(&self) -> Option<&str> {
        self.session_attrs.iter().find(|(n, v)| v.is_none() && DIRECTIONS.contains(&n.as_str())).map(|(n, _)| n.as_str())
    }

    /// A value attribute looked up at media level first, then session level.
    pub fn attr<'a>(&'a self, sec: &'a Section, name: &str) -> Option<&'a str> {
        sec.values(name).first().copied().or_else(|| self.session_value(name))
    }
}

/// Parse SDP text. `None` unless it starts with `v=0` and every `m=` line is well formed.
pub fn parse_sdp(text: &str) -> Option<Sdp> {
    if !text.starts_with("v=0") {
        return None;
    }
    let mut sdp = Sdp { session_attrs: vec![], sections: vec![] };
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r').trim();
        if line.len() < 2 || line.as_bytes()[1] != b'=' {
            continue;
        }
        let (key, val) = (line.as_bytes()[0], &line[2..]);
        match key {
            b'm' => {
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() < 3 {
                    return None;
                }
                let port: u16 = parts[1].split('/').next()?.parse().ok()?;
                sdp.sections.push(Section {
                    kind: parts[0].to_string(),
                    port,
                    protocol: parts[2].to_string(),
                    formats: parts[3..].iter().map(|s| s.to_string()).collect(),
                    attrs: vec![],
                });
            }
            b'a' => {
                let attr = match val.split_once(':') {
                    Some((n, v)) => (n.to_string(), Some(v.to_string())),
                    None => (val.to_string(), None),
                };
                match sdp.sections.last_mut() {
                    Some(s) => s.attrs.push(attr),
                    None => sdp.session_attrs.push(attr),
                }
            }
            _ => {}
        }
    }
    Some(sdp)
}
