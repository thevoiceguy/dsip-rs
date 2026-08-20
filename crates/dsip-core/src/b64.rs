//! base64url without padding, as used by JWS.
//!
//! Spec: §10.2 — the envelope members are base64url strings. Decoding is strict:
//! padding characters and non-alphabet bytes are rejected, because a lenient
//! decoder would accept envelopes whose *text* differs from what was signed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Encode bytes as unpadded base64url.
pub fn encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Strictly decode unpadded base64url. Returns `None` for anything off-alphabet,
/// padded, empty, or of impossible length.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    if s.len() % 4 == 1 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        assert_eq!(decode(&encode(b"hello")).unwrap(), b"hello");
        assert!(decode("aGVsbG8=").is_none(), "padding rejected");
        assert!(decode("aGVs+bG8").is_none(), "std alphabet rejected");
        assert!(decode("").is_none());
    }
}
