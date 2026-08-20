//! ULID parsing, generation, and timestamp extraction.
//!
//! Spec: §10.3 — message ids are ULIDs (26-char Crockford base32); §12.6 glare
//! resolution depends on their lexicographic time ordering; §20.6 requires the
//! timestamp component to be checked against `issued_at`.

use std::fmt;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A validated ULID (26 Crockford base32 characters, first char `0`–`7`).
///
/// Spec: §10.3. Note that prose examples such as `01HZINVITEABC` are not
/// valid ULIDs and fail [`Ulid::parse`] by design.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(String);

impl Ulid {
    /// Parse and validate a ULID string.
    pub fn parse(s: &str) -> Option<Ulid> {
        let b = s.as_bytes();
        if b.len() != 26 || !(b'0'..=b'7').contains(&b[0]) {
            return None;
        }
        if b.iter().all(|c| CROCKFORD.contains(c)) {
            Some(Ulid(s.to_string()))
        } else {
            None
        }
    }

    /// Timestamp component in milliseconds since the Unix epoch (first 10 chars, 48 bits).
    pub fn timestamp_ms(&self) -> u64 {
        self.0.bytes().take(10).fold(0u64, |acc, c| (acc << 5) | decode_char(c) as u64)
    }

    /// Timestamp component in whole seconds.
    pub fn timestamp_s(&self) -> i64 {
        (self.timestamp_ms() / 1000) as i64
    }

    /// Build a ULID from a millisecond timestamp and 10 bytes of randomness.
    pub fn from_parts(ts_ms: u64, rand: [u8; 10]) -> Ulid {
        assert!(ts_ms < (1 << 48), "ULID timestamp out of range");
        let mut n: u128 = (ts_ms as u128) << 80;
        n |= u128::from_be_bytes({
            let mut b = [0u8; 16];
            b[6..].copy_from_slice(&rand);
            b
        });
        let mut out = [0u8; 26];
        for slot in out.iter_mut().rev() {
            *slot = CROCKFORD[(n & 31) as usize];
            n >>= 5;
        }
        Ulid(String::from_utf8(out.to_vec()).expect("ascii"))
    }

    /// A fresh ULID for "now" with OS randomness.
    pub fn generate() -> Ulid {
        use rand::RngCore;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut r = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut r);
        Ulid::from_parts(ts, r)
    }

    /// The string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn decode_char(c: u8) -> u8 {
    CROCKFORD.iter().position(|&x| x == c).expect("validated") as u8
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ulid({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_timestamp() {
        let u = Ulid::parse("01J5Y0Q6K8ZJ4M2N7P9R3S5T7V").unwrap();
        // 01J5Y0Q6K8 → 2024-08-22T21:43:40.904Z; same decoder as impl/tools/dsipvec/ulid.py
        assert_eq!(u.timestamp_ms(), 1_724_363_020_904);
        assert!(Ulid::parse("01HZINVITEABC").is_none(), "prose id rejected");
        assert!(Ulid::parse("81J5Y0Q6K8ZJ4M2N7P9R3S5T7V").is_none(), "first char > 7");
    }

    #[test]
    fn round_trip_from_parts() {
        let u = Ulid::from_parts(1_760_000_000_000, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(u.timestamp_ms(), 1_760_000_000_000);
        assert_eq!(Ulid::parse(u.as_str()), Some(u));
    }
}
