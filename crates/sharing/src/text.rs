//! Text form of binary objects, for copy and paste: a short prefix naming the
//! kind, then unpadded base64url. Decoding ignores whitespace (a terminal
//! wraps long lines), is strict about the alphabet and trailing bits, and
//! bounds the output before allocating it.

use anyhow::{anyhow, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn invalid() -> anyhow::Error {
    anyhow!("invalid share text")
}

fn sextet(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|at| u8::try_from(at).ok())
}

/// `prefix:` followed by the base64url of `bytes`.
#[must_use]
pub fn encode(prefix: &str, bytes: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len() + 1 + bytes.len().div_ceil(3) * 4);
    out.push_str(prefix);
    out.push(':');
    for chunk in bytes.chunks(3) {
        let [a, b, c] = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let group = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            let shift = 18 - 6 * u32::try_from(index).unwrap_or(0);
            let value = usize::try_from((group >> shift) & 0x3F).unwrap_or(0);
            out.push(char::from(ALPHABET.get(value).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// The bytes inside `text`, which must start with `prefix:`.
///
/// # Errors
///
/// `invalid share text` for a wrong prefix, a character outside the
/// alphabet, a non-canonical ending, or more than `max_len` decoded bytes.
pub fn decode(prefix: &str, text: &str, max_len: usize) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(':'))
        .ok_or_else(invalid)?;
    let symbols = body.as_bytes();
    if symbols.len() % 4 == 1 || symbols.len() / 4 * 3 > max_len.saturating_add(3) {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3 + 3);
    for chunk in symbols.chunks(4) {
        let mut group = 0u32;
        for byte in chunk {
            group = (group << 6) | u32::from(sextet(*byte).ok_or_else(invalid)?);
        }
        group <<= 6 * u32::try_from(4 - chunk.len()).map_err(|_| invalid())?;
        let bytes = group.to_be_bytes();
        let produced = chunk.len() - 1;
        let (data, spare) = bytes
            .get(1..)
            .and_then(|three| three.split_at_checked(produced))
            .ok_or_else(invalid)?;
        if spare.iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
        out.extend_from_slice(data);
    }
    if out.len() > max_len {
        return Err(invalid());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{decode, encode};

    #[test]
    fn round_trips_every_length_and_ignores_whitespace() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len)
                .map(|n| u8::try_from(n * 7 % 256).unwrap())
                .collect();
            let text = encode("zp-x", &bytes);
            assert_eq!(decode("zp-x", &text, 64).unwrap(), bytes);
            let wrapped: String = text
                .chars()
                .enumerate()
                .flat_map(|(at, c)| {
                    if at % 11 == 10 {
                        vec![c, '\n', ' ']
                    } else {
                        vec![c]
                    }
                })
                .collect();
            assert_eq!(decode("zp-x", &wrapped, 64).unwrap(), bytes);
        }
    }

    #[test]
    fn matches_the_standard_vectors() {
        assert_eq!(encode("p", b"foobar"), "p:Zm9vYmFy");
        assert_eq!(encode("p", b"fooba"), "p:Zm9vYmE");
        assert_eq!(encode("p", &[0xFB, 0xFF]), "p:-_8");
    }

    #[test]
    fn rejects_bad_prefix_alphabet_endings_and_oversize() {
        assert!(decode("zp-y", &encode("zp-x", b"abc"), 8).is_err());
        assert!(decode("zp-x", "zp-x:ab+d", 8).is_err());
        assert!(decode("zp-x", "zp-x:ab=d", 8).is_err());
        assert!(decode("zp-x", "zp-x:Zm9vY", 8).is_err());
        assert!(decode("zp-x", "zp-x:Zg", 8).is_ok());
        assert!(
            decode("zp-x", "zp-x:Zh", 8).is_err(),
            "non-canonical trailing bits"
        );
        assert!(decode("zp-x", &encode("zp-x", &[1; 100]), 99).is_err());
        assert!(decode("zp-x", &encode("zp-x", &[1; 100]), 100).is_ok());
        assert!(decode("zp-x", "", 8).is_err());
    }
}
