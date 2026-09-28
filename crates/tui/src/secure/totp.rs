//! RFC 6238 time-based one-time codes: HMAC-SHA1 from the `hmac` and `sha1`
//! crates over the 30-second counter, RFC 4226 dynamic truncation.
//!
//! The stored field is a base32 secret or an `otpauth://totp/` URI. Only the
//! parameters this module can honour are accepted (SHA-1, 6 to 8 digits, a
//! positive period); anything else fails closed instead of showing codes the
//! issuer would reject.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

/// Longest accepted field, in bytes.
const MAX_FIELD: usize = 512;
/// Longest decoded key, in bytes.
const MAX_KEY: usize = 128;
/// Default code length.
const DEFAULT_DIGITS: u32 = 6;
/// Default time step, in seconds.
const DEFAULT_PERIOD: u64 = 30;
/// Longest accepted time step, in seconds.
const MAX_PERIOD: u64 = 300;

/// Why a TOTP field cannot produce codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpError {
    /// Not base32, empty, too long, or a malformed URI.
    Invalid,
    /// A valid URI asking for an algorithm, length, or period not supported.
    Unsupported,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "not a valid TOTP secret",
            Self::Unsupported => "unsupported TOTP parameters",
        })
    }
}

/// A parsed TOTP secret. The key is wiped on drop.
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&[u8]> for Totp {
    type Error = TotpError;

    fn try_from(field: &[u8]) -> Result<Self, TotpError> {
        if field.len() > MAX_FIELD {
            return Err(TotpError::Invalid);
        }
        let text = std::str::from_utf8(field)
            .map_err(|_| TotpError::Invalid)?
            .trim();
        match text.strip_prefix("otpauth://totp/") {
            Some(rest) => from_uri(rest),
            None => Ok(Self {
                key: base32(text)?,
                digits: DEFAULT_DIGITS,
                period: DEFAULT_PERIOD,
            }),
        }
    }
}

impl Totp {
    /// The code for `unix_secs`, zero-padded to the configured length.
    #[must_use]
    pub fn code(&self, unix_secs: u64) -> Zeroizing<String> {
        let counter = (unix_secs / self.period).to_be_bytes();
        // Any key length is a legal HMAC key; the constructor still returns `Result`.
        let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&self.key) else {
            return Zeroizing::new(String::new());
        };
        mac.update(&counter);
        let digest = Zeroizing::new(mac.finalize().into_bytes());
        let offset = digest.last().map_or(0, |byte| usize::from(byte & 0x0f));
        let word = digest
            .get(offset..offset + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map_or(0, u32::from_be_bytes)
            & 0x7fff_ffff;
        let value = word % 10u32.pow(self.digits);
        let width = usize::try_from(self.digits).unwrap_or(6);
        Zeroizing::new(format!("{value:0width$}"))
    }

    /// Seconds until the code for `unix_secs` changes.
    #[must_use]
    pub const fn remaining(&self, unix_secs: u64) -> u64 {
        self.period - unix_secs % self.period
    }
}

fn from_uri(rest: &str) -> Result<Totp, TotpError> {
    let query = rest.split_once('?').map_or("", |(_, query)| query);
    let mut key = None;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_PERIOD;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name.to_ascii_lowercase().as_str() {
            "secret" => key = Some(base32(value)?),
            "algorithm" if !value.eq_ignore_ascii_case("SHA1") => {
                return Err(TotpError::Unsupported)
            }
            "digits" => {
                digits = value.parse().map_err(|_| TotpError::Invalid)?;
                if !(6..=8).contains(&digits) {
                    return Err(TotpError::Unsupported);
                }
            }
            "period" => {
                period = value.parse().map_err(|_| TotpError::Invalid)?;
                if !(1..=MAX_PERIOD).contains(&period) {
                    return Err(TotpError::Unsupported);
                }
            }
            _ => {}
        }
    }
    Ok(Totp {
        key: key.ok_or(TotpError::Invalid)?,
        digits,
        period,
    })
}

/// RFC 4648 base32, case-insensitive, spaces, dashes and `=` padding ignored.
fn base32(text: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte.to_ascii_uppercase() {
            letter @ b'A'..=b'Z' => letter - b'A',
            digit @ b'2'..=b'7' => digit - b'2' + 26,
            b' ' | b'-' | b'=' => continue,
            _ => return Err(TotpError::Invalid),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| TotpError::Invalid)?);
        }
    }
    if out.is_empty() || out.len() > MAX_KEY {
        return Err(TotpError::Invalid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{Totp, TotpError};

    /// RFC 6238 appendix B: the SHA-1 seed is ASCII `12345678901234567890`.
    const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc_6238_sha1_vectors() {
        let uri = format!("otpauth://totp/x?secret={RFC_SEED_B32}&digits=8");
        let totp = Totp::try_from(uri.as_bytes()).unwrap();
        for (time, code) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(totp.code(time).as_str(), code, "t={time}");
        }
    }

    #[test]
    fn raw_secret_defaults_to_six_digits_every_thirty_seconds() {
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        let totp = Totp::try_from(spaced.as_bytes()).unwrap();
        assert_eq!(totp.code(59).as_str(), "287082");
        assert_eq!(totp.remaining(59), 1);
        assert_eq!(totp.remaining(60), 30);
    }

    #[test]
    fn unsupported_and_invalid_fields_fail_closed() {
        let sha256 = format!("otpauth://totp/x?secret={RFC_SEED_B32}&algorithm=SHA256");
        assert_eq!(
            Totp::try_from(sha256.as_bytes()).unwrap_err(),
            TotpError::Unsupported
        );
        let long = format!("otpauth://totp/x?secret={RFC_SEED_B32}&digits=10");
        assert_eq!(
            Totp::try_from(long.as_bytes()).unwrap_err(),
            TotpError::Unsupported
        );
        for bad in ["", "not base32!", "otpauth://totp/x?digits=6", "18"] {
            assert_eq!(
                Totp::try_from(bad.as_bytes()).unwrap_err(),
                TotpError::Invalid,
                "{bad:?}"
            );
        }
    }
}
