//! RFC 3986 share URI for out-of-band identity verification and peer hints.
//!
//! Format: `zebrapass://share?v=1&fp=<40-UPPER-HEX>[&addr=<percent-encoded>]`

use std::fmt::Write as _;

use anyhow::{Result, anyhow};

use crate::fingerprint::Fingerprint;

/// Canonical URI scheme.
pub const SHARE_URI_SCHEME: &str = "zebrapass";
/// Canonical URI host / authority.
pub const SHARE_URI_HOST: &str = "share";
/// Current share URI format version.
pub const SHARE_URI_VERSION: u8 = 1;
/// Maximum accepted length of an untrusted share URI before parsing.
pub const MAX_SHARE_URI_LEN: usize = 256;
/// Maximum length of the optional `addr` parameter.
pub const MAX_SHARE_URI_ADDR: usize = 64;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Standard RFC 3986 share payload encoded into the share QR code and Copy URL action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareUri {
    /// 160-bit account fingerprint.
    pub fingerprint: Fingerprint,
    /// Optional peer address (`ip:port`) to hint alongside the fingerprint.
    pub addr: Option<Box<str>>,
}

impl ShareUri {
    /// Build a share URI payload, keeping `addr` only when non-empty, bounded,
    /// and free of ASCII control or whitespace characters.
    #[must_use]
    pub fn new(fingerprint: Fingerprint, addr: Option<&str>) -> Self {
        let clean = addr
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= MAX_SHARE_URI_ADDR)
            .filter(|value| {
                value
                    .bytes()
                    .all(|b| !b.is_ascii_control() && !b.is_ascii_whitespace())
            })
            .map(Box::<str>::from);
        Self {
            fingerprint,
            addr: clean,
        }
    }

    /// Format as a canonical RFC 3986 URI string.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut out = String::with_capacity(96);
        let _ = write!(
            out,
            "{SHARE_URI_SCHEME}://{SHARE_URI_HOST}?v={SHARE_URI_VERSION}&fp={}",
            self.fingerprint.to_hex_compact()
        );
        if let Some(addr) = self.addr.as_deref() {
            out.push_str("&addr=");
            percent_encode_into(addr, &mut out);
        }
        out
    }

    /// Parse and validate a share URI per RFC 3986.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI exceeds [`MAX_SHARE_URI_LEN`], has an
    /// invalid scheme/host/version/query syntax, or contains invalid hex or
    /// percent-encoding.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() || input.len() > MAX_SHARE_URI_LEN {
            return Err(anyhow!("invalid share URI length"));
        }
        if input
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(anyhow!("invalid characters in share URI"));
        }
        let query = strip_prefix_ignore_ascii_case(input, "zebrapass://share?")
            .ok_or_else(|| anyhow!("invalid share URI prefix"))?;
        if query.is_empty() {
            return Err(anyhow!("missing share URI parameters"));
        }

        let mut version: Option<u8> = None;
        let mut fingerprint: Option<Fingerprint> = None;
        let mut addr: Option<Box<str>> = None;

        for pair in query.split('&') {
            if pair.is_empty() {
                return Err(anyhow!("empty share URI parameter"));
            }
            let (key, val) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("malformed share URI parameter"))?;
            match key {
                "v" => {
                    if version.is_some() {
                        return Err(anyhow!("duplicate version parameter"));
                    }
                    let parsed: u8 = val
                        .parse()
                        .map_err(|_| anyhow!("invalid share URI version"))?;
                    if parsed != SHARE_URI_VERSION {
                        return Err(anyhow!("unsupported share URI version"));
                    }
                    version = Some(parsed);
                }
                "fp" => {
                    if fingerprint.is_some() {
                        return Err(anyhow!("duplicate fingerprint parameter"));
                    }
                    fingerprint = Some(parse_fingerprint_hex(val)?);
                }
                "addr" => {
                    if addr.is_some() {
                        return Err(anyhow!("duplicate addr parameter"));
                    }
                    let decoded = percent_decode(val)?;
                    if decoded.is_empty()
                        || decoded.len() > MAX_SHARE_URI_ADDR
                        || decoded
                            .bytes()
                            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                    {
                        return Err(anyhow!("invalid share URI addr"));
                    }
                    addr = Some(decoded.into_boxed_str());
                }
                _ => return Err(anyhow!("unknown share URI parameter")),
            }
        }

        let _ = version.ok_or_else(|| anyhow!("missing version parameter"))?;
        let fingerprint = fingerprint.ok_or_else(|| anyhow!("missing fingerprint parameter"))?;
        Ok(Self { fingerprint, addr })
    }
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| input.get(prefix.len()..))?
}

const fn is_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

fn percent_encode_into(raw: &str, out: &mut String) {
    for byte in raw.bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            let hi = HEX_UPPER
                .get(usize::from(byte >> 4))
                .copied()
                .unwrap_or(b'0');
            let lo = HEX_UPPER
                .get(usize::from(byte & 0x0F))
                .copied()
                .unwrap_or(b'0');
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let hi = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_nibble)
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            let lo = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_nibble)
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| anyhow!("non-utf8 addr parameter"))
}

fn parse_fingerprint_hex(raw: &str) -> Result<Fingerprint> {
    let bytes = raw.as_bytes();
    if bytes.len() != 40 {
        return Err(anyhow!("fingerprint must be 40 hex digits"));
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    let mut out = [0u8; 20];
    for (slot, &[hi_b, lo_b]) in out.iter_mut().zip(pairs) {
        let hi = hex_nibble(hi_b).ok_or_else(|| anyhow!("invalid fingerprint hex"))?;
        let lo = hex_nibble(lo_b).ok_or_else(|| anyhow!("invalid fingerprint hex"))?;
        *slot = (hi << 4) | lo;
    }
    Ok(Fingerprint::from_bytes(out))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{MAX_SHARE_URI_LEN, ShareUri};
    use crate::fingerprint::Fingerprint;

    fn sample_print() -> Fingerprint {
        Fingerprint::from_bytes([
            0x22, 0xDC, 0x4A, 0xB1, 0xC6, 0x18, 0x5D, 0x3C, 0x8E, 0xB2, 0x91, 0x86, 0xE8, 0x10,
            0x67, 0x06, 0x75, 0x58, 0xEA, 0x48,
        ])
    }

    #[test]
    fn round_trips_without_addr_and_with_ipv4_and_ipv6() {
        let fp = sample_print();

        let bare = ShareUri::new(fp, None);
        let bare_uri = bare.to_uri();
        assert_eq!(
            bare_uri,
            "zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48"
        );
        assert_eq!(ShareUri::parse(&bare_uri).unwrap(), bare);

        let v4 = ShareUri::new(fp, Some(" 192.168.15.150:7447 "));
        let v4_uri = v4.to_uri();
        assert_eq!(
            v4_uri,
            "zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48&addr=192.168.15.150%3A7447"
        );
        assert_eq!(ShareUri::parse(&v4_uri).unwrap(), v4);

        let v6 = ShareUri::new(fp, Some("[2804:7f2:c011:d6d0:918b:7082:49d6:d038]:7447"));
        let v6_uri = v6.to_uri();
        assert!(
            v6_uri.contains(
                "&addr=%5B2804%3A7f2%3Ac011%3Ad6d0%3A918b%3A7082%3A49d6%3Ad038%5D%3A7447"
            )
        );
        assert_eq!(ShareUri::parse(&v6_uri).unwrap(), v6);
    }

    #[test]
    fn parses_case_insensitive_scheme_and_host_and_lowercase_fp() {
        let fp = sample_print();
        let uri = "ZEBRAPASS://SHARE?v=1&fp=22dc4ab1c6185d3c8eb29186e81067067558ea48";
        let parsed = ShareUri::parse(uri).unwrap();
        assert_eq!(parsed.fingerprint, fp);
        assert!(parsed.addr.is_none());
    }

    #[test]
    fn rejects_invalid_uris() {
        let valid_fp = "22DC4AB1C6185D3C8EB29186E81067067558EA48";
        let too_long = format!(
            "zebrapass://share?v=1&fp={valid_fp}&addr={}",
            "a".repeat(MAX_SHARE_URI_LEN)
        );
        for bad in [
            "",
            "https://share?v=1&fp=22DC",
            "zebrapass://other?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48",
            "zebrapass://share?",
            &format!("zebrapass://share?v=2&fp={valid_fp}"),
            "zebrapass://share?v=1&fp=22DC",
            &format!("zebrapass://share?v=1&fp=ZZ{}", &valid_fp[2..]),
            &format!("zebrapass://share?v=1&fp={valid_fp}&addr=%ZZ"),
            &format!("zebrapass://share?v=1&fp={valid_fp}&addr=%2"),
            &format!("zebrapass://share?v=1&fp={valid_fp}&addr="),
            &format!("zebrapass://share?v=1&fp={valid_fp}&v=1"),
            &format!("zebrapass://share?v=1&fp={valid_fp}&extra=1"),
            &format!("zebrapass://share?v=1&fp={valid_fp}\n"),
            &too_long,
        ] {
            assert!(ShareUri::parse(bad).is_err(), "accepted invalid URI: {bad}");
        }
    }
}
