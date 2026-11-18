//! Hybrid TLS verifier supporting both WebPKI/custom-CA trust chains and
//! explicitly pinned self-signed end-entity certificates passed via `--extra-ca`.

use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use secret::ct_eq;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GEN_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_VERSION: u8 = 0xA0;
const TAG_ISSUER_UID: u8 = 0x81;
const TAG_SUBJECT_UID: u8 = 0x82;
const TAG_SAN_DNS: u8 = 0x82;
const TAG_SAN_IP: u8 = 0x87;
const TAG_EXTENSIONS: u8 = 0xA3;

/// OID `2.5.29.17` (`id-ce-subjectAltName`).
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];

/// Maximum single DER element length accepted while inspecting pinned leaves.
const MAX_DER_LEN: usize = 64 * 1024;

/// Verifies server certificates via `WebPkiServerVerifier`, falling back only to
/// explicitly pinned single self-signed certificates whose validity window and
/// Subject Alternative Name match the dialed endpoint.
#[derive(Debug)]
pub struct PinnedOrWebPkiVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Box<[CertificateDer<'static>]>,
}

impl PinnedOrWebPkiVerifier {
    /// Construct a verifier combining `inner` with explicit DER certificate pins.
    #[must_use]
    pub fn new(inner: Arc<WebPkiServerVerifier>, pins: Vec<CertificateDer<'static>>) -> Self {
        Self {
            inner,
            pins: pins.into_boxed_slice(),
        }
    }

    fn matches_pin(&self, end_entity: &[u8]) -> bool {
        let mut matched = false;
        for pin in &self.pins {
            matched |= ct_eq(pin.as_ref(), end_entity);
        }
        matched
    }
}

impl ServerCertVerifier for PinnedOrWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(err)
                if intermediates.is_empty()
                    && matches!(
                        err,
                        Error::InvalidCertificate(
                            CertificateError::UnknownIssuer
                                | CertificateError::InvalidPurpose
                                | CertificateError::InvalidPurposeContext { .. }
                                | CertificateError::Other(_)
                        )
                    )
                    && self.matches_pin(end_entity.as_ref())
                    && verify_pinned_x509(end_entity.as_ref(), server_name, now.as_secs()) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn parse_der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&len_b, after_len) = after_tag.split_first()?;
    let (len, rest) = if len_b < 0x80 {
        (usize::from(len_b), after_len)
    } else {
        let octets = usize::from(len_b & 0x7F);
        if octets == 0 || octets > 4 {
            return None;
        }
        let (len_bytes, tail) = after_len.split_at_checked(octets)?;
        if len_bytes.first().copied() == Some(0) {
            return None;
        }
        let mut acc = 0usize;
        for &b in len_bytes {
            acc = acc.checked_shl(8)? | usize::from(b);
        }
        if acc < 128 {
            return None;
        }
        (acc, tail)
    };
    if len > MAX_DER_LEN {
        return None;
    }
    let (val, rem) = rest.split_at_checked(len)?;
    Some((tag, val, rem))
}

fn take_tag<'a>(buf: &mut &'a [u8], expected: u8) -> Option<&'a [u8]> {
    let (tag, val, rem) = parse_der_tlv(buf)?;
    if tag != expected {
        return None;
    }
    *buf = rem;
    Some(val)
}

fn skip_optional(buf: &mut &[u8], tag: u8) {
    if let Some((found, _, rem)) = parse_der_tlv(buf)
        && found == tag
    {
        *buf = rem;
    }
}

/// Validate X.509 `validity` (`now_secs`) and `subjectAltName` against `server_name`.
pub fn verify_pinned_x509(cert_der: &[u8], server_name: &ServerName<'_>, now_secs: u64) -> bool {
    let Some((tag, cert_body, cert_rem)) = parse_der_tlv(cert_der) else {
        return false;
    };
    if tag != TAG_SEQUENCE || !cert_rem.is_empty() {
        return false;
    }
    let Some((tbs_tag, mut tbs, _)) = parse_der_tlv(cert_body) else {
        return false;
    };
    if tbs_tag != TAG_SEQUENCE {
        return false;
    }

    skip_optional(&mut tbs, TAG_VERSION);
    if take_tag(&mut tbs, TAG_INTEGER).is_none()
        || take_tag(&mut tbs, TAG_SEQUENCE).is_none()
        || take_tag(&mut tbs, TAG_SEQUENCE).is_none()
    {
        return false;
    }
    let Some(mut validity) = take_tag(&mut tbs, TAG_SEQUENCE) else {
        return false;
    };
    if !validity_window_ok(&mut validity, now_secs) {
        return false;
    }
    if take_tag(&mut tbs, TAG_SEQUENCE).is_none() || take_tag(&mut tbs, TAG_SEQUENCE).is_none() {
        return false;
    }
    skip_optional(&mut tbs, TAG_ISSUER_UID);
    skip_optional(&mut tbs, TAG_SUBJECT_UID);

    let Some(exts_wrap) = take_tag(&mut tbs, TAG_EXTENSIONS) else {
        return false;
    };
    if !tbs.is_empty() {
        return false;
    }
    let Some((exts_tag, mut exts, exts_rem)) = parse_der_tlv(exts_wrap) else {
        return false;
    };
    if exts_tag != TAG_SEQUENCE || !exts_rem.is_empty() {
        return false;
    }

    while !exts.is_empty() {
        let Some((item_tag, mut item, next_items)) = parse_der_tlv(exts) else {
            return false;
        };
        if item_tag != TAG_SEQUENCE {
            return false;
        }
        exts = next_items;
        let Some(oid) = take_tag(&mut item, TAG_OID) else {
            return false;
        };
        if oid == OID_SAN {
            skip_optional(&mut item, TAG_BOOLEAN);
            let Some(san_der) = take_tag(&mut item, TAG_OCTET_STRING) else {
                return false;
            };
            if !item.is_empty() {
                return false;
            }
            return san_matches(san_der, server_name);
        }
    }
    false
}

fn validity_window_ok(validity: &mut &[u8], now_secs: u64) -> bool {
    let Some(not_before) = parse_der_time(validity) else {
        return false;
    };
    let Some(not_after) = parse_der_time(validity) else {
        return false;
    };
    validity.is_empty() && now_secs >= not_before && now_secs <= not_after
}

fn parse_der_time(buf: &mut &[u8]) -> Option<u64> {
    let (tag, bytes, rem) = parse_der_tlv(buf)?;
    *buf = rem;
    let (year, rest) = match tag {
        TAG_UTC_TIME if bytes.len() == 13 => {
            let (yy, tail) = bytes.split_at_checked(2)?;
            let y2 = u32::from(parse_2d(yy)?);
            (if y2 >= 50 { 1900 + y2 } else { 2000 + y2 }, tail)
        }
        TAG_GEN_TIME if bytes.len() == 15 => {
            let (yyyy, tail) = bytes.split_at_checked(4)?;
            let hi = u32::from(parse_2d(yyyy.get(..2)?)?);
            let lo = u32::from(parse_2d(yyyy.get(2..)?)?);
            let y4 = hi * 100 + lo;
            if y4 < 1970 {
                return None;
            }
            (y4, tail)
        }
        _ => return None,
    };
    if rest.get(10) != Some(&b'Z') {
        return None;
    }
    let month = parse_2d(rest.get(0..2)?)?;
    let day = parse_2d(rest.get(2..4)?)?;
    let hour = parse_2d(rest.get(4..6)?)?;
    let min = parse_2d(rest.get(6..8)?)?;
    let sec = parse_2d(rest.get(8..10)?)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || min > 59
        || sec > 59
    {
        return None;
    }
    let days = days_from_civil(i64::from(year), u32::from(month), u32::from(day))?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(u64::from(hour) * 3_600)?
        .checked_add(u64::from(min) * 60)?
        .checked_add(u64::from(sec))?;
    Some(secs)
}

const fn parse_2d(bytes: &[u8]) -> Option<u8> {
    let [a, b] = bytes else {
        return None;
    };
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    Some((*a - b'0') * 10 + (*b - b'0'))
}

const fn is_leap_year(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

const fn days_in_month(y: u32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's civil-from-epoch algorithm for dates `>= 1970-01-01`.
const fn days_from_civil(y: i64, m: u32, d: u32) -> Option<u64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m_shift = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * m_shift as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        None
    } else {
        Some(days.cast_unsigned())
    }
}

fn san_matches(san_der: &[u8], server_name: &ServerName<'_>) -> bool {
    let Some((tag, mut names, rem)) = parse_der_tlv(san_der) else {
        return false;
    };
    if tag != TAG_SEQUENCE || !rem.is_empty() {
        return false;
    }
    while !names.is_empty() {
        let Some((name_tag, val, next)) = parse_der_tlv(names) else {
            return false;
        };
        names = next;
        match server_name {
            ServerName::DnsName(want) if name_tag == TAG_SAN_DNS => {
                if val.is_ascii()
                    && !val.contains(&0)
                    && val.eq_ignore_ascii_case(want.as_ref().as_bytes())
                {
                    return true;
                }
            }
            ServerName::IpAddress(want) if name_tag == TAG_SAN_IP => {
                let matched = match IpAddr::from(*want) {
                    IpAddr::V4(v4) => ct_eq(val, &v4.octets()),
                    IpAddr::V6(v6) => ct_eq(val, &v6.octets()),
                };
                if matched {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
