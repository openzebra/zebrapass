//! Wire form of [`DeviceCert`]. Version 2 adds the signed device id; the
//! version-1 layout was never issued or stored and has no parser.

use anyhow::{anyhow, Result};
use session::{DeviceCert, SYNC_SIG_LEN, SYNC_VK_LEN};

use crate::reader::Reader;

/// First four bytes of an encoded certificate.
pub const CERT_MAGIC: [u8; 4] = *b"ZPDC";
/// Current certificate wire version.
pub const CERT_WIRE_VERSION: u16 = 2;

/// Exact length of an encoded certificate.
pub const CERT_WIRE_LEN: usize = 4 + 2 + 64 + 16 + SYNC_VK_LEN + 8 + 8 + SYNC_SIG_LEN;

/// Encode `cert`.
///
/// # Errors
///
/// The signature is not [`SYNC_SIG_LEN`] bytes.
pub fn encode_cert(cert: &DeviceCert) -> Result<Vec<u8>> {
    if cert.signature.len() != SYNC_SIG_LEN {
        return Err(anyhow!("device cert signature length"));
    }
    let mut out = Vec::with_capacity(CERT_WIRE_LEN);
    out.extend_from_slice(&CERT_MAGIC);
    out.extend_from_slice(&CERT_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&cert.client_id);
    out.extend_from_slice(&cert.device_id);
    out.extend_from_slice(&cert.device_vk);
    out.extend_from_slice(&cert.not_after_ms.to_be_bytes());
    out.extend_from_slice(&cert.serial.to_be_bytes());
    out.extend_from_slice(&cert.signature);
    Ok(out)
}

/// Decode a certificate. The signature is not verified here.
///
/// # Errors
///
/// Wrong magic or version, truncation, or trailing bytes.
pub fn decode_cert(bytes: &[u8]) -> Result<DeviceCert> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != CERT_MAGIC || reader.u16()? != CERT_WIRE_VERSION {
        return Err(anyhow!("unsupported device cert encoding"));
    }
    let client_id = reader.array()?;
    let device_id = reader.array()?;
    let device_vk = reader.array()?;
    let not_after_ms = reader.u64()?;
    let serial = reader.u64()?;
    let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
    reader.finish()?;
    Ok(DeviceCert {
        client_id,
        device_id,
        device_vk,
        not_after_ms,
        serial,
        signature,
    })
}
