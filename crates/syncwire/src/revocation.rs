//! Wire form of [`Revocation`]: fixed length, strictly parsed.

use anyhow::{anyhow, Result};
use session::{Revocation, SYNC_SIG_LEN};

use crate::cert::{decode_cert, encode_cert, CERT_WIRE_LEN};
use crate::reader::Reader;

/// First four bytes of an encoded revocation.
pub const REVOCATION_MAGIC: [u8; 4] = *b"ZPRV";
/// Current revocation wire version.
pub const REVOCATION_WIRE_VERSION: u16 = 1;
/// Exact length of an encoded revocation.
pub const REVOCATION_WIRE_LEN: usize = 4 + 2 + 64 + 16 + 8 + 8 + CERT_WIRE_LEN + SYNC_SIG_LEN;

/// Encode `revocation`.
///
/// # Errors
///
/// The signature is not [`SYNC_SIG_LEN`] bytes, or the signer certificate
/// does not encode.
pub fn encode_revocation(revocation: &Revocation) -> Result<Vec<u8>> {
    if revocation.signature.len() != SYNC_SIG_LEN {
        return Err(anyhow!("revocation signature length"));
    }
    let mut out = Vec::with_capacity(REVOCATION_WIRE_LEN);
    out.extend_from_slice(&REVOCATION_MAGIC);
    out.extend_from_slice(&REVOCATION_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&revocation.client_id);
    out.extend_from_slice(&revocation.device_id);
    out.extend_from_slice(&revocation.serial.to_be_bytes());
    out.extend_from_slice(&revocation.revoked_at_ms.to_be_bytes());
    out.extend_from_slice(&encode_cert(&revocation.signer)?);
    out.extend_from_slice(&revocation.signature);
    Ok(out)
}

/// Decode a revocation. The signature is not verified here.
///
/// # Errors
///
/// Wrong magic, version or length, or a malformed signer certificate.
pub fn decode_revocation(bytes: &[u8]) -> Result<Revocation> {
    if bytes.len() != REVOCATION_WIRE_LEN {
        return Err(anyhow!("unsupported revocation encoding"));
    }
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != REVOCATION_MAGIC || reader.u16()? != REVOCATION_WIRE_VERSION {
        return Err(anyhow!("unsupported revocation encoding"));
    }
    let client_id = reader.array()?;
    let device_id = reader.array()?;
    let serial = reader.u64()?;
    let revoked_at_ms = reader.u64()?;
    let signer = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
    let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
    reader.finish()?;
    Ok(Revocation {
        client_id,
        device_id,
        serial,
        revoked_at_ms,
        signer,
        signature,
    })
}
