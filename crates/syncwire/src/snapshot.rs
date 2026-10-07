//! A vault file with the attestations of its records: what a member sends a
//! device that must take a whole vault, so the receiver can check that every
//! record was signed by a writer.

use anyhow::{anyhow, Result};
use session::Attestation;

use crate::attestation::{decode_attestation, encode_attestation, ATTESTATION_WIRE_LEN};
use crate::reader::Reader;

/// First four bytes of an encoded snapshot.
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"ZPSN";
/// Current snapshot wire version.
pub const SNAPSHOT_WIRE_VERSION: u16 = 1;
/// Most attestations a snapshot carries.
pub const MAX_SNAPSHOT_ATTESTATIONS: usize = 4096;

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

/// Encode `file` after its `attestations`.
///
/// # Errors
///
/// More than [`MAX_SNAPSHOT_ATTESTATIONS`] attestations, or one that does
/// not encode.
pub fn encode_snapshot(file: &[u8], attestations: &[Attestation]) -> Result<Vec<u8>> {
    if attestations.len() > MAX_SNAPSHOT_ATTESTATIONS {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(
        SNAPSHOT_MAGIC.len() + 2 + 2 + attestations.len() * ATTESTATION_WIRE_LEN + file.len(),
    );
    out.extend_from_slice(&SNAPSHOT_MAGIC);
    out.extend_from_slice(&SNAPSHOT_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&u16::try_from(attestations.len())?.to_be_bytes());
    for attestation in attestations {
        out.extend_from_slice(&encode_attestation(attestation)?);
    }
    out.extend_from_slice(file);
    Ok(out)
}

/// Split an encoded snapshot into the vault file and its attestations. The
/// file is not parsed and the attestations are not verified here; the file
/// reuses the buffer.
///
/// # Errors
///
/// A wrong magic or version, a count over the bound, or truncation.
pub fn decode_snapshot(mut bytes: Vec<u8>) -> Result<(Vec<u8>, Vec<Attestation>)> {
    let mut reader = Reader::new(&bytes);
    if reader.array::<4>()? != SNAPSHOT_MAGIC || reader.u16()? != SNAPSHOT_WIRE_VERSION {
        return Err(invalid());
    }
    let count = usize::from(reader.u16()?);
    if count > MAX_SNAPSHOT_ATTESTATIONS {
        return Err(invalid());
    }
    let attestations = (0..count)
        .map(|_| decode_attestation(reader.take(ATTESTATION_WIRE_LEN)?))
        .collect::<Result<Vec<_>>>()?;
    bytes.drain(..SNAPSHOT_MAGIC.len() + 2 + 2 + count * ATTESTATION_WIRE_LEN);
    Ok((bytes, attestations))
}
