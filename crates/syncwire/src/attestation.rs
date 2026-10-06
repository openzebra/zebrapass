//! Wire forms of what two devices exchange to keep a shared vault in step:
//! an attestation, an attestation with its frame (a bundle), and a frontier.

use anyhow::{anyhow, Result};
use session::{Attestation, FrontierEntry, SYNC_SIG_LEN};

use crate::cert::{decode_cert, encode_cert, CERT_WIRE_LEN};
use crate::limits::MAX_FRAME;
use crate::reader::Reader;

/// First four bytes of an encoded attestation.
pub const ATTESTATION_MAGIC: [u8; 4] = *b"ZPRA";
/// Current attestation wire version.
pub const ATTESTATION_WIRE_VERSION: u16 = 1;
/// Exact length of an encoded attestation.
pub const ATTESTATION_WIRE_LEN: usize = 4 + 2 + 16 + 4 + 8 + 16 + 32 + CERT_WIRE_LEN + SYNC_SIG_LEN;

/// Most records a frontier names.
pub const MAX_FRONTIER: usize = 16_384;

/// Length of one frontier entry.
const ENTRY_LEN: usize = 4 + 8 + 16;

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

/// Encode `attestation`.
///
/// # Errors
///
/// The signature is not [`SYNC_SIG_LEN`] bytes.
pub fn encode_attestation(attestation: &Attestation) -> Result<Vec<u8>> {
    if attestation.signature.len() != SYNC_SIG_LEN {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(ATTESTATION_WIRE_LEN);
    out.extend_from_slice(&ATTESTATION_MAGIC);
    out.extend_from_slice(&ATTESTATION_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&attestation.vault_id);
    out.extend_from_slice(&attestation.record_id.to_be_bytes());
    out.extend_from_slice(&attestation.revision.to_be_bytes());
    out.extend_from_slice(&attestation.origin_device);
    out.extend_from_slice(&attestation.plain_digest);
    out.extend_from_slice(&encode_cert(&attestation.signer)?);
    out.extend_from_slice(&attestation.signature);
    Ok(out)
}

/// Decode an attestation. The signature is not verified here.
///
/// # Errors
///
/// A wrong length, magic or version, or a malformed certificate.
pub fn decode_attestation(bytes: &[u8]) -> Result<Attestation> {
    if bytes.len() != ATTESTATION_WIRE_LEN {
        return Err(invalid());
    }
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != ATTESTATION_MAGIC || reader.u16()? != ATTESTATION_WIRE_VERSION {
        return Err(invalid());
    }
    let vault_id = reader.array()?;
    let record_id = reader.u32()?;
    let revision = reader.u64()?;
    let origin_device = reader.array()?;
    let plain_digest = reader.array()?;
    let signer = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
    let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
    reader.finish()?;
    Ok(Attestation {
        vault_id,
        record_id,
        revision,
        origin_device,
        plain_digest,
        signer,
        signature,
    })
}

/// An attestation followed by the sealed frame it describes.
///
/// # Errors
///
/// An attestation that does not encode, or a frame over [`MAX_FRAME`].
pub fn encode_bundle(attestation: &Attestation, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() > MAX_FRAME {
        return Err(invalid());
    }
    let mut out = encode_attestation(attestation)?;
    out.extend_from_slice(frame);
    Ok(out)
}

/// Split a bundle into its attestation and its frame.
///
/// # Errors
///
/// A bundle shorter than an attestation, a frame over [`MAX_FRAME`], or an
/// attestation that does not decode.
pub fn decode_bundle(bytes: &[u8]) -> Result<(Attestation, &[u8])> {
    let (head, frame) = bytes
        .split_at_checked(ATTESTATION_WIRE_LEN)
        .ok_or_else(invalid)?;
    if frame.len() > MAX_FRAME {
        return Err(invalid());
    }
    Ok((decode_attestation(head)?, frame))
}

/// Encode a frontier: a count, then one entry per record in id order.
///
/// # Errors
///
/// More than [`MAX_FRONTIER`] entries, or ids not strictly increasing.
pub fn encode_frontier(entries: &[FrontierEntry]) -> Result<Vec<u8>> {
    let ordered = entries.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(a, b)| a.record_id < b.record_id)
    });
    if entries.len() > MAX_FRONTIER || !ordered {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(4 + entries.len() * ENTRY_LEN);
    out.extend_from_slice(&u32::try_from(entries.len())?.to_be_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.record_id.to_be_bytes());
        out.extend_from_slice(&entry.revision.to_be_bytes());
        out.extend_from_slice(&entry.origin_device);
    }
    Ok(out)
}

/// Decode a frontier. The count is checked against the bound before
/// anything is allocated.
///
/// # Errors
///
/// A count over [`MAX_FRONTIER`], a length that does not match it, or ids
/// that are not strictly increasing.
pub fn decode_frontier(bytes: &[u8]) -> Result<Vec<FrontierEntry>> {
    let mut reader = Reader::new(bytes);
    let count = usize::try_from(reader.u32()?).map_err(|_| invalid())?;
    if count > MAX_FRONTIER || bytes.len() != 4 + count * ENTRY_LEN {
        return Err(invalid());
    }
    let entries = (0..count)
        .map(|_| {
            Ok(FrontierEntry {
                record_id: reader.u32()?,
                revision: reader.u64()?,
                origin_device: reader.array()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    let ordered = entries.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(a, b)| a.record_id < b.record_id)
    });
    if ordered {
        Ok(entries)
    } else {
        Err(invalid())
    }
}
