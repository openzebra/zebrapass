//! Wire form of [`SyncRecord`].

use anyhow::{anyhow, Result};
use session::{SyncRecord, SYNC_SIG_LEN};

use crate::limits::{MAX_FRAME, MAX_ORIGIN};
use crate::reader::Reader;

/// First four bytes of an encoded record.
pub const RECORD_MAGIC: [u8; 4] = *b"ZPSR";
/// Current record wire version.
pub const RECORD_WIRE_VERSION: u16 = 1;

/// Encode `record`.
///
/// # Errors
///
/// A field exceeds its wire bound.
pub fn encode_record(record: &SyncRecord) -> Result<Vec<u8>> {
    if record.server_origin.len() > MAX_ORIGIN || record.frame.len() > MAX_FRAME {
        return Err(anyhow!("sync record field over limit"));
    }
    if record.signature.len() != SYNC_SIG_LEN {
        return Err(anyhow!("sync record signature length"));
    }
    let origin_len = u16::try_from(record.server_origin.len())?;
    let frame_len = u32::try_from(record.frame.len())?;
    let mut out = Vec::with_capacity(
        4 + 2
            + 64
            + 32
            + 32
            + 16
            + 16
            + 4
            + 8
            + 2
            + 4
            + 2
            + record.server_origin.len()
            + 4
            + record.frame.len()
            + SYNC_SIG_LEN,
    );
    out.extend_from_slice(&RECORD_MAGIC);
    out.extend_from_slice(&RECORD_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&record.client_id);
    out.extend_from_slice(&record.prev_hash);
    out.extend_from_slice(&record.content_hash);
    out.extend_from_slice(&record.vault_id);
    out.extend_from_slice(&record.device_id);
    out.extend_from_slice(&record.record_id.to_be_bytes());
    out.extend_from_slice(&record.revision.to_be_bytes());
    out.extend_from_slice(&record.msg_version.to_be_bytes());
    out.extend_from_slice(&record.key_generation.to_be_bytes());
    out.extend_from_slice(&origin_len.to_be_bytes());
    out.extend_from_slice(&record.server_origin);
    out.extend_from_slice(&frame_len.to_be_bytes());
    out.extend_from_slice(&record.frame);
    out.extend_from_slice(&record.signature);
    Ok(out)
}

/// Decode a record. The signature is not verified here.
///
/// # Errors
///
/// Wrong magic or version, a length over its bound, truncation, or trailing
/// bytes.
pub fn decode_record(bytes: &[u8]) -> Result<SyncRecord> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != RECORD_MAGIC || reader.u16()? != RECORD_WIRE_VERSION {
        return Err(anyhow!("unsupported sync record encoding"));
    }
    let client_id = reader.array()?;
    let prev_hash = reader.array()?;
    let content_hash = reader.array()?;
    let vault_id = reader.array()?;
    let device_id = reader.array()?;
    let record_id = reader.u32()?;
    let revision = reader.u64()?;
    let msg_version = reader.u16()?;
    let key_generation = reader.u32()?;
    let server_origin = Box::from(reader.bytes_u16(MAX_ORIGIN)?);
    let frame = reader.bytes_u32(MAX_FRAME)?.to_vec();
    let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
    reader.finish()?;
    Ok(SyncRecord {
        client_id,
        prev_hash,
        content_hash,
        vault_id,
        device_id,
        record_id,
        revision,
        msg_version,
        key_generation,
        server_origin,
        frame,
        signature,
    })
}
