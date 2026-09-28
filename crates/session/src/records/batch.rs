//! Many new records in one body append.

use container::VaultFile;
use frame::{FrameMeta, ALG_CASCADE, KIND_REVISION};
use record::Document;
use zeroize::Zeroizing;

use super::{frame_key_for, index, now_ms, pack_frame};
use crate::create::Session;
use crate::rotate::write_records;

/// Most documents written by one [`write_records_batch`] call.
pub const MAX_BATCH: usize = 20_000;

/// Write every document in `docs` as a new record in one body append.
///
/// One generation, one commit update. Returns the new record ids in input
/// order; they continue after the highest id in the body.
///
/// # Errors
///
/// `batch too large` above [`MAX_BATCH`]; `record id overflow` when the ids
/// would pass `u32::MAX`; frame and body-write errors as in
/// [`super::write_record`]. On error the vault is unchanged.
pub fn write_records_batch(
    session: &mut Session,
    file: &mut VaultFile,
    docs: &[Document],
) -> anyhow::Result<Vec<u32>> {
    if docs.len() > MAX_BATCH {
        anyhow::bail!("batch too large");
    }
    if docs.is_empty() {
        return Ok(Vec::new());
    }
    let refs = index(session)?;
    let first = refs
        .iter()
        .map(|r| r.record_id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("record id overflow"))?;
    let count = u32::try_from(docs.len()).map_err(|_| anyhow::anyhow!("batch too large"))?;
    first
        .checked_add(count - 1)
        .ok_or_else(|| anyhow::anyhow!("record id overflow"))?;
    let mut frames = Vec::new();
    let ids = docs
        .iter()
        .zip(first..)
        .map(|(doc, record_id)| {
            let key = frame_key_for(session, record_id)?;
            let encoded = Zeroizing::new(doc.encode()?);
            let padded = Zeroizing::new(pack_frame(&encoded)?);
            let meta = FrameMeta {
                kind: KIND_REVISION,
                record_id,
                revision: 1,
                origin_device: session.origin_device,
                timestamp_ms: now_ms(),
                alg: ALG_CASCADE,
            };
            frames.extend_from_slice(&frame::seal(&key, &meta, &padded)?);
            Ok(record_id)
        })
        .collect::<anyhow::Result<Vec<u32>>>()?;
    write_records(session, file, &frames)?;
    Ok(ids)
}
