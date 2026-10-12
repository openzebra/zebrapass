//! Many new records in one body append.

use container::VaultFile;
use frame::{FrameMeta, ALG_CASCADE, KIND_REVISION};
use record::Document;
use zeroize::Zeroizing;

use super::ids::fresh_many;
use super::{frame_key_for, index, now_ms, pack_frame};
use crate::create::Session;
use crate::rotate::write_records;

/// Most documents written by one [`write_records_batch`] call.
pub const MAX_BATCH: usize = 20_000;

/// Write every document in `docs` as a new record in one body append.
///
/// One generation, one commit update. Returns the new record ids in input
/// order: random, distinct, and none already held.
///
/// # Errors
///
/// `batch too large` above [`MAX_BATCH`]; `no free record id` as in
/// [`super::fresh_record_id`]; frame and body-write errors as in
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
    let fresh = fresh_many(&index(session)?, docs.len())?;
    let mut frames = Vec::new();
    let ids = docs
        .iter()
        .zip(fresh)
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
