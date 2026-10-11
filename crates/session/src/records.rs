//! Record operations over the decrypted frame body.
//!
//! The body is a sequence of frames; a record is a `record_id` shared by
//! its frames. The winning frame of a record is the highest
//! `(revision, origin_device)` — a deterministic order that does not
//! depend on clocks. A write appends one frame: a new revision for a
//! record write or restore, a tombstone for a delete. Nothing in the body
//! is ever rewritten in place except by [`clear_history`], which drops
//! frames wholesale. Frames with unknown kinds or algorithms are carried
//! over byte for byte.

use std::time::{SystemTime, UNIX_EPOCH};

use container::VaultFile;
use frame::{
    frame_at, latest, parse_index, FrameMeta, FrameRef, ALG_CASCADE, KIND_REVISION, KIND_TOMBSTONE,
};
use kdf::frame_key;
use record::Document;
use secret::Secret;

use crate::create::Session;
use crate::rotate::write_records;

mod batch;
mod ids;

pub use batch::{write_records_batch, MAX_BATCH};
pub use ids::fresh_record_id;

/// One live record: its winning revision frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSummary {
    /// Record id.
    pub id: u32,
    /// Revision of the winning frame.
    pub revision: u64,
    /// Advisory unix milliseconds of the winning frame.
    pub timestamp_ms: u64,
}

/// One revision of one record: header information only. The plaintext is
/// materialized by [`open_revision`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionInfo {
    /// Revision counter.
    pub revision: u64,
    /// Device that sealed this revision.
    pub origin_device: [u8; 16],
    /// Advisory unix milliseconds.
    pub timestamp_ms: u64,
}

/// Every live record in the vault, by ascending id. Deleted records and
/// the vault metadata (`id` 0) are hidden.
///
/// # Errors
///
/// `corrupted length` when the session body is not a valid frame sequence.
pub fn list_records(session: &Session) -> anyhow::Result<Vec<RecordSummary>> {
    let refs = index(session)?;
    let mut ids: Vec<u32> = refs
        .iter()
        .filter(|r| r.known() && r.record_id != 0)
        .map(|r| r.record_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(winner) = latest(&refs, id) {
            if winner.is_revision() {
                out.push(RecordSummary {
                    id,
                    revision: winner.revision,
                    timestamp_ms: winner.timestamp_ms,
                });
            }
        }
    }
    Ok(out)
}

/// The current document of `record_id`: the winning revision frame,
/// opened on demand.
///
/// # Errors
///
/// `record not found` when no frame carries the id (or its newest frame
/// has an unknown kind); `record deleted` when the newest frame is a
/// tombstone; frame-key and frame-open errors as in [`crate::unlock`].
pub fn open_record(session: &Session, record_id: u32) -> anyhow::Result<Document> {
    let refs = index(session)?;
    let Some(winner) = latest(&refs, record_id) else {
        anyhow::bail!("record not found");
    };
    if winner.is_tombstone() {
        anyhow::bail!("record deleted");
    }
    if !winner.is_revision() {
        anyhow::bail!("record not found");
    }
    open_frame(session, winner)
}

/// One historical revision of `record_id`, opened on demand.
///
/// # Errors
///
/// `revision not found` when no revision frame carries that exact
/// revision; frame errors as in [`open_record`].
pub fn open_revision(session: &Session, record_id: u32, revision: u64) -> anyhow::Result<Document> {
    let refs = index(session)?;
    let winner = refs
        .iter()
        .filter(|r| r.record_id == record_id && r.is_revision() && r.revision == revision)
        .max_by(|a, b| a.origin_device.cmp(&b.origin_device))
        .ok_or_else(|| anyhow::anyhow!("revision not found"))?;
    open_frame(session, winner)
}

/// The revision history of `record_id`, oldest first. Tombstones are not
/// revisions and are not listed.
///
/// # Errors
///
/// `corrupted length` when the session body is not a valid frame sequence.
pub fn history(session: &Session, record_id: u32) -> anyhow::Result<Vec<RevisionInfo>> {
    let refs = index(session)?;
    let mut infos: Vec<RevisionInfo> = refs
        .iter()
        .filter(|r| r.record_id == record_id && r.is_revision())
        .map(|r| RevisionInfo {
            revision: r.revision,
            origin_device: r.origin_device,
            timestamp_ms: r.timestamp_ms,
        })
        .collect();
    infos.sort_unstable_by_key(|info| (info.revision, info.origin_device));
    infos.dedup();
    Ok(infos)
}

/// Write `doc` as the next revision of `record_id`, or of a fresh record
/// when `id` is `None`: the id is one past the highest id in the body
/// (never 0). Returns the record id.
///
/// # Errors
///
/// `record id overflow` when the highest id is `u32::MAX`;
/// `revision overflow` when the record's newest revision is `u64::MAX`;
/// `frame too large` or `document too large` for oversize payloads;
/// frame-key and body-write errors as in [`crate::write_records`].
pub fn write_record(
    session: &mut Session,
    file: &mut VaultFile,
    id: Option<u32>,
    doc: &Document,
) -> anyhow::Result<u32> {
    let record_id = match id {
        Some(id) => id,
        None => fresh_record_id(session)?,
    };
    let refs = index(session)?;
    let revision = next_revision(latest(&refs, record_id))?;
    let encoded = doc.encode()?;
    append_frame(
        session,
        file,
        record_id,
        revision,
        KIND_REVISION,
        &pack_frame(&encoded)?,
    )?;
    Ok(record_id)
}

/// Append a tombstone for `record_id`. Returns the tombstone revision.
///
/// # Errors
///
/// `record not found` when no frame carries the id; `record deleted` when
/// the newest frame is already a tombstone; `revision overflow` as in
/// [`write_record`].
pub fn delete_record(
    session: &mut Session,
    file: &mut VaultFile,
    record_id: u32,
) -> anyhow::Result<u64> {
    let refs = index(session)?;
    let winner = latest(&refs, record_id).ok_or_else(|| anyhow::anyhow!("record not found"))?;
    if winner.is_tombstone() {
        anyhow::bail!("record deleted");
    }
    let revision = next_revision(Some(winner))?;
    append_frame(session, file, record_id, revision, KIND_TOMBSTONE, &[])?;
    Ok(revision)
}

/// Copy an old revision into a brand-new revision of the same record.
/// History is immutable: the old frame stays. Returns the new revision.
///
/// # Errors
///
/// Revision errors as in [`open_revision`]; write errors as in
/// [`write_record`].
pub fn restore_revision(
    session: &mut Session,
    file: &mut VaultFile,
    record_id: u32,
    revision: u64,
) -> anyhow::Result<u64> {
    let doc = open_revision(session, record_id, revision)?;
    let id = write_record(session, file, Some(record_id), &doc)?;
    let refs = index(session)?;
    latest(&refs, id)
        .map(|winner| winner.revision)
        .ok_or_else(|| anyhow::anyhow!("record not found"))
}

/// Drop superseded history: every live record keeps only its winning
/// frame, and the frames of deleted records are dropped entirely.
///
/// Unknown frames are preserved byte for byte. When nothing would change,
/// the file is left alone.
///
/// # Errors
///
/// `corrupted length` when the session body is not a valid frame sequence;
/// body-write errors as in [`crate::write_records`].
pub fn clear_history(session: &mut Session, file: &mut VaultFile) -> anyhow::Result<()> {
    let refs = index(session)?;
    let old = session.records.expose();
    let mut next: Vec<u8> = Vec::with_capacity(old.len());
    for reference in &refs {
        if reference.known() {
            let keep = latest(&refs, reference.record_id)
                .is_some_and(|winner| winner.is_revision() && winner.start == reference.start);
            if !keep {
                continue;
            }
        }
        next.extend_from_slice(frame_at(old, reference)?);
    }
    if next.len() == old.len() {
        return Ok(());
    }
    crate::rewrite_body(session, file, &next)
}

/// The vault metadata document (`record_id` 0), or an empty document when
/// none was written yet.
///
/// # Errors
///
/// Frame errors as in [`open_record`].
pub fn vault_meta(session: &Session) -> anyhow::Result<Document> {
    let refs = index(session)?;
    match latest(&refs, 0) {
        Some(winner) if winner.is_revision() => open_frame(session, winner),
        _ => Ok(Document::new()),
    }
}

/// Replace the vault metadata with `doc` as its next revision. Returns
/// the new revision.
///
/// # Errors
///
/// `revision overflow` as in [`write_record`]; write errors as in
/// [`write_record`].
pub fn write_vault_meta(
    session: &mut Session,
    file: &mut VaultFile,
    doc: &Document,
) -> anyhow::Result<u64> {
    let refs = index(session)?;
    let revision = next_revision(latest(&refs, 0))?;
    append_frame(session, file, 0, revision, KIND_REVISION, &doc.encode()?)?;
    Ok(revision)
}

fn index(session: &Session) -> anyhow::Result<Vec<FrameRef>> {
    parse_index(session.records.expose())
}

fn frame_key_for(session: &Session, record_id: u32) -> anyhow::Result<Secret<[u8; 32]>> {
    frame_key(session.vk.expose(), &session.vault_id, record_id)
}

fn open_frame(session: &Session, reference: &FrameRef) -> anyhow::Result<Document> {
    let key = frame_key_for(session, reference.record_id)?;
    let bytes = frame_at(session.records.expose(), reference)?;
    let plaintext = frame::open(&key, bytes)?;
    Document::parse(unpack_frame(plaintext.expose())?)
}

/// Ciphertext sizes at which record writes are padded, so the sealed
/// frame length only reveals the bucket, not the document size.
const BUCKETS: [usize; 6] = [256, 1024, 4_096, 16_384, 65_536, 262_144];

/// First four bytes of a padded frame: `"ZPAD"`. Encoded documents begin
/// with the little-endian schema `u16`, so no document can start with it.
const PAD_MAGIC: [u8; 4] = *b"ZPAD";

/// Frames written before the padding scheme carry the document verbatim;
/// `unpack_frame` tells the two layouts apart by the `ZPAD` prefix.
fn unpack_frame(plaintext: &[u8]) -> anyhow::Result<&[u8]> {
    let Some(magic) = plaintext.first_chunk::<4>() else {
        return Ok(plaintext);
    };
    if magic != &PAD_MAGIC {
        return Ok(plaintext);
    }
    let real_len = plaintext
        .get(4..8)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_le_bytes) as usize;
    plaintext
        .get(8..8 + real_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))
}

/// Wire layout of a padded record plaintext:
/// `"ZPAD" ‖ u32 real_len ‖ doc ‖ zero padding`.
fn pack_frame(doc: &[u8]) -> anyhow::Result<Vec<u8>> {
    let bucket = BUCKETS.iter().copied().find(|bucket| {
        doc.len()
            .checked_add(8)
            .is_some_and(|total| total <= *bucket)
    });
    let padded = match bucket {
        Some(bucket) => bucket,
        None => total_len(doc.len())?,
    };
    let mut out = vec![0u8; padded];
    let real_len = u32::try_from(doc.len()).map_err(|_| anyhow::anyhow!("document too large"))?;
    let Some(head) = out.get_mut(..4) else {
        return Err(anyhow::anyhow!("frame too small"));
    };
    head.copy_from_slice(&PAD_MAGIC);
    let Some(prefix) = out.get_mut(4..8) else {
        return Err(anyhow::anyhow!("frame too small"));
    };
    prefix.copy_from_slice(&real_len.to_le_bytes());
    let Some(body) = out.get_mut(8..8 + doc.len()) else {
        return Err(anyhow::anyhow!("frame too small"));
    };
    body.copy_from_slice(doc);
    Ok(out)
}

fn total_len(doc_len: usize) -> anyhow::Result<usize> {
    doc_len
        .checked_add(4)
        .and_then(|total| total.checked_next_multiple_of(65_536))
        .ok_or_else(|| anyhow::anyhow!("frame too large"))
}

fn next_revision(winner: Option<&FrameRef>) -> anyhow::Result<u64> {
    winner.map_or(Ok(1), |winner| {
        winner
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("revision overflow"))
    })
}

fn append_frame(
    session: &mut Session,
    file: &mut VaultFile,
    record_id: u32,
    revision: u64,
    kind: u8,
    plaintext: &[u8],
) -> anyhow::Result<()> {
    let meta = FrameMeta {
        kind,
        record_id,
        revision,
        origin_device: session.origin_device,
        timestamp_ms: now_ms(),
        alg: ALG_CASCADE,
    };
    let key = frame_key_for(session, record_id)?;
    let frame_bytes = frame::seal(&key, &meta, plaintext)?;
    // write_records appends: it owns the old bytes and the commit update.
    write_records(session, file, &frame_bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests;
