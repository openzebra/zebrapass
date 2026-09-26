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
use frame::{frame_at, latest, parse_index, FrameMeta, FrameRef, ALG_AEGIS256, KIND_REVISION, KIND_TOMBSTONE};
use kdf::frame_key;
use record::Document;
use secret::Secret;

use crate::create::Session;
use crate::rotate::write_records;

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
pub fn open_revision(
    session: &Session,
    record_id: u32,
    revision: u64,
) -> anyhow::Result<Document> {
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
    let refs = index(session)?;
    let record_id = if let Some(id) = id {
        id
    } else {
        let max = refs.iter().map(|r| r.record_id).max().unwrap_or(0);
        max.checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record id overflow"))?
    };
    let revision = next_revision(latest(&refs, record_id))?;
    append_frame(session, file, record_id, revision, KIND_REVISION, &doc.encode()?)?;
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
            let keep = latest(&refs, reference.record_id).is_some_and(|winner| {
                winner.is_revision() && winner.start == reference.start
            });
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

fn frame_key_for(
    session: &Session,
    record_id: u32,
) -> anyhow::Result<Secret<[u8; 32]>> {
    frame_key(session.vk.expose(), &session.vault_id, record_id)
}

fn open_frame(session: &Session, reference: &FrameRef) -> anyhow::Result<Document> {
    let key = frame_key_for(session, reference.record_id)?;
    let bytes = frame_at(session.records.expose(), reference)?;
    let plaintext = frame::open(&key, bytes)?;
    Document::parse(plaintext.expose())
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
        origin_device: session.origin_device.unwrap_or([0u8; 16]),
        timestamp_ms: now_ms(),
        alg: ALG_AEGIS256,
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
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "tests may unwrap, index, and panic"
    )]

    use aead::BodyAlg;
    use kdf::KdfProfile;
    use record::{Document, ValueType, TAG_NAME, TAG_PASSWORD, TAG_TITLE};

    use super::{delete_record, history, list_records, open_record, open_revision, restore_revision, vault_meta, RecordSummary};
    use crate::{create, write_record, write_vault_meta};

    fn sample_doc(title: &str, password: &str) -> Document {
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, title);
        doc.set_data(TAG_PASSWORD, ValueType::Secret, password.as_bytes());
        doc
    }

    fn fresh_vault() -> (container::VaultFile, crate::Session) {
        let master = [1u8; 64];
        create(&master, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap()
    }

    #[test]
    fn record_lifecycle() {
        let (mut file, mut session) = fresh_vault();
        let id = write_record(&mut session, &mut file, None, &sample_doc("Blog", "p1")).unwrap();
        assert_eq!(id, 1);
        let listed = list_records(&session).unwrap();
        assert_eq!(listed, vec![RecordSummary { id: 1, revision: 1, timestamp_ms: listed[0].timestamp_ms }]);
        let doc = open_record(&session, 1).unwrap();
        assert_eq!(doc.text(TAG_TITLE).unwrap().unwrap(), "Blog");

        write_record(&mut session, &mut file, Some(1), &sample_doc("Blog", "p2")).unwrap();
        assert_eq!(history(&session, 1).unwrap().len(), 2);

        let restored_rev =
            restore_revision(&mut session, &mut file, 1, 1).unwrap();
        assert_eq!(restored_rev, 3);
        assert_eq!(
            open_record(&session, 1).unwrap().data(TAG_PASSWORD).unwrap().unwrap(),
            b"p1".as_slice()
        );
        assert_eq!(history(&session, 1).unwrap().len(), 3);

        let tomb = delete_record(&mut session, &mut file, 1).unwrap();
        assert_eq!(tomb, 4);
        assert!(list_records(&session).unwrap().is_empty());
        assert_eq!(open_record(&session, 1).unwrap_err().to_string(), "record deleted");
        assert_eq!(
            open_revision(&session, 1, 1).unwrap().text(TAG_TITLE).unwrap().unwrap(),
            "Blog"
        );
    }

    #[test]
    fn missing_and_deleted_records() {
        let (mut file, mut session) = fresh_vault();
        assert_eq!(open_record(&session, 9).unwrap_err().to_string(), "record not found");
        assert_eq!(
            delete_record(&mut session, &mut file, 9).unwrap_err().to_string(),
            "record not found"
        );
        write_record(&mut session, &mut file, Some(9), &sample_doc("Nine", "")).unwrap();
        delete_record(&mut session, &mut file, 9).unwrap();
        assert_eq!(
            delete_record(&mut session, &mut file, 9).unwrap_err().to_string(),
            "record deleted"
        );
    }

    #[test]
    fn ids_are_allocated_from_the_highest() {
        let (mut file, mut session) = fresh_vault();
        let a = write_record(&mut session, &mut file, Some(5), &sample_doc("A", "")).unwrap();
        let b = write_record(&mut session, &mut file, None, &sample_doc("B", "")).unwrap();
        assert_eq!((a, b), (5, 6));
        // Explicit ids can be sparse; allocation follows the maximum.
        let listed = list_records(&session).unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn vault_meta_round_trip() {
        let (mut file, mut session) = fresh_vault();
        assert!(vault_meta(&session).unwrap().fields().is_empty());
        let mut doc = Document::new();
        doc.set_text(TAG_NAME, "Personal");
        let rev = write_vault_meta(&mut session, &mut file, &doc).unwrap();
        assert_eq!(rev, 1);
        let meta = vault_meta(&session).unwrap();
        assert_eq!(meta.text(TAG_NAME).unwrap().unwrap(), "Personal");
        // Vault meta is hidden from the record list.
        assert!(list_records(&session).unwrap().is_empty());
        // Unknown frames and vault meta survive record writes.
        write_record(&mut session, &mut file, Some(1), &sample_doc("R", "")).unwrap();
        assert_eq!(vault_meta(&session).unwrap().text(TAG_NAME).unwrap().unwrap(), "Personal");
    }
}
