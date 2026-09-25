//! Export one sealed record as a self-contained sync object.
//!
//! A sync record is the record's latest sealed frame plus its revision and
//! an ML-DSA signature over the frame bytes. Receiving devices keep the
//! remote copy only when its revision is strictly newer ([`newer`]).

use sha2::{Digest, Sha256};

use crate::create::Session;
use crate::sync_sig::{sign_record, sync_verifying_key, verify_record, SYNC_SEED_LEN, SYNC_VK_LEN};

/// One record's sync payload: the latest sealed frame, signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncRecord {
    /// Record the frame belongs to.
    pub record_id: u32,
    /// Revision of the exported frame.
    pub revision: u64,
    /// Sealed frame bytes (header + ciphertext + tag).
    pub frame: Vec<u8>,
    /// SHA-256 of [`SyncRecord::frame`].
    pub content_hash: [u8; 32],
    /// ML-DSA-65 signature over [`record_message`](crate::sync_sig) fields.
    pub signature: Vec<u8>,
}

impl SyncRecord {
    /// Verify the signature over this payload.
    ///
    /// # Errors
    ///
    /// See [`verify_record`].
    pub fn verify(&self, verifying_key: &[u8; SYNC_VK_LEN], vault_id: &[u8; 16]) -> anyhow::Result<()> {
        verify_record(
            verifying_key,
            vault_id,
            self.record_id,
            self.revision,
            &self.content_hash,
            &self.frame,
            &self.signature,
        )
    }
}

/// True when a remote frame should replace the local one. Equal revisions
/// tie-break on `(revision, origin_device)` at frame level; same revision
/// and same device is a no-op, so `newer` is strict.
#[must_use]
pub const fn newer(local_revision: u64, remote_revision: u64) -> bool {
    remote_revision > local_revision
}

/// Sign and export the latest frame of `record_id`.
///
/// # Errors
///
/// `unknown record` when the session has no frame for that id; frame
/// indexing, key derivation, and signing errors otherwise.
pub fn export_record(
    session: &Session,
    sync_seed: &[u8; SYNC_SEED_LEN],
    record_id: u32,
) -> anyhow::Result<SyncRecord> {
    let refs = frame::parse_index(session.records.expose())?;
    let reference = frame::latest(&refs, record_id)
        .ok_or_else(|| anyhow::anyhow!("unknown record"))?;
    let frame_bytes = frame::frame_at(session.records.expose(), reference)?.to_vec();
    let revision = reference.revision;
    let content_hash: [u8; 32] = Sha256::digest(&frame_bytes).into();
    let signature = sign_record(
        sync_seed,
        session.vault_id(),
        record_id,
        revision,
        &content_hash,
        &frame_bytes,
    )?;
    Ok(SyncRecord {
        record_id,
        revision,
        frame: frame_bytes,
        content_hash,
        signature,
    })
}

/// Verify an exported payload against the verifying key of `sync_seed`.
///
/// # Errors
///
/// See [`SyncRecord::verify`].
pub fn verify_sync_record(
    record: &SyncRecord,
    sync_seed: &[u8; SYNC_SEED_LEN],
    vault_id: &[u8; 16],
) -> anyhow::Result<()> {
    let key = sync_verifying_key(sync_seed)?;
    record.verify(&key, vault_id)
}
