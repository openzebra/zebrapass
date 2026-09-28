//! Export one sealed record as a self-contained sync object.
//!
//! A sync record is the record's latest sealed frame plus its revision and
//! an ML-DSA signature over the frame bytes. Every device signs with its own
//! certified key ([`DeviceSignKey`]), so revoking the device revokes its
//! write access. Receiving devices keep the remote copy only when its
//! revision is strictly newer ([`newer`], [`check_fresh`]).

use sha2::{Digest, Sha256};

use crate::create::Session;
use crate::error::SessionError;
use crate::sync_msg::MSG_VERSION;
use crate::sync_sig::{sign_record, verify_record, DeviceSignKey, SyncRecord, SYNC_VK_LEN};

/// True when a remote frame should replace the local one. Equal revisions
/// tie-break on `(revision, origin_device)` at frame level; same revision
/// and same device is a no-op, so `newer` is strict.
#[must_use]
pub const fn newer(local_revision: u64, remote_revision: u64) -> bool {
    remote_revision > local_revision
}

/// The one freshness rule, shared by the client and the server reference:
/// an incoming revision must be strictly newer than the last one seen for
/// that record.
///
/// `last_seen` is `None` before the first sighting.
///
/// # Errors
///
/// [`SessionError::StaleRevision`] when `incoming <= last_seen`.
pub const fn check_fresh(last_seen: Option<u64>, incoming: u64) -> Result<(), SessionError> {
    match last_seen {
        Some(rev) if incoming <= rev => Err(SessionError::StaleRevision),
        _ => Ok(()),
    }
}

/// Sign and export the latest frame of `record_id`.
///
/// `device` is this device's ML-DSA key; the signature binds the server
/// origin, the account `client_id`, the sealing device, `vault_id`,
/// `record_id`, `revision`, the hash of the superseded frame, the content
/// hash, the wire-format version, and the vault-key generation, so the
/// receiver can detect a foreign server, account or vault, a replayed
/// revision, and a stale key epoch. `server_origin` is empty until a sync
/// server exists.
///
/// # Errors
///
/// `unknown record` when the session has no frame for that id;
/// [`SessionError::ZeroOrigin`] when the frame was written by a seed or
/// password unlock (no certified sender can attribute it); frame indexing,
/// key derivation, and signing errors otherwise.
pub fn export_record(
    session: &Session,
    device: &DeviceSignKey,
    record_id: u32,
    client_id: &[u8; 64],
    server_origin: &[u8],
) -> anyhow::Result<SyncRecord> {
    let refs = frame::parse_index(session.records.expose())?;
    let reference =
        frame::latest(&refs, record_id).ok_or_else(|| anyhow::anyhow!("unknown record"))?;
    let prev_hash = refs
        .iter()
        .filter(|r| r.record_id == record_id && r.known() && r.start != reference.start)
        .max_by_key(|r| (r.revision, r.origin_device))
        .map_or(Ok([0u8; 32]), |prev| {
            frame::frame_at(session.records.expose(), prev)
                .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)))
        })?;
    let frame_bytes = frame::frame_at(session.records.expose(), reference)?.to_vec();
    let origin = frame::parse(&frame_bytes)?.origin_device;
    if origin == [0u8; 16] {
        return Err(SessionError::ZeroOrigin.into());
    }
    let content_hash: [u8; 32] = Sha256::digest(&frame_bytes).into();
    let generation =
        u32::try_from(session.generation()).map_err(|_| anyhow::anyhow!("ciphertext too large"))?;
    let unsigned = SyncRecord {
        client_id: *client_id,
        prev_hash,
        content_hash,
        vault_id: *session.vault_id(),
        device_id: origin,
        record_id,
        revision: reference.revision,
        msg_version: MSG_VERSION,
        key_generation: generation,
        server_origin: Box::from(server_origin),
        frame: frame_bytes,
        signature: Vec::new(),
    };
    let signature = sign_record(device, &unsigned)?;
    Ok(SyncRecord {
        signature,
        ..unsigned
    })
}

/// Verify an exported payload against a device verifying key and the vault
/// it claims. The trust decision (is this device key certified?) belongs to
/// the caller, which holds the root key.
///
/// # Errors
///
/// See [`SyncRecord::verify`].
pub fn verify_sync_record(
    record: &SyncRecord,
    device_vk: &[u8; SYNC_VK_LEN],
    vault_id: &[u8; 16],
) -> anyhow::Result<()> {
    verify_record(device_vk, record, vault_id)
}
