//! Keep a record frame another device of the same account sent.
//!
//! A personal vault has no writer roles and its records carry no
//! attestations: the trust anchor is the channel the frame arrived on, which
//! only a device whose certificate chains to this account's root can open,
//! and the vault key, which only such a device holds. So the checks are the
//! frame's own: its shape, its freshness, and that it opens under this
//! vault's key for that record. Shared vaults must not use this path; their
//! records need [`crate::accept_revision`].

use container::VaultFile;
use frame::{ALG_AEGIS256, ALG_CASCADE, KIND_REVISION, KIND_TOMBSTONE};
use kdf::frame_key;

use crate::attest::MAX_ATTESTED_FRAME;
use crate::create::Session;
use crate::error::SessionError;
use crate::rotate::write_records;
use crate::sync_import::Accepted;

/// Keep `frame_bytes` if it is a newer revision of a record of this vault.
///
/// Record 0 (the vault's own metadata) is refused. The same rule keeps it out
/// of shared vaults, where an attestation cannot cover it; here every device
/// is an owner, so the reason is different but the effect is wanted: the
/// frontier never lists record 0, and a change to it travels with the whole
/// vault file, never as a single frame from a peer.
///
/// A revision wins over the local one when `(revision, origin_device)` is
/// greater, the order that picks the winner everywhere, so concurrent edits
/// settle on every device. On error `file` and `session` are unchanged.
///
/// # Errors
///
/// [`SessionError`]: `ZeroOrigin`, `HeaderMismatch` (record 0, an unknown
/// kind or algorithm, an oversized frame), `StaleRevision`; frame-opening
/// failure when the frame was not sealed under this vault's key; publish
/// errors.
pub fn accept_peer_frame(
    session: &mut Session,
    file: &mut VaultFile,
    frame_bytes: &[u8],
) -> anyhow::Result<Accepted> {
    if frame_bytes.len() > MAX_ATTESTED_FRAME {
        return Err(SessionError::HeaderMismatch.into());
    }
    let header = frame::parse(frame_bytes)?;
    if header.origin_device == [0u8; 16] {
        return Err(SessionError::ZeroOrigin.into());
    }
    let shape = header.record_id != 0
        && matches!(header.kind, KIND_REVISION | KIND_TOMBSTONE)
        && matches!(header.alg, ALG_CASCADE | ALG_AEGIS256);
    if !shape {
        return Err(SessionError::HeaderMismatch.into());
    }
    let refs = frame::parse_index(session.records.expose())?;
    let local = frame::latest(&refs, header.record_id)
        .map(|winner| (winner.revision, winner.origin_device));
    if local.is_some_and(|winner| (header.revision, header.origin_device) <= winner) {
        return Err(SessionError::StaleRevision.into());
    }
    frame::open(
        &frame_key(session.vk.expose(), &session.vault_id, header.record_id)?,
        frame_bytes,
    )?;
    write_records(session, file, frame_bytes)?;
    Ok(Accepted {
        record_id: header.record_id,
        revision: header.revision,
        origin_device: header.origin_device,
    })
}
