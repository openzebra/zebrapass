//! Receive and apply a signed sync record.
//!
//! The receiver is a full vault peer: it holds the vault key (through its
//! own wrap) and every frame key derives from it, so an incoming frame is
//! authenticated twice — by the ML-DSA signature over the outer fields and
//! by the frame AEAD — before anything is stored. Checks run cheapest
//! first and nothing is decrypted before the signature verifies.

use sha2::{Digest, Sha256};

use container::VaultFile;
use frame::{parse, Header, ALG_AEGIS256, KIND_REVISION, KIND_TOMBSTONE};
use kdf::frame_key;
use pq::SYNC_VK_LEN;

use crate::create::Session;
use crate::rotate::write_records;
use crate::error::SessionError;
use crate::sync_export::{check_fresh, verify_sync_record};
use crate::sync_sig::{DeviceCert, SyncRecord};

/// Keys this device trusts: the account root plus the certified devices.
#[derive(Debug)]
pub struct TrustedKeys<'a> {
    /// Account id every certificate must carry.
    pub client_id: [u8; 64],
    /// Verifying key of the account root.
    pub root_vk: [u8; SYNC_VK_LEN],
    /// `(origin_device, certificate)` for every enrolled device. The
    /// certificate is re-verified against `root_vk` on every record.
    pub devices: &'a [([u8; 16], DeviceCert)],
    /// Wall clock in unix milliseconds, for certificate expiry.
    pub now_ms: u64,
}

/// What a successful [`accept_record`] applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accepted {
    /// Record the frame belongs to.
    pub record_id: u32,
    /// Revision stored.
    pub revision: u64,
    /// Device that signed and sealed the frame.
    pub origin_device: [u8; 16],
}

/// The record must belong to the vault this session has open.
///
/// `key_generation` is signed bookkeeping for the server's epoch table; the
/// real epoch check for a vault-key change is the AEAD open — a frame sealed
/// under a key this session does not derive cannot open.
fn check_vault(session: &Session, rec: &SyncRecord) -> Result<(), SessionError> {
    if rec.vault_id == *session.vault_id() {
        Ok(())
    } else {
        Err(SessionError::VaultMismatch)
    }
}

/// The signed outer fields must describe the frame they cover, the digest
/// must match, and a certified device must never claim the zero origin
/// (only seed/password unlocks may stamp it).
fn check_header_binding(header: &Header, rec: &SyncRecord) -> Result<(), SessionError> {
    if header.origin_device == [0u8; 16] {
        return Err(SessionError::ZeroOrigin);
    }
    if header.record_id != rec.record_id
        || header.revision != rec.revision
        || !matches!(header.kind, KIND_REVISION | KIND_TOMBSTONE)
        || header.alg != ALG_AEGIS256
    {
        return Err(SessionError::HeaderMismatch);
    }
    let content_hash: [u8; 32] = Sha256::digest(rec.frame.as_slice()).into();
    if content_hash == rec.content_hash {
        Ok(())
    } else {
        Err(SessionError::ContentHashMismatch)
    }
}

/// The certificate that signs for `origin_device`, re-verified now.
fn cert_for<'a>(
    trust: &'a TrustedKeys<'_>,
    origin_device: &[u8; 16],
) -> Result<&'a DeviceCert, SessionError> {
    let (_, cert) = trust
        .devices
        .iter()
        .find(|(id, _)| id == origin_device)
        .ok_or(SessionError::DeviceNotTrusted)?;
    if cert.client_id != trust.client_id {
        return Err(SessionError::CertRejected);
    }
    cert.verify(&trust.root_vk, trust.now_ms)
        .map_err(|error| {
            if error.to_string() == "device cert expired" {
                SessionError::CertExpired
            } else {
                SessionError::CertRejected
            }
        })?;
    Ok(cert)
}

/// The highest revision the vault and the server have both seen.
fn seen_revision(
    local: Option<u64>,
    record_id: u32,
    last_seen: impl Fn(u32) -> Option<u64>,
) -> Option<u64> {
    last_seen(record_id).map_or(local, |remote| {
        Some(local.map_or(remote, |latest| latest.max(remote)))
    })
}

/// The highest revision any known frame carries for `record_id` in the
/// local body.
fn local_latest(session: &Session, record_id: u32) -> anyhow::Result<Option<u64>> {
    Ok(frame::parse_index(session.records.expose())?
        .iter()
        .filter(|r| r.record_id == record_id && r.known())
        .map(|r| r.revision)
        .max())
}

/// Authenticate and apply one incoming record.
///
/// Order of checks, cheapest and strongest first:
/// 1. The claimed signer (frame header `origin_device`) has a live
///    certificate for this account, and the signature over the outer
///    fields verifies under the certified key. This covers the frame
///    bytes, so the header is authenticated afterwards, not before.
/// 2. `vault_id` is this vault; the key epoch rides along as signed
///    bookkeeping while the frame AEAD carries the real epoch check.
/// 3. [`check_fresh`] against both the local body and the caller's
///    `last_seen` table: the revision must be strictly newer than
///    everything seen for that record.
/// 4. The frame header equals the signed outer fields, and the frame kind
///    and algorithm are ones this build can authenticate.
/// 5. The frame opens under the frame key (AEAD authenticates again).
/// 6. The frame is appended through the same publish path as local
///    writes — there is no second copy of that logic.
///
/// On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// [`SessionError`]: [`DeviceNotTrusted`], [`CertRejected`],
/// [`VaultMismatch`], [`StaleRevision`], [`ZeroOrigin`],
/// [`HeaderMismatch`], [`ContentHashMismatch`]; ML-DSA and frame-open
/// verification failures; publish errors.
///
/// [`SessionError`]: crate::SessionError
pub fn accept_record(
    session: &mut Session,
    file: &mut VaultFile,
    rec: &SyncRecord,
    trust: &TrustedKeys<'_>,
    last_seen: impl Fn(u32) -> Option<u64>,
) -> anyhow::Result<Accepted> {
    let header = parse(&rec.frame)?;
    let cert = cert_for(trust, &header.origin_device)?;
    verify_sync_record(rec, &cert.device_vk, &rec.vault_id)?;

    check_vault(session, rec)?;
    let local = local_latest(session, rec.record_id)?;
    check_fresh(seen_revision(local, rec.record_id, last_seen), rec.revision)?;
    check_header_binding(&header, rec)?;

    frame::open(
        &frame_key(session.vk.expose(), &session.vault_id, rec.record_id)?,
        &rec.frame,
    )?;
    write_records(session, file, &rec.frame)?;

    Ok(Accepted {
        record_id: rec.record_id,
        revision: rec.revision,
        origin_device: header.origin_device,
    })
}
