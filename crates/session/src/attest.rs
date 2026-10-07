//! Revision attestations: who wrote a revision, in a form that survives a
//! vault-key rotation.
//!
//! A signature over a sealed frame would die the moment a rotation re-seals
//! it. An attestation signs a digest of the plaintext instead, together with
//! the vault, record, revision and writing device, so it stays valid when the
//! same revision is sealed under a new key. A receiver opens the frame with
//! the vault key, recomputes the digest, and checks the writer's certificate,
//! signature and role before it keeps the frame.

use kdf::frame_key;
use pq::{sync_sign, sync_verify, REVISION_CTX, SYNC_VK_LEN};
use sha2::{Digest, Sha256};

use crate::create::Session;
use crate::error::SessionError;
use crate::revocation::Revocation;
use crate::rotate::write_records;
use crate::sync_import::Accepted;
use crate::sync_msg::frame_parts;
use crate::sync_sig::{DeviceCert, DeviceSignKey};
use container::VaultFile;

const DOMAIN_DIGEST: &[u8] = b"brby/v2/revision-digest";
const DOMAIN_ATTEST: &[u8] = b"brby/v2/revision-attest";

/// Largest frame an attestation accompanies.
pub const MAX_ATTESTED_FRAME: usize =
    frame::HEADER_LEN + frame::MAX_FRAME_PLAINTEXT + frame::CASCADE_OVERHEAD + frame::TAG_LEN;

/// The digest an attestation signs: the vault, the record, the revision, the
/// frame kind and the plaintext, so it cannot be moved to another revision.
#[must_use]
pub fn plain_digest(
    vault_id: &[u8; 16],
    record_id: u32,
    revision: u64,
    kind: u8,
    plaintext: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_DIGEST)
        .chain_update(vault_id)
        .chain_update(record_id.to_be_bytes())
        .chain_update(revision.to_be_bytes())
        .chain_update([kind])
        .chain_update(plaintext)
        .finalize()
        .into()
}

/// A device's signed statement that it wrote one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The vault the revision belongs to.
    pub vault_id: [u8; 16],
    /// The record.
    pub record_id: u32,
    /// The revision.
    pub revision: u64,
    /// The device that wrote and signed it.
    pub origin_device: [u8; 16],
    /// [`plain_digest`] of the revision.
    pub plain_digest: [u8; 32],
    /// Certificate of the writing device.
    pub signer: DeviceCert,
    /// ML-DSA-65 signature over [`Attestation::signed_message`].
    pub signature: Vec<u8>,
}

impl Attestation {
    /// Bytes the writer signs.
    ///
    /// # Errors
    ///
    /// `sync field too long` when a part does not fit a `u16` length.
    pub fn signed_message(&self) -> anyhow::Result<Vec<u8>> {
        frame_parts(&[
            DOMAIN_ATTEST,
            &self.vault_id,
            &self.record_id.to_be_bytes(),
            &self.revision.to_be_bytes(),
            &self.origin_device,
            &self.plain_digest,
            &self.signer.device_id,
            &self.signer.serial.to_be_bytes(),
            &self.signer.client_id,
        ])
    }

    /// Verify the signer's certificate against its account root at `now_ms`,
    /// that the certificate is the writing device's, and the signature.
    ///
    /// # Errors
    ///
    /// `device cert expired`, or `device cert rejected` for every other
    /// failure.
    pub fn verify(&self, root_vk: &[u8; SYNC_VK_LEN], now_ms: u64) -> Result<(), SessionError> {
        self.signer.verify(root_vk, now_ms).map_err(|error| {
            if error.to_string() == "device cert expired" {
                SessionError::CertExpired
            } else {
                SessionError::CertRejected
            }
        })?;
        if self.signer.device_id != self.origin_device {
            return Err(SessionError::CertRejected);
        }
        let message = self
            .signed_message()
            .map_err(|_| SessionError::CertRejected)?;
        sync_verify(
            &self.signer.device_vk,
            REVISION_CTX,
            &message,
            &self.signature,
        )
        .map_err(|_| SessionError::CertRejected)
    }
}

/// One record's winning frame, as an index entry of a frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontierEntry {
    /// The record.
    pub record_id: u32,
    /// Its winning revision.
    pub revision: u64,
    /// The device that wrote it.
    pub origin_device: [u8; 16],
}

/// The winning frame of every record (the vault's own record 0 excluded),
/// sorted by record id: what two devices compare to see what the other lacks.
///
/// # Errors
///
/// `corrupted length` when the frame log does not index.
pub fn frontier(session: &Session) -> anyhow::Result<Vec<FrontierEntry>> {
    let refs = frame::parse_index(session.records.expose())?;
    let mut ids: Vec<u32> = refs
        .iter()
        .filter(|frame| frame.known() && frame.record_id != 0)
        .map(|frame| frame.record_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids
        .into_iter()
        .filter_map(|id| frame::latest(&refs, id))
        .map(|winner| FrontierEntry {
            record_id: winner.record_id,
            revision: winner.revision,
            origin_device: winner.origin_device,
        })
        .collect())
}

/// What two frontiers say each side lacks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reconcile {
    /// Records the remote side has a winning revision of that this side lacks
    /// or holds an older one.
    pub pull: Vec<u32>,
    /// Records this side has a winning revision of that the remote side lacks
    /// or holds an older one.
    pub push: Vec<u32>,
}

/// Compare two frontiers, both sorted by record id. A revision wins by
/// `(revision, origin_device)`, the order that picks the winner everywhere,
/// so both sides compute complementary answers.
#[must_use]
pub fn reconcile(local: &[FrontierEntry], remote: &[FrontierEntry]) -> Reconcile {
    let key = |entry: &FrontierEntry| (entry.revision, entry.origin_device);
    let mut out = Reconcile::default();
    let (mut mine, mut theirs) = (local.iter().peekable(), remote.iter().peekable());
    loop {
        match (mine.peek().copied(), theirs.peek().copied()) {
            (None, None) => break,
            (Some(a), None) => {
                out.push.push(a.record_id);
                mine.next();
            }
            (None, Some(b)) => {
                out.pull.push(b.record_id);
                theirs.next();
            }
            (Some(a), Some(b)) => match a.record_id.cmp(&b.record_id) {
                std::cmp::Ordering::Less => {
                    out.push.push(a.record_id);
                    mine.next();
                }
                std::cmp::Ordering::Greater => {
                    out.pull.push(b.record_id);
                    theirs.next();
                }
                std::cmp::Ordering::Equal => {
                    match key(a).cmp(&key(b)) {
                        std::cmp::Ordering::Less => out.pull.push(a.record_id),
                        std::cmp::Ordering::Greater => out.push.push(a.record_id),
                        std::cmp::Ordering::Equal => {}
                    }
                    mine.next();
                    theirs.next();
                }
            },
        }
    }
    out
}

/// The sealed winning frame of `record_id`.
///
/// # Errors
///
/// `unknown record` when no frame carries the id.
pub fn latest_frame(session: &Session, record_id: u32) -> anyhow::Result<Vec<u8>> {
    let refs = frame::parse_index(session.records.expose())?;
    let winner =
        frame::latest(&refs, record_id).ok_or_else(|| anyhow::anyhow!("unknown record"))?;
    Ok(frame::frame_at(session.records.expose(), winner)?.to_vec())
}

/// Attest the winning frame of `record_id`, which this device must have
/// written. Returns the attestation and the frame it describes.
///
/// # Errors
///
/// [`SessionError::NotYours`] when another device wrote the frame;
/// [`SessionError::ZeroOrigin`] for a frame no certified device wrote;
/// `unknown record`, frame-opening and signing errors.
pub fn attest_latest(
    session: &Session,
    key: &DeviceSignKey,
    cert: &DeviceCert,
    record_id: u32,
) -> anyhow::Result<(Attestation, Vec<u8>)> {
    let frame_bytes = latest_frame(session, record_id)?;
    let header = frame::parse(&frame_bytes)?;
    if header.origin_device == [0u8; 16] {
        return Err(SessionError::ZeroOrigin.into());
    }
    if header.origin_device != cert.device_id {
        return Err(SessionError::NotYours.into());
    }
    let plaintext = frame::open(
        &frame_key(session.vk.expose(), &session.vault_id, record_id)?,
        &frame_bytes,
    )?;
    let digest = plain_digest(
        &session.vault_id,
        record_id,
        header.revision,
        header.kind,
        plaintext.expose(),
    );
    let unsigned = Attestation {
        vault_id: session.vault_id,
        record_id,
        revision: header.revision,
        origin_device: header.origin_device,
        plain_digest: digest,
        signer: cert.clone(),
        signature: Vec::new(),
    };
    let signature = sync_sign(key.seed(), REVISION_CTX, &unsigned.signed_message()?)
        .map_err(|_| SessionError::SignFailed)?;
    Ok((
        Attestation {
            signature,
            ..unsigned
        },
        frame_bytes,
    ))
}

/// Who may sign: the accounts of the vault and the devices revoked from them.
#[derive(Clone, Copy, Debug)]
pub struct Trust<'a, 'b> {
    /// The accounts a signer may belong to.
    pub accounts: &'a [TrustedAccount<'b>],
    /// Devices whose signatures are no longer accepted.
    pub revoked: &'a [Revocation],
}

/// An account whose members' devices may attest revisions here.
#[derive(Clone, Copy, Debug)]
pub struct TrustedAccount<'a> {
    /// The account id its certificates carry.
    pub client_id: [u8; 64],
    /// The root key those certificates chain to.
    pub root_vk: &'a [u8; SYNC_VK_LEN],
    /// Whether the account may write; a reader's attestations are refused.
    pub can_write: bool,
}

fn check_shape(
    session: &Session,
    header: &frame::Header,
    attestation: &Attestation,
) -> Result<(), SessionError> {
    if attestation.vault_id != session.vault_id {
        return Err(SessionError::VaultMismatch);
    }
    if header.origin_device == [0u8; 16] {
        return Err(SessionError::ZeroOrigin);
    }
    let shape = header.record_id == attestation.record_id
        && header.revision == attestation.revision
        && header.origin_device == attestation.origin_device
        && attestation.record_id != 0
        && matches!(header.kind, frame::KIND_REVISION | frame::KIND_TOMBSTONE)
        && matches!(header.alg, frame::ALG_CASCADE | frame::ALG_AEGIS256);
    if shape {
        Ok(())
    } else {
        Err(SessionError::HeaderMismatch)
    }
}

/// The checks that need no decryption: the shape of the frame against the
/// attestation, the vault, the writer's account and role, the certificate and
/// the signature.
fn check_signed(
    session: &Session,
    frame_bytes: &[u8],
    attestation: &Attestation,
    trust: &Trust<'_, '_>,
    now_ms: u64,
) -> anyhow::Result<frame::Header> {
    if frame_bytes.len() > MAX_ATTESTED_FRAME {
        return Err(SessionError::HeaderMismatch.into());
    }
    let header = frame::parse(frame_bytes)?;
    check_shape(session, &header, attestation)?;
    let account = trust
        .accounts
        .iter()
        .find(|account| account.client_id == attestation.signer.client_id)
        .ok_or(SessionError::DeviceNotTrusted)?;
    if !account.can_write {
        return Err(SessionError::NotAWriter.into());
    }
    attestation.verify(account.root_vk, now_ms)?;
    if trust
        .revoked
        .iter()
        .any(|revocation| revocation.covers(&attestation.signer))
    {
        return Err(SessionError::CertRejected.into());
    }
    Ok(header)
}

/// Open the frame with the vault key: its plaintext digest must equal the
/// signed one.
fn check_plaintext(
    session: &Session,
    header: &frame::Header,
    frame_bytes: &[u8],
    attestation: &Attestation,
) -> anyhow::Result<()> {
    let plaintext = frame::open(
        &frame_key(
            session.vk.expose(),
            &session.vault_id,
            attestation.record_id,
        )?,
        frame_bytes,
    )?;
    let digest = plain_digest(
        &session.vault_id,
        attestation.record_id,
        attestation.revision,
        header.kind,
        plaintext.expose(),
    );
    if secret::ct_eq_32(&digest, &attestation.plain_digest) {
        Ok(())
    } else {
        Err(SessionError::AttestationMismatch.into())
    }
}

/// Check that every record in `session` was written by one of `accounts`.
///
/// Each winning revision needs an attestation for exactly that revision and
/// device, with a valid certificate and signature, over the plaintext the
/// frame holds. Returns the attestations that matched, one per record.
///
/// This is what a device runs on a whole vault file it did not build, so a
/// member holding the vault key cannot slip in a record no writer signed.
///
/// # Errors
///
/// [`SessionError::AttestationMismatch`] for a record without a matching
/// attestation, and the errors of [`accept_revision`] for one that does not
/// verify.
pub fn verify_snapshot(
    session: &Session,
    attestations: &[Attestation],
    trust: &Trust<'_, '_>,
    now_ms: u64,
) -> anyhow::Result<Vec<Attestation>> {
    let refs = frame::parse_index(session.records.expose())?;
    if frame::latest(&refs, 0).is_some() {
        // No writer attests the vault's own record, so a shared vault has none.
        return Err(SessionError::AttestationMismatch.into());
    }
    frontier(session)?
        .into_iter()
        .map(|entry| {
            let attestation = attestations
                .iter()
                .find(|held| {
                    held.record_id == entry.record_id
                        && held.revision == entry.revision
                        && held.origin_device == entry.origin_device
                })
                .ok_or(SessionError::AttestationMismatch)?;
            let frame_bytes = latest_frame(session, entry.record_id)?;
            let header = check_signed(session, &frame_bytes, attestation, trust, now_ms)?;
            check_plaintext(session, &header, &frame_bytes, attestation)?;
            Ok(attestation.clone())
        })
        .collect()
}

/// Keep a frame a peer sent, if its attestation holds.
///
/// Cheapest checks first, and nothing is decrypted before the signature
/// verifies: the shape of the frame against the attestation, the vault, the
/// writer's account and role, the certificate and signature, then freshness.
/// A revision wins over the local one when `(revision, origin_device)` is
/// greater, the same order that picks the winner, so concurrent edits settle
/// on every device. Finally the frame is opened with the vault key and its
/// plaintext digest must equal the signed one. On error `file` and `session`
/// are unchanged.
///
/// # Errors
///
/// [`SessionError`]: `VaultMismatch`, `ZeroOrigin`, `HeaderMismatch`,
/// `DeviceNotTrusted` (an account the vault does not list), `NotAWriter`,
/// `CertRejected` (also for a revoked signer), `CertExpired`, `StaleRevision`, `AttestationMismatch`;
/// frame-opening and publish errors.
pub fn accept_revision(
    session: &mut Session,
    file: &mut VaultFile,
    frame_bytes: &[u8],
    attestation: &Attestation,
    trust: &Trust<'_, '_>,
    now_ms: u64,
    last_seen: impl Fn(u32) -> Option<u64>,
) -> anyhow::Result<Accepted> {
    let header = check_signed(session, frame_bytes, attestation, trust, now_ms)?;
    let record_id = attestation.record_id;
    let refs = frame::parse_index(session.records.expose())?;
    let incoming = (attestation.revision, header.origin_device);
    let local =
        frame::latest(&refs, record_id).map(|winner| (winner.revision, winner.origin_device));
    let behind_seen = last_seen(record_id).is_some_and(|seen| attestation.revision < seen);
    if behind_seen || local.is_some_and(|winner| incoming <= winner) {
        return Err(SessionError::StaleRevision.into());
    }
    check_plaintext(session, &header, frame_bytes, attestation)?;
    write_records(session, file, frame_bytes)?;
    Ok(Accepted {
        record_id,
        revision: attestation.revision,
        origin_device: header.origin_device,
    })
}
