//! Quantum-safe `.zpbackup` (`ZPBK` v1) bundle creation and export.
//!
//! Packs the personal `vault.brby` together with all ready shared vaults
//! (`vault.brby`, `members.log`, and `attest.store`) into a Cascade `0xA005`
//! authenticated bundle committed by a whole-file `HMAC-SHA256` tag checked
//! before decryption. Device-bound private material (`device.key`, `sync.id`)
//! is never read or included.

use std::collections::BTreeSet;
use std::path::Path;

use frame::{ALG_CASCADE, FrameMeta, KIND_REVISION, encode_frames, seal};
use hmac::{Hmac, KeyInit, Mac};
use memberlog::ENTRY_WIRE_LEN;
use secret::Secret;
use session::{Attestation, Factor, Session, VaultFile, wrap_directory};
use sha2::Sha256;
use syncwire::encode_snapshot;
use zeroize::Zeroizing;

use crate::shared::{is_pending, load_attest_any, load_log_any};
use crate::shared_ref::list_shared_refs;
use crate::{now_ms, shared_paths_for, write_atomic};

type HmacSha256 = Hmac<Sha256>;

/// Magic prefix of a `ZebraPass` backup bundle.
pub const BACKUP_MAGIC: [u8; 4] = *b"ZPBK";

/// Current backup bundle wire version.
pub const BACKUP_VERSION: u16 = 1;

/// Fixed byte length of the `ZPBK` static header.
pub const BACKUP_HEADER_LEN: usize = 70;

/// Byte length of the whole-bundle HMAC-SHA256 tail commitment.
pub const BACKUP_COMMIT_LEN: usize = 32;

/// Maximum personal vault size inside a backup (64 MiB).
pub const MAX_BACKUP_VAULT: usize = 64 << 20;

/// Maximum encrypted auxiliary section size inside a backup (128 MiB).
pub const MAX_BACKUP_AUX: usize = 128 << 20;

/// Maximum number of shared vaults packed in one backup.
pub const MAX_BACKUP_SHARED: usize = 64;

/// Maximum total `.zpbackup` file size accepted before allocation (256 MiB).
pub const MAX_BACKUP_FILE: usize = 256 << 20;

const AUX_CHUNK_BYTES: usize = 512 * 1024;

/// A verified shared vault unpacked from a `.zpbackup` bundle.
#[derive(Debug)]
pub struct RestoredShared {
    /// Shared vault identifier.
    pub vault_id: [u8; 16],
    /// Cryptographically verified membership log entries from genesis.
    pub entries: Vec<memberlog::Entry>,
    /// Verified shared vault container.
    pub vault_file: VaultFile,
    /// Writer attestations matching the shared vault records.
    pub attestations: Vec<Attestation>,
}

/// Legacy single-vault (`BRBY`) backup contents.
#[derive(Debug)]
pub struct LegacyBackup {
    /// Decoded personal container.
    pub file: VaultFile,
    /// Unlocked session for the personal container.
    pub session: Session,
}

/// Full `ZPBK` v1 backup contents (personal + all ready shared vaults).
#[derive(Debug)]
pub struct BundleBackup {
    /// Bundle creation timestamp in unix milliseconds.
    pub created_at_ms: u64,
    /// Saved personal vault display name.
    pub name: String,
    /// Decoded personal container.
    pub file: VaultFile,
    /// Unlocked session for the personal container.
    pub session: Session,
    /// Ready shared vaults recovered from the encrypted auxiliary section.
    pub shared: Vec<RestoredShared>,
}

/// Verified backup payload returned by [`crate::open_backup_bundle`].
#[derive(Debug)]
pub enum BackupContents {
    /// Raw `BRBY` vault container backup.
    LegacyVault(Box<LegacyBackup>),
    /// Full `ZPBK` v1 personal + shared vault bundle.
    Bundle(Box<BundleBackup>),
}

pub fn auth_failed() -> anyhow::Error {
    anyhow::anyhow!("backup authentication failed")
}

pub fn malformed() -> anyhow::Error {
    anyhow::anyhow!("corrupted backup length")
}

pub fn mac_backup(key: &[u8; 32], data: &[u8]) -> anyhow::Result<[u8; 32]> {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return Err(malformed());
    };
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

fn has_portable_wrap(file: &VaultFile) -> anyhow::Result<bool> {
    let dir = wrap_directory(file)?;
    Ok(dir
        .factors
        .iter()
        .any(|factor| matches!(factor, Factor::Recovery | Factor::Password { .. })))
}

fn encode_aux_plaintext(
    base: &Path,
    session: &Session,
    name: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let refs = list_shared_refs(session);
    let mut packed: Vec<([u8; 16], Vec<u8>, Vec<u8>)> = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for reference in refs {
        if !seen_ids.insert(reference.vault_id) || is_pending(base, &reference) {
            continue;
        }
        if packed.len() >= MAX_BACKUP_SHARED {
            anyhow::bail!("too many shared vaults for backup");
        }
        let paths = shared_paths_for(base, &reference.vault_id);
        let meta = std::fs::metadata(&paths.vault_file)?;
        if meta.len() > MAX_BACKUP_VAULT as u64 {
            anyhow::bail!("shared vault too large for backup");
        }
        let vault_bytes = std::fs::read(&paths.vault_file)?;
        let log = load_log_any(&paths, &reference)?;
        let mut log_wire = Vec::with_capacity(log.entries().len() * ENTRY_WIRE_LEN);
        for entry in log.entries() {
            log_wire.extend_from_slice(&entry.encode()?);
        }
        let attest = load_attest_any(&paths, &reference)?;
        let attestations: Vec<Attestation> = attest.iter().cloned().collect();
        let snap_wire = encode_snapshot(&vault_bytes, &attestations)?;
        packed.push((reference.vault_id, log_wire, snap_wire));
    }

    let name_bytes = name.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).map_err(|_| malformed())?;
    let count = u16::try_from(packed.len()).map_err(|_| malformed())?;
    let total = 4
        + name_bytes.len()
        + packed
            .iter()
            .map(|(_, l, s)| 16 + 4 + l.len() + 4 + s.len())
            .sum::<usize>();
    let mut plain = Zeroizing::new(Vec::with_capacity(total));
    plain.extend_from_slice(&name_len.to_be_bytes());
    plain.extend_from_slice(name_bytes);
    plain.extend_from_slice(&count.to_be_bytes());
    for (vault_id, log_wire, snap_wire) in packed {
        let log_len = u32::try_from(log_wire.len()).map_err(|_| malformed())?;
        let snap_len = u32::try_from(snap_wire.len()).map_err(|_| malformed())?;
        plain.extend_from_slice(&vault_id);
        plain.extend_from_slice(&log_len.to_be_bytes());
        plain.extend_from_slice(&log_wire);
        plain.extend_from_slice(&snap_len.to_be_bytes());
        plain.extend_from_slice(&snap_wire);
    }
    Ok(plain)
}

fn seal_aux_chunks(
    k_seal: &Secret<[u8; 32]>,
    created_at_ms: u64,
    plain: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let chunks: Vec<&[u8]> = if plain.is_empty() {
        vec![&[]]
    } else {
        plain.chunks(AUX_CHUNK_BYTES).collect()
    };
    let total = u64::try_from(chunks.len()).map_err(|_| malformed())?;
    let mut frames = Vec::new();
    for (idx, chunk) in chunks.into_iter().enumerate() {
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: u32::try_from(idx).map_err(|_| malformed())?,
            revision: total,
            origin_device: [0u8; 16],
            timestamp_ms: created_at_ms,
            alg: ALG_CASCADE,
        };
        frames.extend_from_slice(&seal(k_seal, &meta, chunk)?);
    }
    let encoded = encode_frames(&frames)?;
    if encoded.len() > MAX_BACKUP_AUX {
        anyhow::bail!("backup auxiliary section too large");
    }
    Ok(encoded)
}

/// Build an authenticated, post-quantum encrypted `.zpbackup` (`ZPBK` v1)
/// bundle from an unlocked personal session and all ready shared vaults.
///
/// Fails closed if the personal container lacks a portable wrap (recovery
/// phrase or human password). Never reads `device.key` or `sync.id`.
///
/// # Errors
///
/// Missing portable wrap, OS RNG failure, key-derivation or sealing errors.
pub fn build_backup_bundle(
    base: &Path,
    session: &Session,
    file: &VaultFile,
    name: &str,
) -> anyhow::Result<Vec<u8>> {
    if !has_portable_wrap(file)? {
        anyhow::bail!("cannot back up a vault without a recovery phrase or password factor");
    }
    let personal_bytes = file.as_bytes();
    if personal_bytes.len() > MAX_BACKUP_VAULT {
        anyhow::bail!("vault too large for backup");
    }
    let personal_len = u32::try_from(personal_bytes.len()).map_err(|_| malformed())?;
    let created_at_ms = now_ms();
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|_| anyhow::anyhow!("os entropy failed"))?;

    let mut header = Vec::with_capacity(BACKUP_HEADER_LEN);
    header.extend_from_slice(&BACKUP_MAGIC);
    header.extend_from_slice(&BACKUP_VERSION.to_be_bytes());
    header.extend_from_slice(&created_at_ms.to_be_bytes());
    header.extend_from_slice(session.vault_id());
    header.extend_from_slice(&session.generation().to_be_bytes());
    header.extend_from_slice(&salt);

    let (k_seal, k_commit) =
        kdf::backup_keys(session.reopen_key().expose(), session.vault_id(), &header)?;
    let aux_plain = encode_aux_plaintext(base, session, name)?;
    let aux_section = seal_aux_chunks(&k_seal, created_at_ms, &aux_plain)?;
    let aux_len = u32::try_from(aux_section.len()).map_err(|_| malformed())?;

    let total_len =
        BACKUP_HEADER_LEN + 4 + personal_bytes.len() + 4 + aux_section.len() + BACKUP_COMMIT_LEN;
    if total_len > MAX_BACKUP_FILE {
        anyhow::bail!("backup exceeds maximum file size");
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(&personal_len.to_be_bytes());
    out.extend_from_slice(personal_bytes);
    out.extend_from_slice(&aux_len.to_be_bytes());
    out.extend_from_slice(&aux_section);
    let tag = mac_backup(k_commit.expose(), &out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Write a `.zpbackup` bundle atomically (`0600`) to `dest`.
///
/// # Errors
///
/// Backup creation or atomic write failure.
pub fn export_backup_file(
    dest: &Path,
    base: &Path,
    session: &Session,
    file: &VaultFile,
    name: &str,
) -> anyhow::Result<()> {
    let bytes = build_backup_bundle(base, session, file, name)?;
    write_atomic(dest, &bytes)
}
