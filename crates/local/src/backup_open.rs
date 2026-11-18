//! Verification and restoration of `.zpbackup` (`ZPBK` v1) bundles and
//! legacy `BRBY` vault files.

use std::path::Path;

use frame::{ALG_CASCADE, decode_frames, open, parse, spans};
use memberlog::{ENTRY_WIRE_LEN, Entry, MAX_ENTRIES, MemberLog};
use secret::Secret;
use session::{Seen, Session, UnlockCreds, VaultFile, check_seen, unlock, unlock_with_key};
use syncwire::decode_snapshot;
use zeroize::Zeroizing;

use crate::backup::{
    BACKUP_COMMIT_LEN, BACKUP_HEADER_LEN, BACKUP_MAGIC, BACKUP_VERSION, BackupContents,
    BundleBackup, LegacyBackup, MAX_BACKUP_AUX, MAX_BACKUP_FILE, MAX_BACKUP_SHARED,
    MAX_BACKUP_VAULT, RestoredShared, auth_failed, mac_backup, malformed,
};
use crate::meta::load_local_meta;
use crate::shared::{adopt_shared_file, file_keys};
use crate::shared_files::{SharedState, save_member_log};
use crate::shared_ref::{SharedRef, list_shared_refs};
use crate::{SyncIdentity, shared_paths_for};

const MAX_SHARED_LOG_BYTES: usize = MAX_ENTRIES * ENTRY_WIRE_LEN;
const MAX_SHARED_SNAPSHOT_BYTES: usize = 64 << 20;

fn read_u16_be(src: &[u8], off: usize) -> anyhow::Result<u16> {
    let bytes: [u8; 2] = src
        .get(off..off + 2)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32_be(src: &[u8], off: usize) -> anyhow::Result<u32> {
    let bytes: [u8; 4] = src
        .get(off..off + 4)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64_be(src: &[u8], off: usize) -> anyhow::Result<u64> {
    let bytes: [u8; 8] = src
        .get(off..off + 8)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(u64::from_be_bytes(bytes))
}

fn open_aux_chunks(
    k_seal: &Secret<[u8; 32]>,
    aux_bytes: &[u8],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let frames = decode_frames(aux_bytes)?;
    let frame_spans = spans(&frames)?;
    if frame_spans.is_empty() {
        return Err(auth_failed());
    }
    let expected_total = u64::try_from(frame_spans.len()).map_err(|_| auth_failed())?;
    let mut out = Zeroizing::new(Vec::new());
    for (idx, (start, len)) in frame_spans.into_iter().enumerate() {
        let end = start.checked_add(len).ok_or_else(auth_failed)?;
        let raw = frames.get(start..end).ok_or_else(auth_failed)?;
        let meta = parse(raw).map_err(|_| auth_failed())?;
        if meta.alg != ALG_CASCADE
            || u64::from(meta.record_id) != u64::try_from(idx).map_err(|_| auth_failed())?
            || meta.revision != expected_total
        {
            return Err(auth_failed());
        }
        let pt = open(k_seal, raw).map_err(|_| auth_failed())?;
        out.extend_from_slice(pt.expose());
    }
    Ok(out)
}

fn decode_aux_payload(
    plain: &[u8],
    refs: &[SharedRef],
) -> anyhow::Result<(String, Vec<RestoredShared>)> {
    let name_len = usize::from(read_u16_be(plain, 0)?);
    let mut pos = 2usize;
    let name_end = pos.checked_add(name_len).ok_or_else(malformed)?;
    let name = std::str::from_utf8(plain.get(pos..name_end).ok_or_else(malformed)?)
        .map_err(|_| malformed())?
        .to_owned();
    pos = name_end;

    let count = usize::from(read_u16_be(plain, pos)?);
    pos = pos.checked_add(2).ok_or_else(malformed)?;
    if count > MAX_BACKUP_SHARED {
        return Err(malformed());
    }
    let mut shared = Vec::with_capacity(count);
    for _ in 0..count {
        let id_end = pos.checked_add(16).ok_or_else(malformed)?;
        let vault_id: [u8; 16] = plain
            .get(pos..id_end)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?;
        pos = id_end;

        let log_len = usize::try_from(read_u32_be(plain, pos)?).map_err(|_| malformed())?;
        pos = pos.checked_add(4).ok_or_else(malformed)?;
        if log_len > MAX_SHARED_LOG_BYTES || !log_len.is_multiple_of(ENTRY_WIRE_LEN) {
            return Err(malformed());
        }
        let log_end = pos.checked_add(log_len).ok_or_else(malformed)?;
        let log_slice = plain.get(pos..log_end).ok_or_else(malformed)?;
        pos = log_end;

        let snap_len = usize::try_from(read_u32_be(plain, pos)?).map_err(|_| malformed())?;
        pos = pos.checked_add(4).ok_or_else(malformed)?;
        if snap_len > MAX_SHARED_SNAPSHOT_BYTES {
            return Err(malformed());
        }
        let snap_end = pos.checked_add(snap_len).ok_or_else(malformed)?;
        let snap_slice = plain.get(pos..snap_end).ok_or_else(malformed)?;
        pos = snap_end;

        let reference = refs
            .iter()
            .find(|r| r.vault_id == vault_id)
            .ok_or_else(auth_failed)?;
        let entries = log_slice
            .as_chunks::<ENTRY_WIRE_LEN>()
            .0
            .iter()
            .map(|chunk| Entry::decode(chunk.as_slice()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        MemberLog::from_entries(vault_id, &entries, &reference.anchor)?;
        let (file_bytes, attestations) = decode_snapshot(snap_slice.to_vec())?;
        shared.push(RestoredShared {
            vault_id,
            entries,
            vault_file: VaultFile::new(file_bytes),
            attestations,
        });
    }
    if pos != plain.len() {
        return Err(malformed());
    }
    Ok((name, shared))
}

struct BackupSections<'a> {
    header_bytes: &'a [u8],
    created_at_ms: u64,
    header_vault_id: [u8; 16],
    header_generation: u64,
    personal_bytes: &'a [u8],
    aux_bytes: &'a [u8],
    prefix: &'a [u8],
    tail: [u8; 32],
}

fn split_backup_sections(bytes: &[u8]) -> anyhow::Result<BackupSections<'_>> {
    if !bytes.starts_with(&BACKUP_MAGIC)
        || bytes.len() < BACKUP_HEADER_LEN + 4 + 4 + BACKUP_COMMIT_LEN
    {
        return Err(malformed());
    }
    let header_bytes = bytes.get(..BACKUP_HEADER_LEN).ok_or_else(malformed)?;
    if read_u16_be(header_bytes, 4)? != BACKUP_VERSION {
        anyhow::bail!("unsupported backup version");
    }
    let created_at_ms = read_u64_be(header_bytes, 6)?;
    let header_vault_id: [u8; 16] = header_bytes
        .get(14..30)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    let header_generation = read_u64_be(header_bytes, 30)?;

    let personal_len =
        usize::try_from(read_u32_be(bytes, BACKUP_HEADER_LEN)?).map_err(|_| malformed())?;
    if personal_len > MAX_BACKUP_VAULT {
        return Err(malformed());
    }
    let personal_start = BACKUP_HEADER_LEN + 4;
    let personal_end = personal_start
        .checked_add(personal_len)
        .ok_or_else(malformed)?;
    let personal_bytes = bytes
        .get(personal_start..personal_end)
        .ok_or_else(malformed)?;

    let aux_len = usize::try_from(read_u32_be(bytes, personal_end)?).map_err(|_| malformed())?;
    if aux_len > MAX_BACKUP_AUX {
        return Err(malformed());
    }
    let aux_start = personal_end.checked_add(4).ok_or_else(malformed)?;
    let aux_end = aux_start.checked_add(aux_len).ok_or_else(malformed)?;
    let expected_total = aux_end
        .checked_add(BACKUP_COMMIT_LEN)
        .ok_or_else(malformed)?;
    if expected_total != bytes.len() {
        return Err(malformed());
    }
    let prefix = bytes.get(..aux_end).ok_or_else(malformed)?;
    let tail: [u8; 32] = bytes
        .get(aux_end..expected_total)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    let aux_bytes = bytes.get(aux_start..aux_end).ok_or_else(malformed)?;
    Ok(BackupSections {
        header_bytes,
        created_at_ms,
        header_vault_id,
        header_generation,
        personal_bytes,
        aux_bytes,
        prefix,
        tail,
    })
}

fn verify_backup_bundle(
    sec: &BackupSections<'_>,
    file: VaultFile,
    session: Session,
) -> anyhow::Result<BackupContents> {
    if !secret::ct_eq(session.vault_id(), &sec.header_vault_id)
        || session.generation() != sec.header_generation
    {
        return Err(auth_failed());
    }
    let (k_seal, k_commit) = kdf::backup_keys(
        session.reopen_key().expose(),
        session.vault_id(),
        sec.header_bytes,
    )?;
    let actual_tag = mac_backup(k_commit.expose(), sec.prefix)?;
    if !secret::ct_eq_32(&actual_tag, &sec.tail) {
        return Err(auth_failed());
    }
    let aux_plain = open_aux_chunks(&k_seal, sec.aux_bytes)?;
    let refs = list_shared_refs(&session);
    let (name, shared) = decode_aux_payload(&aux_plain, &refs)?;
    Ok(BackupContents::Bundle(Box::new(BundleBackup {
        created_at_ms: sec.created_at_ms,
        name,
        file,
        session,
        shared,
    })))
}

/// Verify and unlock either a legacy `BRBY` file or a `ZPBK` v1 backup bundle.
///
/// Checks the whole-bundle `HMAC-SHA256` commitment in constant time BEFORE
/// decrypting any auxiliary shared-vault frames.
///
/// # Errors
///
/// `backup authentication failed` on tamper or wrong credentials; container,
/// limit, or member-log verification failures.
pub fn open_backup_bundle(bytes: &[u8], creds: &UnlockCreds<'_>) -> anyhow::Result<BackupContents> {
    if bytes.len() > MAX_BACKUP_FILE {
        return Err(malformed());
    }
    if bytes.starts_with(b"BRBY") {
        let file = VaultFile::new(bytes.to_vec());
        let session = unlock(&file, creds, None)?;
        return Ok(BackupContents::LegacyVault(Box::new(LegacyBackup {
            file,
            session,
        })));
    }
    let sec = split_backup_sections(bytes)?;
    let file = VaultFile::new(sec.personal_bytes.to_vec());
    let session = unlock(&file, creds, None).map_err(|_| auth_failed())?;
    verify_backup_bundle(&sec, file, session)
}

/// Verify and open a `ZPBK` v1 backup bundle (or `BRBY` file) using the
/// already-unlocked personal vault key `vk` (for live cloud-backup pulls).
///
/// # Errors
///
/// `backup authentication failed` on tamper or mismatched vault key.
pub fn open_backup_with_vk(
    bytes: &[u8],
    vk: &Secret<[u8; 32]>,
    origin_device: [u8; 16],
) -> anyhow::Result<BackupContents> {
    if bytes.len() > MAX_BACKUP_FILE {
        return Err(malformed());
    }
    if bytes.starts_with(b"BRBY") {
        let file = VaultFile::new(bytes.to_vec());
        let session = unlock_with_key(&file, vk, origin_device).map_err(|_| auth_failed())?;
        return Ok(BackupContents::LegacyVault(Box::new(LegacyBackup {
            file,
            session,
        })));
    }
    let sec = split_backup_sections(bytes)?;
    let file = VaultFile::new(sec.personal_bytes.to_vec());
    let session = unlock_with_key(&file, vk, origin_device).map_err(|_| auth_failed())?;
    verify_backup_bundle(&sec, file, session)
}

/// Restore unpacked shared vaults from a verified `ZPBK` bundle into `base`,
/// enforcing rollback checks unless `allow_rollback` is set by an explicit
/// phrase-authenticated restore.
///
/// # Errors
///
/// Missing `SharedRef`, rollback/conflict when `!allow_rollback`, member-log
/// or attestation failure, or storage errors.
pub fn restore_shared_entries(
    base: &Path,
    identity: &SyncIdentity,
    session: &Session,
    entries: &[RestoredShared],
    allow_rollback: bool,
) -> anyhow::Result<usize> {
    let refs = list_shared_refs(session);
    let mut restored = 0usize;
    for item in entries {
        let Some(reference) = refs.iter().find(|r| r.vault_id == item.vault_id) else {
            anyhow::bail!("shared reference missing for backup entry");
        };
        let paths = shared_paths_for(base, &reference.vault_id);
        if !allow_rollback && paths.vault_file.is_file() {
            let existing = VaultFile::new(std::fs::read(&paths.vault_file)?);
            let parsed = existing.parse()?;
            let incoming = item.vault_file.parse()?;
            if incoming.generation < parsed.generation {
                anyhow::bail!("shared vault rollback rejected");
            }
            if incoming.generation == parsed.generation
                && !secret::ct_eq(&parsed.commit, &incoming.commit)
            {
                anyhow::bail!("shared vault conflict rejected");
            }
            let opened = unlock(
                &item.vault_file,
                &UnlockCreds::master(reference.seed.expose()),
                None,
            )?;
            if let Ok(meta) = load_local_meta(&paths.local_meta, &opened.local_meta_key()?) {
                let seen = meta.seen.map(|c| Seen {
                    generation: c.generation,
                    commit_tag: c.commit_tag,
                });
                check_seen(&opened, seen)?;
            }
        }
        let log = MemberLog::from_entries(reference.vault_id, &item.entries, &reference.anchor)?;
        let keys = file_keys(&reference.seed, &reference.vault_id)?;
        save_member_log(&paths.members_log(), &keys.log, &log)?;
        if allow_rollback || !paths.shared_state().is_file() {
            SharedState::default().save(&paths.shared_state(), &keys.state)?;
        }
        adopt_shared_file(
            base,
            reference,
            item.vault_file.clone(),
            &item.attestations,
            identity,
        )?;
        restored += 1;
    }
    Ok(restored)
}
