//! Snapshot record merging (preserving local tombstone deletions), local
//! device-wrap preservation, and `last_seen` synchronization helpers.

use std::path::Path;
use std::sync::Arc;

use local::{
    SharedVault, SyncIdentity, decode_personal_head, load_personal_entries, open_personal_rekey,
    open_shared_rekey, read_member_log, save_personal_entries, seed_matches_log, shared_paths_for,
};
use memberlog::{Entry, MemberLog};
use secret::Secret;
use session::{Session, VaultFile, accept_peer_frame_seen, check_seen, unlock_with_key};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
use zsync::{DecryptedSnapshot, wraps_tag};

use crate::vault::Vault;
use crate::vault::device;
use crate::vault::shared::{SharedItem, Status};

pub(super) fn merge_local_records_into(
    old_sess: &Session,
    new_sess: &mut Session,
    new_file: &mut VaultFile,
) -> bool {
    let mut merged = false;
    let remote_frontier = session::frontier(new_sess).unwrap_or_default();
    for local_entry in session::frontier(old_sess).unwrap_or_default() {
        let id = local_entry.record_id;
        let local_key = (local_entry.revision, local_entry.origin_device);
        let remote_key = remote_frontier
            .iter()
            .find(|r| r.record_id == id)
            .map(|r| (r.revision, r.origin_device));
        let keep_local = remote_key.is_none_or(|rk| local_key > rk);
        if !keep_local {
            continue;
        }
        let Ok(raw) = session::latest_frame(old_sess, id) else {
            continue;
        };
        let Ok(hdr) = frame::parse(&raw) else {
            continue;
        };
        if session::accept_peer_frame(new_sess, new_file, &raw).is_ok() {
            merged = true;
            continue;
        }
        if hdr.kind == frame::KIND_TOMBSTONE {
            if remote_key.is_some() && session::delete_record(new_sess, new_file, id).is_ok() {
                merged = true;
            }
        } else if let Ok(doc) = session::open_record(old_sess, id)
            && session::write_record(new_sess, new_file, Some(id), &doc).is_ok()
        {
            merged = true;
        }
    }
    merged
}

pub(super) fn preserve_local_chip_wrap(
    old_vault: &Vault,
    identity: &SyncIdentity,
    new_session: &mut Session,
    new_file: &mut VaultFile,
) -> bool {
    let Some(owned) = device::owned_id(&old_vault.paths) else {
        return false;
    };
    if identity
        .devices()
        .first()
        .is_some_and(|own| identity.revocations().is_revoked(own))
    {
        return false;
    }
    let already_present = session::wrap_directory(new_file).is_ok_and(|dir| {
        dir.factors
            .iter()
            .any(|f| matches!(f, session::Factor::Chip(c) if c.publics.id == owned))
    });
    if already_present {
        return false;
    }
    let local_publics = session::wrap_directory(&old_vault.file)
        .ok()
        .and_then(|dir| {
            dir.factors.into_iter().find_map(|f| match f {
                session::Factor::Chip(c) if c.publics.id == owned => Some(c.publics),
                session::Factor::Chip(_)
                | session::Factor::Recovery
                | session::Factor::Password { .. }
                | session::Factor::Prf { .. } => None,
            })
        });
    local_publics.is_some_and(|pubs| session::add_chip_unlock(new_session, new_file, &pubs).is_ok())
}

pub(super) fn sync_session_revisions_to_identity(session: &Session, identity: &mut SyncIdentity) {
    for entry in session::frontier(session).unwrap_or_default() {
        let _ = identity
            .last_seen_mut()
            .note(entry.record_id, entry.revision);
    }
}

pub(super) type SharedRekeySlice<'a> = &'a [(u64, [u8; 16], Zeroizing<Vec<u8>>)];

pub(super) enum SeedAdvance {
    None,
    Removed,
    Rotated(Secret<[u8; 64]>, u32),
}

pub(super) fn unlock_snapshot_candidate(
    file: &VaultFile,
    current_vk: &Secret<[u8; 32]>,
    identity: &SyncIdentity,
    head_vid: &[u8; 16],
    adopted_vk: Option<&Secret<[u8; 32]>>,
    rekeys: &[(u64, Zeroizing<Vec<u8>>)],
) -> Option<(Session, bool)> {
    let dev_id = identity.device_id()?;
    if let Ok(sess) = unlock_with_key(file, current_vk, dev_id) {
        return Some((sess, false));
    }
    if let Some(vk_new) = adopted_vk
        && let Ok(sess) = unlock_with_key(file, vk_new, dev_id)
    {
        return Some((sess, true));
    }
    for (rgen, blob) in rekeys {
        if let Ok(vk_new) =
            open_personal_rekey(identity.share_keys(), &dev_id, head_vid, *rgen, blob)
            && let Ok(sess) = unlock_with_key(file, &vk_new, dev_id)
        {
            return Some((sess, true));
        }
    }
    None
}

pub(super) fn evaluate_shared_seed_advance(
    base: &Path,
    item: &SharedItem,
    identity: &SyncIdentity,
    entries: &[Entry],
    rekeys: SharedRekeySlice<'_>,
) -> SeedAdvance {
    if entries.is_empty() {
        return SeedAdvance::None;
    }
    let Some(own_cert) = identity.devices().first() else {
        return SeedAdvance::None;
    };
    let vault_id = item.reference.vault_id;
    let base_log = match &item.status {
        Status::Ready(sv) => build_log_copy(sv),
        Status::Pending | Status::Unavailable
            if shared_paths_for(base, &vault_id).members_log().is_file() =>
        {
            read_member_log(base, &item.reference).ok()
        }
        Status::Pending | Status::Unavailable => None,
    };
    let cand = base_log.map_or_else(
        || MemberLog::from_entries(vault_id, entries, &item.reference.anchor).ok(),
        |mut l| l.merge(entries).ok().map(|()| l),
    );
    let Some(cand) = cand else {
        return SeedAdvance::None;
    };
    if cand.epoch() <= item.reference.epoch {
        return SeedAdvance::None;
    }
    if cand.role_of(&own_cert.client_id).is_none() {
        return SeedAdvance::Removed;
    }
    let target_epoch = cand.epoch();
    let new_seed = rekeys.iter().find_map(|(rgen, target_dev, blob)| {
        if *target_dev != own_cert.device_id || u32::try_from(*rgen).ok() != Some(target_epoch) {
            return None;
        }
        let seed = open_shared_rekey(
            identity.share_keys(),
            &own_cert.device_id,
            &vault_id,
            &item.reference.anchor,
            target_epoch,
            blob,
        )
        .ok()?;
        seed_matches_log(&cand, target_epoch, &seed).then_some(seed)
    });
    new_seed.map_or(SeedAdvance::None, |seed| {
        SeedAdvance::Rotated(seed, target_epoch)
    })
}

fn build_log_copy(sv: &SharedVault) -> Option<MemberLog> {
    MemberLog::from_entries(*sv.log.vault_id(), sv.log.entries(), sv.log.anchor()).ok()
}

pub(super) enum SnapshotOutcome {
    Rejected,
    SameHead,
    Adopted {
        updated_id: Option<Arc<SyncIdentity>>,
        need_push_back: bool,
    },
}

pub(super) fn try_apply_snapshot_to_vault(
    vault: &mut Vault,
    identity: &SyncIdentity,
    (snap_bytes, head_bytes, head_epoch): DecryptedSnapshot,
    prev_head_epoch: u64,
    adopted_vk: Option<&Secret<[u8; 32]>>,
    rekeys: &[(u64, Zeroizing<Vec<u8>>)],
    rec_frames: &[Vec<u8>],
) -> SnapshotOutcome {
    let Ok((head_vid, head_commit, head_vault_gen)) = decode_personal_head(&head_bytes) else {
        return SnapshotOutcome::Rejected;
    };
    if !bool::from(head_vid.ct_eq(vault.session.vault_id())) {
        return SnapshotOutcome::Rejected;
    }
    let file = VaultFile::new(snap_bytes.to_vec());
    let Ok(parsed) = file.parse() else {
        return SnapshotOutcome::Rejected;
    };
    if !bool::from(parsed.commit.ct_eq(&head_commit)) || parsed.generation != head_vault_gen {
        return SnapshotOutcome::Rejected;
    }
    if bool::from(vault.session.commit_tag().ct_eq(&parsed.commit)) {
        return SnapshotOutcome::SameHead;
    }
    let Some((new_session, unlocked_via_rekey)) = unlock_snapshot_candidate(
        &file,
        &vault.session.reopen_key(),
        identity,
        &head_vid,
        adopted_vk,
        rekeys,
    ) else {
        return SnapshotOutcome::Rejected;
    };
    if !snapshot_epoch_acceptable(
        vault,
        &file,
        &new_session,
        unlocked_via_rekey,
        head_epoch,
        prev_head_epoch,
    ) {
        return if !unlocked_via_rekey
            && wraps_tag(vault.file.as_bytes())
                .ok()
                .zip(wraps_tag(file.as_bytes()).ok())
                .is_some_and(|(lt, rt)| secret::ct_eq_32(&lt, &rt))
        {
            SnapshotOutcome::SameHead
        } else {
            SnapshotOutcome::Rejected
        };
    }
    commit_snapshot_into_vault(
        vault,
        identity,
        new_session,
        file,
        unlocked_via_rekey,
        rec_frames,
    )
}

fn snapshot_epoch_acceptable(
    vault: &Vault,
    new_file: &VaultFile,
    new_session: &Session,
    unlocked_via_rekey: bool,
    head_epoch: u64,
    prev_head_epoch: u64,
) -> bool {
    let _ = new_file;
    if unlocked_via_rekey {
        return !secret::ct_eq(
            new_session.reopen_key().expose(),
            vault.session.reopen_key().expose(),
        ) && head_epoch > prev_head_epoch;
    }
    if head_epoch <= prev_head_epoch {
        return false;
    }
    let seen = vault.meta.seen.map(|c| session::Seen {
        generation: c.generation,
        commit_tag: c.commit_tag,
    });
    !(prev_head_epoch == 0
        && head_epoch < vault.session.generation()
        && check_seen(new_session, seen).is_err())
}

fn commit_snapshot_into_vault(
    vault: &mut Vault,
    identity: &SyncIdentity,
    mut new_session: Session,
    mut file: VaultFile,
    unlocked_via_rekey: bool,
    rec_frames: &[Vec<u8>],
) -> SnapshotOutcome {
    let mut old_id = vault
        .session
        .sync_identity_key()
        .ok()
        .and_then(|k| SyncIdentity::load(&vault.paths.sync_identity(), &k).ok());
    let preserved = merge_local_records_into(&vault.session, &mut new_session, &mut file);
    for frame in rec_frames {
        let _ = accept_peer_frame_seen(&mut new_session, &mut file, frame, |id| {
            old_id.as_ref().map_or_else(
                || identity.last_seen().get(id),
                |oid| oid.last_seen().get(id),
            )
        });
    }
    let _ = preserve_local_chip_wrap(vault, identity, &mut new_session, &mut file);
    let old_peers = vault
        .session
        .personal_peers_key()
        .ok()
        .and_then(|k| load_personal_entries(&vault.paths.peers_store(), &k, true).ok());
    if unlocked_via_rekey {
        vault.meta.seen = None;
    }
    vault.session = new_session;
    vault.file = file;
    if vault.persist().is_err() {
        return SnapshotOutcome::Rejected;
    }
    let updated_id =
        if let (Some(mut id), Ok(key)) = (old_id.take(), vault.session.sync_identity_key()) {
            sync_session_revisions_to_identity(&vault.session, &mut id);
            let _ = id.save(&vault.paths.sync_identity(), &key);
            Some(Arc::new(id))
        } else {
            None
        };
    if let (Some(peers), Ok(key)) = (old_peers, vault.session.personal_peers_key()) {
        let _ = save_personal_entries(&vault.paths.peers_store(), &key, &peers);
    }
    SnapshotOutcome::Adopted {
        updated_id,
        need_push_back: preserved,
    }
}
