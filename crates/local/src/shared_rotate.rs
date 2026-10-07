//! Replacing a shared vault's seed: what an owner does when removing a member
//! or rotating, and what a device that was behind does when the new seed
//! reaches it.
//!
//! A removed member still holds the old seed and so the old vault key. The
//! rotation draws a new vault key and re-seals the master wrap from a new
//! seed, so what is written afterwards stays closed to them. The owner's
//! signed log entry commits to the new seed by hash, so no member can hand
//! out a forked vault under a seed of their choosing.

use std::path::Path;

use memberlog::{rotation_commit, Action, Entry, MemberLog};
use secret::Secret;
use session::{rotate_vault_key, unlock, Attestation, RotateCreds, UnlockCreds, VaultFile};

use crate::meta::LocalMeta;
use crate::shared::{file_keys, load_log_any, load_state_any, SharedVault};
use crate::shared_files::save_member_log;
use crate::shared_ref::SharedRef;
use crate::shared_sync::attested_store;
use crate::sync_identity::SyncIdentity;
use crate::usage::Usage;
use crate::{mark_seen, now_ms, shared_paths_for, write_atomic};

fn failed() -> anyhow::Error {
    anyhow::anyhow!("shared vault unavailable")
}

/// What the owner's log entry does besides replacing the seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replace {
    /// Remove this account from the vault.
    Remove([u8; 64]),
    /// Remove nobody: the seed is replaced, say after a member left.
    Rotate,
}

/// A fresh seed and the reference that makes it current.
///
/// `log_epoch` is the epoch of the verified member log: the new seed is the
/// next one after it, whatever an earlier cut-short attempt left in the
/// reference. Store the returned reference in the personal vault *before*
/// [`apply_rotation`], so the new seed survives a crash in between: every
/// reader falls back to the retired seed until the vault file has moved.
///
/// # Errors
///
/// Randomness failure.
pub fn plan_rotation(reference: &SharedRef, log_epoch: u32) -> anyhow::Result<SharedRef> {
    let mut seed = Secret::new([0u8; 64]);
    getrandom::fill(seed.expose_mut())?;
    Ok(reference.rotated(seed, log_epoch.saturating_add(1)))
}

/// Rotate the vault under `next`'s seed and append the owner's log entry.
///
/// The entry is checked against a copy of the log first, so a request the
/// log would refuse (an unknown account, the last owner) changes nothing.
/// Afterwards the vault file, the member log and the local state are all
/// sealed under the new seed.
///
/// # Errors
///
/// `shared vault unavailable` when `next` is not the next epoch of this
/// vault; the log's refusal of the entry; signing, rotation and storage
/// errors.
pub fn apply_rotation(
    vault: &mut SharedVault,
    next: &SharedRef,
    identity: &SyncIdentity,
    replace: Replace,
) -> anyhow::Result<()> {
    let own = identity.devices().first().ok_or_else(failed)?;
    let vault_id = *vault.session.vault_id();
    if next.vault_id != vault_id || next.epoch != vault.log.epoch().saturating_add(1) {
        return Err(failed());
    }
    let commit = rotation_commit(&vault_id, next.epoch, next.seed.expose());
    let action = match replace {
        Replace::Remove(client_id) => Action::Remove { client_id, commit },
        Replace::Rotate => Action::Rotate { commit },
    };
    let entry = vault
        .log
        .propose(&identity.sign_key(), own, action, now_ms())?;
    let mut trial = MemberLog::from_entries(vault_id, vault.log.entries(), vault.log.anchor())?;
    trial.append(entry.clone())?;

    let creds = RotateCreds {
        master: next.seed.expose(),
        prfs: &[],
        human_password: None,
    };
    rotate_vault_key(&mut vault.session, &mut vault.file, &creds)?;
    let mut session = unlock(&vault.file, &UnlockCreds::master(next.seed.expose()), None)
        .map_err(|_| failed())?;
    session.set_origin_device(own.device_id)?;
    vault.session = session;
    vault.meta.seen = None;
    vault.log.append(entry)?;
    vault.save_log(&next.seed)?;
    vault.persist(&next.seed)
}

/// A vault file with the attestations that came with it.
#[derive(Debug)]
pub struct Attested<'a> {
    /// The vault file.
    pub file: VaultFile,
    /// The attestations of the records in it.
    pub attestations: &'a [Attestation],
}

/// Everything a device checked before it takes a rotated vault, ready to
/// write.
///
/// Nothing has been written yet: store [`RekeyPlan::reference`] in the
/// personal vault, then [`RekeyPlan::commit`]. A crash in between is
/// harmless, because the files still on disk open through the retired seed
/// and the next fetch finishes the job.
pub struct RekeyPlan {
    base: std::path::PathBuf,
    reference: SharedRef,
    file: VaultFile,
    session: session::Session,
    log: MemberLog,
    state: crate::shared_files::SharedState,
    attest: crate::attest_store::AttestStore,
    device_id: [u8; 16],
}

impl RekeyPlan {
    /// The reference to store in the personal vault.
    #[must_use]
    pub const fn reference(&self) -> &SharedRef {
        &self.reference
    }

    /// Write the log, the state, the vault file and the rollback cursor under
    /// the new seed.
    ///
    /// # Errors
    ///
    /// Storage and key-derivation errors.
    pub fn commit(self) -> anyhow::Result<SharedVault> {
        let Self {
            base,
            reference,
            file,
            session,
            log,
            state,
            attest,
            device_id,
        } = self;
        let paths = shared_paths_for(&base, &reference.vault_id);
        let keys = file_keys(&reference.seed, &reference.vault_id)?;
        save_member_log(&paths.members_log(), &keys.log, &log)?;
        state.save(&paths.shared_state(), &keys.state)?;
        attest.save(&paths.attest_store(), &keys.attest)?;
        write_atomic(&paths.vault_file, file.as_bytes())?;
        let mut meta = LocalMeta {
            device_id,
            client_id: kdf::client_id(reference.seed.expose())?,
            created_at_ms: now_ms(),
            name: reference.name.clone(),
            seen: None,
            prefs: None,
            usage: Usage::default(),
        };
        mark_seen(&paths, &mut meta, &session)?;
        Ok(SharedVault {
            paths,
            session,
            file,
            meta,
            log,
            state,
            attest,
            stale: false,
        })
    }
}

/// Check a rotated vault on a device that was behind: its file, sealed under
/// the new seed, plus the member log entries that announced it. Writes
/// nothing.
///
/// The log is merged with every new entry verified, and the seed is accepted
/// only if it is the epoch the log reached and hashes to the owner-signed
/// commitment. The file must open with it, be this vault, and, when
/// `min_generation` is given, be newer than what this device had. Every record
/// in it must be attested by a writer of the merged log.
///
/// # Errors
///
/// `shared vault unavailable` for any failed check.
pub fn prepare_rekey(
    base: &Path,
    old: &SharedRef,
    new: SharedRef,
    incoming: Attested<'_>,
    identity: &SyncIdentity,
    entries: &[Entry],
    min_generation: Option<u64>,
) -> anyhow::Result<RekeyPlan> {
    let Attested { file, attestations } = incoming;
    let own = identity.devices().first().ok_or_else(failed)?;
    let paths = shared_paths_for(base, &old.vault_id);
    let mut log = load_log_any(&paths, old)?;
    log.merge(entries)?;
    let committed = log.commit_for(new.epoch).copied();
    let honest = new.vault_id == old.vault_id
        && new.anchor == old.anchor
        && new.epoch == log.epoch()
        && committed == Some(rotation_commit(&old.vault_id, new.epoch, new.seed.expose()));
    let introduced = !crate::shared::is_pending(base, old)
        || old
            .introduction
            .as_ref()
            .is_none_or(|intro| intro.confirms(&log));
    if !honest || !introduced || log.role_of(&own.client_id).is_none() {
        return Err(failed());
    }
    let mut session =
        unlock(&file, &UnlockCreds::master(new.seed.expose()), None).map_err(|_| failed())?;
    if session.vault_id() != &old.vault_id
        || min_generation.is_some_and(|floor| session.generation() <= floor)
    {
        return Err(failed());
    }
    session.set_origin_device(own.device_id)?;
    let state = load_state_any(&paths, old)?;
    let attest = attested_store(
        &session,
        &log,
        attestations,
        crate::shared::load_attest_any(&paths, old)?,
    )?;
    Ok(RekeyPlan {
        base: base.to_path_buf(),
        reference: new,
        file,
        session,
        log,
        state,
        attest,
        device_id: own.device_id,
    })
}

/// [`prepare_rekey`] and [`RekeyPlan::commit`] in one step, for callers that
/// store the reference themselves afterwards.
///
/// # Errors
///
/// As [`prepare_rekey`] and [`RekeyPlan::commit`].
pub fn adopt_rekeyed(
    base: &Path,
    old: &SharedRef,
    new: SharedRef,
    incoming: Attested<'_>,
    identity: &SyncIdentity,
    entries: &[Entry],
    min_generation: Option<u64>,
) -> anyhow::Result<SharedVault> {
    prepare_rekey(base, old, new, incoming, identity, entries, min_generation)?.commit()
}

/// Whether this device's seed is behind the member log: an owner rotated and
/// the new seed has not reached it yet.
#[must_use]
pub fn is_behind(reference: &SharedRef, log: &MemberLog) -> bool {
    log.epoch() > reference.epoch
}

/// Check a seed offered by a peer against the owner-signed commitment of
/// `log` for `epoch`, without touching any file.
#[must_use]
pub fn seed_matches_log(log: &MemberLog, epoch: u32, seed: &Secret<[u8; 64]>) -> bool {
    log.epoch() == epoch
        && log.commit_for(epoch).copied()
            == Some(rotation_commit(log.vault_id(), epoch, seed.expose()))
}
