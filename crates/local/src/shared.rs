//! Creating, joining and opening shared vaults on this device.
//!
//! A shared vault is an ordinary vault file unlocked with a random 64-byte
//! seed that its members hold. The creator makes it and the first member log
//! entry; an invitee stores the log, the seed reference and local state at
//! once (the device is then *pending*) and receives the vault file from a
//! member over sync, after which [`adopt_shared_file`] makes it usable.

use std::path::Path;

use aead::BodyAlg;
use kdf::KdfProfile;
use memberlog::MemberLog;
use secret::Secret;
use session::{unlock, Session, UnlockCreds, VaultFile};

use crate::attest_store::AttestStore;
use crate::meta::{load_local_meta, LocalMeta};
use crate::shared_files::{load_member_log, save_member_log, SharedState};
use crate::shared_ref::SharedRef;
use crate::sync_identity::SyncIdentity;
use crate::usage::Usage;
use crate::{create_vault, mark_seen, now_ms, shared_paths_for, shared_root, write_atomic, Paths};

fn failed() -> anyhow::Error {
    anyhow::anyhow!("shared vault unavailable")
}

/// A shared vault opened on this device.
#[derive(Debug)]
pub struct SharedVault {
    /// Where the vault's files are.
    pub paths: Paths,
    /// The unlocked vault.
    pub session: Session,
    /// The vault file as last read or written.
    pub file: VaultFile,
    /// This device's metadata for the vault.
    pub meta: LocalMeta,
    /// The verified member log.
    pub log: MemberLog,
    /// What this device has seen and revoked.
    pub state: SharedState,
    /// The signed attestations of the revisions this vault holds.
    pub attest: AttestStore,
    /// The vault file only opened with a retired seed: a rotation reached
    /// this device's reference but not yet its files.
    pub stale: bool,
}

/// The keys of the two files, derived from the shared seed.
pub struct FileKeys {
    pub log: Secret<[u8; 32]>,
    pub state: Secret<[u8; 32]>,
    pub attest: Secret<[u8; 32]>,
}

pub fn file_keys(seed: &Secret<[u8; 64]>, vault_id: &[u8; 16]) -> anyhow::Result<FileKeys> {
    Ok(FileKeys {
        log: kdf::shared_members_key(seed.expose(), vault_id)?,
        state: kdf::shared_state_key(seed.expose(), vault_id)?,
        attest: kdf::shared_attest_key(seed.expose(), vault_id)?,
    })
}

/// Run `attempt` with the current seed, then each retired one, and return
/// the first success. Files may still be sealed under an older seed when a
/// rotation was cut short, so every reader tries them all.
pub fn try_seeds<T>(
    reference: &SharedRef,
    mut attempt: impl FnMut(&Secret<[u8; 64]>) -> anyhow::Result<T>,
) -> anyhow::Result<(T, usize)> {
    let mut last = failed();
    for (index, seed) in reference.seeds().enumerate() {
        match attempt(seed) {
            Ok(value) => return Ok((value, index)),
            Err(error) => last = error,
        }
    }
    Err(last)
}

pub fn load_log_any(paths: &Paths, reference: &SharedRef) -> anyhow::Result<MemberLog> {
    try_seeds(reference, |seed| {
        let keys = file_keys(seed, &reference.vault_id)?;
        load_member_log(
            &paths.members_log(),
            &keys.log,
            reference.vault_id,
            &reference.anchor,
        )
    })
    .map(|(log, _)| log)
}

pub fn load_attest_any(paths: &Paths, reference: &SharedRef) -> anyhow::Result<AttestStore> {
    try_seeds(reference, |seed| {
        let keys = file_keys(seed, &reference.vault_id)?;
        AttestStore::load(&paths.attest_store(), &keys.attest)
    })
    .map(|(store, _)| store)
}

pub fn load_state_any(paths: &Paths, reference: &SharedRef) -> anyhow::Result<SharedState> {
    try_seeds(reference, |seed| {
        let keys = file_keys(seed, &reference.vault_id)?;
        SharedState::load(&paths.shared_state(), &keys.state)
    })
    .map(|(state, _)| state)
}

impl SharedVault {
    /// Write the vault file, advance the rollback cursor and save the local
    /// state. Call after every change.
    ///
    /// # Errors
    ///
    /// Storage and key-derivation errors.
    pub fn persist(&mut self, seed: &Secret<[u8; 64]>) -> anyhow::Result<()> {
        write_atomic(&self.paths.vault_file, self.file.as_bytes())?;
        mark_seen(&self.paths, &mut self.meta, &self.session)?;
        let keys = file_keys(seed, self.session.vault_id())?;
        self.attest.save(&self.paths.attest_store(), &keys.attest)?;
        self.state.save(&self.paths.shared_state(), &keys.state)
    }

    /// Replace the stored member log with the current one.
    ///
    /// # Errors
    ///
    /// Sealing or write failure.
    pub fn save_log(&self, seed: &Secret<[u8; 64]>) -> anyhow::Result<()> {
        let keys = file_keys(seed, self.session.vault_id())?;
        save_member_log(&self.paths.members_log(), &keys.log, &self.log)
    }
}

/// Create a shared vault owned by this account.
///
/// Draws the vault's seed, creates the vault file, and writes the first
/// member log entry, signed by this device, which makes this account the
/// first owner. Returns the vault and the reference to store in the personal
/// vault.
///
/// # Errors
///
/// Randomness, key-derivation, signing and storage errors.
pub fn create_shared_vault(
    base: &Path,
    identity: &SyncIdentity,
    name: &str,
    profile: KdfProfile,
) -> anyhow::Result<(SharedVault, SharedRef)> {
    if name.len() > crate::limits::SHARED_NAME_MAX {
        return Err(failed());
    }
    let own = identity.devices().first().ok_or_else(failed)?;
    let mut seed = Secret::new([0u8; 64]);
    getrandom::fill(seed.expose_mut())?;
    let (paths, mut session, file, mut meta) =
        create_vault(&shared_root(base), seed.expose(), profile, BodyAlg::Frames)?;
    session.set_origin_device(own.device_id)?;
    name.clone_into(&mut meta.name);
    let log = MemberLog::genesis(
        *session.vault_id(),
        &identity.sign_key(),
        own,
        identity.root_vk(),
        now_ms(),
    )?;
    let reference = SharedRef {
        vault_id: *session.vault_id(),
        anchor: *log.anchor(),
        seed,
        name: name.to_owned(),
        hints: Vec::new(),
        epoch: 0,
        retired: Vec::new(),
    };
    let mut vault = SharedVault {
        paths,
        session,
        file,
        meta,
        log,
        state: SharedState::default(),
        attest: AttestStore::default(),
        stale: false,
    };
    vault.save_log(&reference.seed)?;
    vault.persist(&reference.seed)?;
    Ok((vault, reference))
}

/// Store a shared vault this account was invited to. The vault file is not
/// here yet: the device is pending until [`adopt_shared_file`].
///
/// # Errors
///
/// Key-derivation and storage errors.
pub fn join_shared_vault(
    base: &Path,
    reference: &SharedRef,
    log: &MemberLog,
) -> anyhow::Result<()> {
    if log.vault_id() != &reference.vault_id || log.anchor() != &reference.anchor {
        return Err(failed());
    }
    let paths = shared_paths_for(base, &reference.vault_id);
    let keys = file_keys(&reference.seed, &reference.vault_id)?;
    save_member_log(&paths.members_log(), &keys.log, log)?;
    AttestStore::default().save(&paths.attest_store(), &keys.attest)?;
    SharedState::default().save(&paths.shared_state(), &keys.state)
}

/// The member log of a shared vault that is on this device, open or
/// pending, verified against its anchor.
///
/// # Errors
///
/// `member log unreadable` and the log's own verification errors.
pub fn read_member_log(base: &Path, reference: &SharedRef) -> anyhow::Result<MemberLog> {
    load_log_any(&shared_paths_for(base, &reference.vault_id), reference)
}

/// The local state of a shared vault on this device, read with whichever of
/// the reference's seeds it is sealed under.
///
/// # Errors
///
/// `shared state unreadable` and sealing errors.
pub fn read_shared_state(base: &Path, reference: &SharedRef) -> anyhow::Result<SharedState> {
    load_state_any(&shared_paths_for(base, &reference.vault_id), reference)
}

/// Whether this device still waits for the vault file.
#[must_use]
pub fn is_pending(base: &Path, reference: &SharedRef) -> bool {
    !shared_paths_for(base, &reference.vault_id)
        .vault_file
        .exists()
}

/// Make a joined shared vault usable with the vault file a member sent.
///
/// The file must open with the shared seed and be the vault the reference
/// names; it becomes the first state this device accepts.
///
/// # Errors
///
/// `shared vault unavailable` for a file that is another vault or does not
/// open; storage and key-derivation errors.
pub fn adopt_shared_file(
    base: &Path,
    reference: &SharedRef,
    file: VaultFile,
    identity: &SyncIdentity,
) -> anyhow::Result<SharedVault> {
    let own = identity.devices().first().ok_or_else(failed)?;
    let (mut session, used) = try_seeds(reference, |seed| {
        unlock(&file, &UnlockCreds::master(seed.expose()), None).map_err(|_| failed())
    })?;
    if session.vault_id() != &reference.vault_id {
        return Err(failed());
    }
    session.set_origin_device(own.device_id)?;
    let paths = shared_paths_for(base, &reference.vault_id);
    write_atomic(&paths.vault_file, file.as_bytes())?;
    let mut meta = LocalMeta {
        device_id: own.device_id,
        client_id: kdf::client_id(reference.seed.expose())?,
        created_at_ms: now_ms(),
        name: reference.name.clone(),
        seen: None,
        prefs: None,
        usage: Usage::default(),
    };
    mark_seen(&paths, &mut meta, &session)?;
    let log = load_log_any(&paths, reference)?;
    let state = load_state_any(&paths, reference)?;
    let attest = load_attest_any(&paths, reference)?;
    Ok(SharedVault {
        paths,
        session,
        file,
        meta,
        log,
        state,
        attest,
        stale: used > 0,
    })
}

/// Open a shared vault that is already on this device.
///
/// Applies the rollback cursor, so an older copy of the file is refused.
///
/// # Errors
///
/// `shared vault unavailable` when the vault is pending or does not open;
/// rollback and conflict errors from the unlock; storage errors.
pub fn open_shared_vault(
    base: &Path,
    reference: &SharedRef,
    identity: &SyncIdentity,
) -> anyhow::Result<SharedVault> {
    let own = identity.devices().first().ok_or_else(failed)?;
    let paths = shared_paths_for(base, &reference.vault_id);
    let file = VaultFile::new(std::fs::read(&paths.vault_file).map_err(|_| failed())?);
    let (mut session, used) = try_seeds(reference, |seed| {
        unlock(&file, &UnlockCreds::master(seed.expose()), None).map_err(|_| failed())
    })?;
    if session.vault_id() != &reference.vault_id {
        return Err(failed());
    }
    let mut meta = load_local_meta(&paths.local_meta, &session.local_meta_key()?)?;
    let seen = meta.seen.map(|cursor| session::Seen {
        generation: cursor.generation,
        commit_tag: cursor.commit_tag,
    });
    session::check_seen(&session, seen)?;
    session.set_origin_device(own.device_id)?;
    mark_seen(&paths, &mut meta, &session)?;
    let log = load_log_any(&paths, reference)?;
    let state = load_state_any(&paths, reference)?;
    let attest = load_attest_any(&paths, reference)?;
    Ok(SharedVault {
        paths,
        session,
        file,
        meta,
        log,
        state,
        attest,
        stale: used > 0,
    })
}
