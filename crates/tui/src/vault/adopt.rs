//! Replace a placeholder with the account's vault (from an HTTPS/WSS sync
//! server or a LAN peer).
//!
//! A device restored without a vault file holds an empty vault of its own;
//! when a sync server or another device of the account answers, the file it
//! holds takes its place and this device enrolls its own unlock factor
//! independently (password or PIN-sealed device key file).

use std::sync::Arc;

use local::{
    BackupContents, Paths, SyncIdentity, decode_personal_head, load_local_meta, open_backup_bundle,
    paths_for, remember_personal_peer, restore_shared_entries, save_meta,
};
use p2p_net::{Announce, PersonalFetch, fetch_personal};
use secret::Secret;
use session::{
    KdfProfile, Seen, Session, UnlockCreds, VaultFile, check_seen, unlock, wrap_directory,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::vault::create::{Enrollment, land};
use crate::vault::error::UnlockError;
use crate::vault::factors::presence;
use crate::vault::open::{Vault, read_vault_file};

/// File in a placeholder's directory that says it is one.
const MARKER: &str = "placeholder";

/// Whether the vault at `paths` is an empty stand-in waiting for the real one.
#[must_use]
pub fn is_placeholder(paths: &Paths) -> bool {
    paths.vault_dir().join(MARKER).is_file()
}

/// Mark the vault at `paths` as a placeholder.
///
/// # Errors
///
/// Storage failure.
pub fn mark_placeholder(paths: &Paths) -> anyhow::Result<()> {
    local::write_atomic(&paths.vault_dir().join(MARKER), b"")
}

/// Remove the placeholder marker at `paths` so the vault is served as the
/// account's personal vault.
pub fn unmark_placeholder(paths: &Paths) {
    let _ = std::fs::remove_file(paths.vault_dir().join(MARKER));
}

/// Which local unlock factor a restored device chose for itself.
pub enum HeldFactor {
    /// Human-chosen password.
    Password(Zeroizing<Vec<u8>>),
    /// PIN-sealed device key file with its Argon2id profile.
    DevicePin(Zeroizing<Vec<u8>>, KdfProfile),
}

impl std::fmt::Debug for HeldFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldFactor([REDACTED])")
    }
}

/// Credentials kept in memory for an unresolved placeholder vault until the
/// account's real vault arrives and adopts this device's own factor.
pub struct Held {
    /// Master seed derived from the recovery phrase at restore time (`None` if
    /// reopening a placeholder after a lock screen with password only).
    pub seed: Option<Secret<[u8; 64]>>,
    /// Argon2id profile for password enrollment.
    pub profile: KdfProfile,
    /// This device's own unlock factor.
    pub factor: HeldFactor,
}

impl Held {
    /// Build a held credential carrying the master seed from phrase restore.
    #[must_use]
    pub fn from_phrase(seed: &[u8; 64], profile: KdfProfile, factor: HeldFactor) -> Arc<Self> {
        Arc::new(Self {
            seed: Some(Secret::new(*seed)),
            profile,
            factor,
        })
    }

    /// Build a password-only held credential when reopening a placeholder vault
    /// after locking.
    #[must_use]
    pub fn password_only(password: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            seed: None,
            profile: KdfProfile::Balanced,
            factor: HeldFactor::Password(Zeroizing::new(password.to_vec())),
        })
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Held([REDACTED])")
    }
}

/// What it takes to fetch the account's vault and replace a placeholder.
pub struct AdoptRequest {
    /// Where the placeholder lives.
    pub placeholder: Paths,
    /// This device's identity, enrolled at restore.
    pub identity: Arc<SyncIdentity>,
    /// Derived from the phrase at restore; kept on this device's metadata.
    pub client_id: [u8; 64],
    /// Display name on this device.
    pub name: String,
    /// Held restore credentials + local factor to enroll on this device.
    pub held: Arc<Held>,
    /// LAN/WAN P2P addresses to try, newest last.
    pub addresses: Vec<String>,
    /// Addresses the owner typed, which the account's vault keeps once here.
    pub manual: Vec<String>,
    /// Addresses on this machine may be dialed.
    pub loopback: bool,
    /// HTTPS/WSS sync server URLs configured on CLI or settings.
    pub sync_servers: Vec<String>,
    /// Outbound proxy URL configured on CLI or settings.
    pub sync_proxy: Option<String>,
    /// Optional additional CA certificate PEM bytes.
    pub extra_ca_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for AdoptRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdoptRequest([REDACTED])")
    }
}

/// Fetch the account's vault from configured HTTPS/WSS sync servers first, then
/// LAN peers, verify it, enroll this device's own factor, and remove the
/// placeholder.
///
/// # Errors
///
/// [`UnlockError::Peer`] when nothing answers, [`UnlockError::WrongVault`]
/// when the file does not match what was announced, [`UnlockError::Denied`]
/// when held credentials cannot unlock it, [`UnlockError::Rollback`] /
/// [`UnlockError::Conflict`] against a newer local file, or [`UnlockError::Io`].
pub fn adopt(request: &AdoptRequest) -> Result<Box<Vault>, UnlockError> {
    if !request.sync_servers.is_empty()
        && let Some(vault) = adopt_from_https(request)?
    {
        return Ok(vault);
    }
    let mut last = UnlockError::Peer(p2p_net::FetchError::Unreachable);
    for address in request.addresses.iter().rev() {
        match fetch_personal(&request.identity, address, request.loopback) {
            Ok(fetched) => return adopt_fetched(request, fetched, address),
            Err(reason) => last = UnlockError::Peer(reason),
        }
    }
    Err(last)
}

fn adopt_from_https(request: &AdoptRequest) -> Result<Option<Box<Vault>>, UnlockError> {
    let Ok(client) = sync_https::SyncClient::new(
        &request.sync_servers,
        request.sync_proxy.as_deref(),
        request.extra_ca_pem.as_deref(),
        true,
    ) else {
        return Ok(None);
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| UnlockError::Io)?;
    if let Ok(Some(pulled)) = rt.block_on(client.pull_personal_state(&request.identity, 0))
        && let Some((snap_bytes, head_bytes, _)) = pulled.snapshot
    {
        let (vault_id, commit_tag, generation) =
            decode_personal_head(&head_bytes).map_err(|_| UnlockError::WrongVault)?;
        let peer = request
            .identity
            .devices()
            .first()
            .cloned()
            .ok_or(UnlockError::Io)?;
        let fetched = PersonalFetch {
            announce: Announce {
                vault_id,
                generation,
                commit_tag,
            },
            file: snap_bytes.to_vec(),
            peer,
        };
        let mut vault = adopt_fetched_with_frames(request, fetched, &pulled.frames, None)?;
        apply_sync_prefs(&mut vault, request)?;
        return Ok(Some(vault));
    }
    if let Ok(Some(zpbk_bytes)) = rt.block_on(client.pull_cloud_backup(&request.identity)) {
        let mut vault = adopt_from_backup_bytes(request, &zpbk_bytes)?;
        apply_sync_prefs(&mut vault, request)?;
        return Ok(Some(vault));
    }
    Ok(None)
}

fn unlock_with_held(file: &VaultFile, held: &Held) -> Result<Session, UnlockError> {
    let dir = wrap_directory(file).map_err(|_| UnlockError::NotAVault)?;
    let has_password = presence(&dir, None).password;
    match &held.factor {
        HeldFactor::Password(pw) if has_password => {
            unlock(file, &UnlockCreds::default().with_human(pw), None)
                .map_err(|_| UnlockError::Denied)
        }
        HeldFactor::Password(_) | HeldFactor::DevicePin(_, _) => {
            let seed = held.seed.as_ref().ok_or(UnlockError::Denied)?;
            unlock(file, &UnlockCreds::master(seed.expose()), None).map_err(|_| UnlockError::Denied)
        }
    }
}

fn local_enrollment(file: &VaultFile, held: &Held) -> Result<Enrollment, UnlockError> {
    let dir = wrap_directory(file).map_err(|_| UnlockError::NotAVault)?;
    match &held.factor {
        HeldFactor::Password(pw) => {
            if presence(&dir, None).password {
                Ok(Enrollment::KeepExisting)
            } else {
                Ok(Enrollment::Password(Zeroizing::new(pw.to_vec())))
            }
        }
        HeldFactor::DevicePin(pin, profile) => {
            Ok(Enrollment::Device(Zeroizing::new(pin.to_vec()), *profile))
        }
    }
}

fn adopt_from_backup_bytes(
    request: &AdoptRequest,
    bytes: &[u8],
) -> Result<Box<Vault>, UnlockError> {
    let contents = match request.held.seed.as_ref() {
        Some(seed) => open_backup_bundle(bytes, &UnlockCreds::master(seed.expose())),
        None => match &request.held.factor {
            HeldFactor::Password(pw) => {
                open_backup_bundle(bytes, &UnlockCreds::default().with_human(pw))
            }
            HeldFactor::DevicePin(_, _) => return Err(UnlockError::Denied),
        },
    }
    .map_err(|_| UnlockError::Denied)?;
    let (file, mut session, shared) = match contents {
        BackupContents::Bundle(bundle) => (bundle.file, bundle.session, bundle.shared),
        BackupContents::LegacyVault(legacy) => (legacy.file, legacy.session, Vec::new()),
    };
    if let HeldFactor::Password(pw) = &request.held.factor {
        let dir = wrap_directory(&file).map_err(|_| UnlockError::NotAVault)?;
        if presence(&dir, None).password {
            unlock(&file, &UnlockCreds::default().with_human(pw), None)
                .map_err(|_| UnlockError::Denied)?;
        }
    }
    let device_id = request.identity.device_id().ok_or(UnlockError::Io)?;
    let paths = paths_for(&request.placeholder.base, session.vault_id());
    if paths.vault_dir() == request.placeholder.vault_dir() {
        return Err(UnlockError::WrongVault);
    }
    refuse_older(&paths, &session)?;
    session
        .set_origin_device(device_id)
        .map_err(|_| UnlockError::Io)?;
    request
        .identity
        .save(
            &paths.sync_identity(),
            &session.sync_identity_key().map_err(|_| UnlockError::Io)?,
        )
        .map_err(|_| UnlockError::Io)?;
    let enrollment = local_enrollment(&file, &request.held)?;
    let vault = land(
        (session, file, paths),
        (request.client_id, request.name.clone()),
        request.held.profile,
        enrollment,
    )?;
    if !shared.is_empty() {
        restore_shared_entries(
            &request.placeholder.base,
            &request.identity,
            &vault.session,
            &shared,
            false,
        )
        .map_err(|_| UnlockError::Io)?;
    }
    drop(std::fs::remove_dir_all(request.placeholder.vault_dir()));
    Ok(vault)
}

/// Verify a fetched vault file, enroll this device's factor, and replace the
/// placeholder.
///
/// # Errors
///
/// As [`adopt`], for everything after the fetch.
pub fn adopt_fetched(
    request: &AdoptRequest,
    fetched: PersonalFetch,
    address: &str,
) -> Result<Box<Vault>, UnlockError> {
    let mut vault = adopt_fetched_with_frames(request, fetched, &[], Some(address))?;
    apply_sync_prefs(&mut vault, request)?;
    Ok(vault)
}

fn adopt_fetched_with_frames(
    request: &AdoptRequest,
    fetched: PersonalFetch,
    frames: &[(u64, Zeroizing<Vec<u8>>)],
    address: Option<&str>,
) -> Result<Box<Vault>, UnlockError> {
    let device_id = request.identity.device_id().ok_or(UnlockError::Io)?;
    let mut file = VaultFile::new(fetched.file);
    let announced = {
        let parsed = file.parse().map_err(|_| UnlockError::NotAVault)?;
        let announce = &fetched.announce;
        bool::from(parsed.header.vault_id.ct_eq(&announce.vault_id))
            && bool::from(parsed.commit.ct_eq(&announce.commit_tag))
            && parsed.generation == announce.generation
    };
    if !announced {
        return Err(UnlockError::WrongVault);
    }
    let mut session = unlock_with_held(&file, &request.held)?;
    for (_, raw) in frames {
        if !raw.starts_with(&local::PERSONAL_DEVICE_MAGIC) {
            let _ = session::accept_peer_frame(&mut session, &mut file, raw);
        }
    }
    let paths = paths_for(&request.placeholder.base, session.vault_id());
    if paths.vault_dir() == request.placeholder.vault_dir() {
        return Err(UnlockError::WrongVault);
    }
    refuse_older(&paths, &session)?;
    session
        .set_origin_device(device_id)
        .map_err(|_| UnlockError::Io)?;
    request
        .identity
        .save(
            &paths.sync_identity(),
            &session.sync_identity_key().map_err(|_| UnlockError::Io)?,
        )
        .map_err(|_| UnlockError::Io)?;
    if let Some(addr) = address {
        remember_peer(&paths, &session, addr);
    }
    keep_manual(&paths, &session, &request.manual);
    let enrollment = local_enrollment(&file, &request.held)?;
    let vault = land(
        (session, file, paths),
        (request.client_id, request.name.clone()),
        request.held.profile,
        enrollment,
    )?;
    drop(std::fs::remove_dir_all(request.placeholder.vault_dir()));
    Ok(vault)
}

fn apply_sync_prefs(vault: &mut Vault, request: &AdoptRequest) -> Result<(), UnlockError> {
    if request.sync_servers.is_empty() && request.sync_proxy.is_none() {
        return Ok(());
    }
    let mut prefs = vault.meta.prefs.clone().unwrap_or_default();
    if prefs.sync_servers.is_empty() {
        prefs.sync_servers = request
            .sync_servers
            .iter()
            .map(|s| Box::from(s.as_str()))
            .collect();
    }
    if prefs.sync_proxy.is_none() {
        prefs.sync_proxy = request.sync_proxy.as_deref().map(Box::from);
    }
    vault.meta.prefs = Some(prefs);
    save_meta(&vault.paths, &vault.meta, &vault.session).map_err(|_| UnlockError::Io)
}

fn keep_manual(paths: &Paths, session: &Session, manual: &[String]) {
    if let Ok(key) = session.personal_peers_key() {
        manual.iter().rev().for_each(|address| {
            drop(local::add_manual_peer(
                &paths.peers_store(),
                &key,
                address,
                true,
            ));
        });
    }
}

fn remember_peer(paths: &Paths, session: &Session, address: &str) {
    let _ = session
        .personal_peers_key()
        .and_then(|key| remember_personal_peer(&paths.peers_store(), &key, address));
}

fn refuse_older(paths: &Paths, session: &Session) -> Result<(), UnlockError> {
    if let Ok(held) = read_vault_file(&paths.vault_file)
        && let Ok(parsed) = held.parse()
    {
        let same_tag = bool::from(parsed.commit.ct_eq(session.commit_tag()));
        if session.generation() < parsed.generation {
            return Err(UnlockError::Rollback {
                seen: parsed.generation,
                disk: session.generation(),
            });
        }
        if session.generation() == parsed.generation && !same_tag {
            return Err(UnlockError::Conflict {
                generation: parsed.generation,
            });
        }
    }
    let Ok(key) = session.local_meta_key() else {
        return Err(UnlockError::Io);
    };
    if let Ok(meta) = load_local_meta(&paths.local_meta, &key) {
        let seen = meta.seen.map(|cursor| Seen {
            generation: cursor.generation,
            commit_tag: cursor.commit_tag,
        });
        check_seen(session, seen).map_err(|error| match UnlockError::from(&error) {
            UnlockError::Rollback { .. } => UnlockError::Rollback {
                seen: seen.map_or(0, |cursor| cursor.generation),
                disk: session.generation(),
            },
            UnlockError::Conflict { .. } => UnlockError::Conflict {
                generation: session.generation(),
            },
            other => other,
        })?;
    }
    Ok(())
}
