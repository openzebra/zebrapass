//! Create a vault from a fresh phrase, or restore one on this device.
//!
//! Both end the same way: this device enrolls its own unlock factor, the
//! file is written atomically, and the rollback cursor is recorded.

use std::path::{Path, PathBuf};

use local::{
    BACKUP_MAGIC, BackupContents, LocalMeta, MAX_BACKUP_FILE, Paths, open_backup_bundle, paths_for,
    restore_shared_entries,
};
use record::Document;
use seed::SeedPhrase;
use session::{
    BodyAlg, HumanPasswordPublics, KdfProfile, Session, UnlockCreds, VaultFile, add_human_password,
    replace_human_password, unlock, wrap_directory, write_records_batch,
};
use zeroize::Zeroizing;

use crate::vault::device;
use crate::vault::error::UnlockError;
use crate::vault::open::{Vault, read_vault_file};

/// The factor this device enrolls.
pub enum Enrollment {
    /// A human password, sealed under Argon2id with the given profile.
    Password(Zeroizing<Vec<u8>>),
    /// Keep the password factor the restored file already has.
    KeepExisting,
    /// Replace the password the restored file already has with this one. A
    /// file carries one human password and the first one found opens it, so
    /// a restore over the network, which brings another device's file, must
    /// not add a second that would never be tried.
    ReplacePassword(Zeroizing<Vec<u8>>),
    /// This device's keys, sealed under this PIN with this Argon2id preset.
    Device(Zeroizing<Vec<u8>>, KdfProfile),
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Enrollment([REDACTED])")
    }
}

/// A new-vault request.
#[derive(Debug)]
pub struct NewVault {
    /// The freshly generated phrase.
    pub phrase: Box<SeedPhrase>,
    /// Display name.
    pub name: String,
    /// Data directory.
    pub base: PathBuf,
    /// Argon2id profile for the header and the password factor.
    pub profile: KdfProfile,
    /// This device's factor.
    pub factor: Enrollment,
    /// Records imported from another manager, written with the vault.
    pub records: Vec<Document>,
}

/// Where a restore gets the vault file from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreSource {
    /// A vault file on this machine: a backup or a copy from another device.
    File(PathBuf),
    /// No file: an empty vault of this device's own, replaced by the
    /// account's vault when another device is found on the network.
    Empty,
}

/// A restore request.
#[derive(Debug)]
pub struct RestoreVault {
    /// The recovery phrase, already checksum-validated.
    pub phrase: Box<SeedPhrase>,
    /// Display name on this device.
    pub name: String,
    /// Data directory.
    pub base: PathBuf,
    /// Where the vault file comes from.
    pub source: RestoreSource,
    /// Argon2id profile for a newly enrolled password.
    pub profile: KdfProfile,
    /// This device's factor.
    pub factor: Enrollment,
}

/// Create a vault and enroll this device.
///
/// # Errors
///
/// Core and storage errors; the vault directory may be left behind when the
/// failure happens after the first write.
pub fn create(request: NewVault) -> anyhow::Result<Box<Vault>> {
    let NewVault {
        phrase,
        name,
        base,
        profile,
        factor,
        records,
    } = request;
    // Every new vault uses per-record frames: each frame is the AEGIS-256 +
    // Kuznyechik cascade, and there is no cipher choice to get wrong.
    let (paths, mut session, mut file, mut meta) =
        local::create_vault(&base, phrase.seed(), profile, BodyAlg::Frames)?;
    local::SyncIdentity::enroll(phrase.seed(), &meta.client_id, meta.device_id, u64::MAX)?
        .save(&paths.sync_identity(), &session.sync_identity_key()?)?;
    drop(phrase);
    meta.name = name;
    enroll(&mut session, &mut file, &paths, profile, factor)?;
    write_records_batch(&mut session, &mut file, &records)?;
    drop(records);
    let directory = wrap_directory(&file)?;
    let mut vault = Box::new(Vault {
        session,
        file,
        meta,
        paths,
        directory,
    });
    vault.persist()?;
    Ok(vault)
}

/// Restore a vault file with its phrase, enroll this device, and start a
/// fresh rollback cursor. This is the deliberate override path: a phrase
/// holder may reset the cursor.
///
/// # Errors
///
/// [`UnlockError::Denied`] when the phrase does not open the file; storage
/// errors as [`UnlockError::Io`].
pub fn restore(request: RestoreVault) -> Result<Box<Vault>, UnlockError> {
    match request.source.clone() {
        RestoreSource::File(source) => restore_file(request, &source),
        RestoreSource::Empty => restore_empty(request),
    }
}

fn restore_empty(request: RestoreVault) -> Result<Box<Vault>, UnlockError> {
    let RestoreVault {
        phrase,
        name,
        base,
        profile,
        factor,
        ..
    } = request;
    let vault = create(NewVault {
        phrase,
        name,
        base,
        profile,
        factor,
        records: Vec::new(),
    })
    .map_err(|_| UnlockError::Io)?;
    crate::vault::adopt::mark_placeholder(&vault.paths).map_err(|_| UnlockError::Io)?;
    Ok(vault)
}

fn restore_file(request: RestoreVault, source: &Path) -> Result<Box<Vault>, UnlockError> {
    let RestoreVault {
        phrase,
        name,
        base,
        profile,
        factor,
        ..
    } = request;
    let is_backup = is_zpbk_header(source);
    let (file, session, shared) = if is_backup {
        let len = std::fs::metadata(source)
            .map_err(|_| UnlockError::Io)?
            .len();
        if len > MAX_BACKUP_FILE as u64 {
            return Err(UnlockError::NotAVault);
        }
        let bytes = std::fs::read(source).map_err(|_| UnlockError::Io)?;
        let contents = open_backup_bundle(&bytes, &UnlockCreds::master(phrase.seed()))
            .map_err(|error| UnlockError::from(&error))?;
        match contents {
            BackupContents::Bundle(bundle) => (bundle.file, bundle.session, bundle.shared),
            BackupContents::LegacyVault(legacy) => (legacy.file, legacy.session, Vec::new()),
        }
    } else {
        let file = read_vault_file(source)?;
        let session = unlock(&file, &UnlockCreds::master(phrase.seed()), None)
            .map_err(|error| UnlockError::from(&error))?;
        (file, session, Vec::new())
    };
    let client_id = kdf::client_id(phrase.seed()).map_err(|_| UnlockError::Io)?;
    let paths = paths_for(&base, session.vault_id());
    let identity =
        local::SyncIdentity::enroll(phrase.seed(), &client_id, session.origin_device(), u64::MAX)
            .map_err(|_| UnlockError::Io)?;
    identity
        .save(
            &paths.sync_identity(),
            &session.sync_identity_key().map_err(|_| UnlockError::Io)?,
        )
        .map_err(|_| UnlockError::Io)?;
    drop(phrase);
    let factor = match factor {
        Enrollment::Password(pw)
            if wrap_directory(&file)
                .is_ok_and(|dir| crate::vault::factors::presence(&dir, None).password) =>
        {
            Enrollment::ReplacePassword(pw)
        }
        other => other,
    };
    let vault = land((session, file, paths), (client_id, name), profile, factor)?;
    if !shared.is_empty() {
        restore_shared_entries(&base, &identity, &vault.session, &shared, true)
            .map_err(|_| UnlockError::Io)?;
    }
    Ok(vault)
}

fn is_zpbk_header(source: &Path) -> bool {
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(source) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == BACKUP_MAGIC
}

/// Make a restored vault this device's: its metadata with a fresh rollback
/// cursor, this device's factor, and the file written.
pub(crate) fn land(
    (mut session, mut file, paths): (Session, VaultFile, Paths),
    (client_id, name): ([u8; 64], String),
    profile: KdfProfile,
    factor: Enrollment,
) -> Result<Box<Vault>, UnlockError> {
    let meta = LocalMeta {
        device_id: session.origin_device(),
        client_id,
        created_at_ms: unix_ms(),
        name,
        seen: None,
        prefs: None,
        usage: local::Usage::default(),
    };
    enroll(&mut session, &mut file, &paths, profile, factor).map_err(|_| UnlockError::Io)?;
    let directory = wrap_directory(&file).map_err(|_| UnlockError::NotAVault)?;
    let mut vault = Box::new(Vault {
        session,
        file,
        meta,
        paths,
        directory,
    });
    vault.persist().map_err(|_| UnlockError::Io)?;
    Ok(vault)
}

/// Add this device's factor.
fn enroll(
    session: &mut Session,
    file: &mut VaultFile,
    paths: &Paths,
    profile: KdfProfile,
    factor: Enrollment,
) -> anyhow::Result<()> {
    match factor {
        Enrollment::Password(password) => add_password(session, file, &password, profile),
        Enrollment::KeepExisting => Ok(()),
        Enrollment::ReplacePassword(password) => {
            replace_password(session, file, &password, profile)
        }
        Enrollment::Device(pin, pin_profile) => {
            device::enroll(session, file, paths, &pin, pin_profile)
        }
    }
}

/// Seal the vault key under a human password.
///
/// # Errors
///
/// `os entropy failed` when the key id cannot be drawn; core seal errors.
pub fn add_password(
    session: &mut Session,
    file: &mut VaultFile,
    password: &[u8],
    profile: KdfProfile,
) -> anyhow::Result<()> {
    let cost = (profile.m_kib(), profile.t(), profile.p());
    add_human_password(session, file, &password_publics(password, cost)?)
}

fn replace_password(
    session: &mut Session,
    file: &mut VaultFile,
    password: &[u8],
    profile: KdfProfile,
) -> anyhow::Result<()> {
    let cost = (profile.m_kib(), profile.t(), profile.p());
    replace_human_password(session, file, &password_publics(password, cost)?)
}

/// A human password wrap request with a fresh key id and Argon2id `cost`
/// as `(m_kib, t, p)`. The result wipes its password copy on drop.
///
/// # Errors
///
/// `os entropy failed` when the key id cannot be drawn.
pub fn password_publics(
    password: &[u8],
    (m_kib, t, p): (u32, u32, u32),
) -> anyhow::Result<HumanPasswordPublics> {
    let mut kid = [0u8; 8];
    getrandom::fill(&mut kid).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok(HumanPasswordPublics {
        kid,
        password: password.to_vec(),
        m_kib,
        t,
        p,
    })
}

/// Unix milliseconds now, for record ages and metadata.
#[must_use]
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
