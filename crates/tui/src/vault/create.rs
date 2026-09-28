//! Create a vault from a fresh phrase, or restore one on this device.
//!
//! Both end the same way: this device enrolls its own unlock factor, the
//! file is written atomically, and the rollback cursor is recorded.

use std::path::PathBuf;

use local::{paths_for, LocalMeta, Paths};
use seed::SeedPhrase;
use session::{
    add_human_password, unlock, wrap_directory, BodyAlg, HumanPasswordPublics, KdfProfile, Session,
    UnlockCreds, VaultFile,
};
use zeroize::Zeroizing;

use crate::vault::device;
use crate::vault::error::UnlockError;
use crate::vault::open::{read_vault_file, Vault};

/// The factor this device enrolls.
pub enum Enrollment {
    /// A human password, sealed under Argon2id with the given profile.
    Password(Zeroizing<Vec<u8>>),
    /// Keep the password factor the restored file already has.
    KeepExisting,
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
    /// The vault file to restore (a backup or a copy from another device).
    pub source: PathBuf,
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
    } = request;
    // Every new vault uses per-record frames: each frame is the AEGIS-256 +
    // Kuznyechik cascade, and there is no cipher choice to get wrong.
    let (paths, mut session, mut file, mut meta) =
        local::create_vault(&base, phrase.seed(), profile, BodyAlg::Frames)?;
    drop(phrase);
    meta.name = name;
    enroll(&mut session, &mut file, &paths, profile, factor)?;
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
    let RestoreVault {
        phrase,
        name,
        base,
        source,
        profile,
        factor,
    } = request;
    let mut file = read_vault_file(&source)?;
    let mut session = unlock(&file, &UnlockCreds::master(phrase.seed()), None)
        .map_err(|error| UnlockError::from(&error))?;
    let client_id = kdf::client_id(phrase.seed()).map_err(|_| UnlockError::Io)?;
    drop(phrase);
    let paths = paths_for(&base, session.vault_id());
    let meta = LocalMeta {
        device_id: session.origin_device(),
        client_id,
        created_at_ms: unix_ms(),
        name,
        seen: None,
        prefs: None,
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
