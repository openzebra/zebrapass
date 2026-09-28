//! Unlock: read the file (bounded), open it through `session::unlock`, then
//! apply this device's rollback cursor before anything is shown.
//!
//! The cursor lives in `local.meta`, sealed under a key derived from the vault
//! key, so it can only be read after the vault key is unwrapped. The session
//! is checked with `session::check_seen` and dropped on any mismatch; no
//! record is decrypted before that check passes.

use std::path::Path;

use local::{load_local_meta, mark_seen, LocalMeta, Paths};
use seed::SeedPhrase;
use session::{
    check_seen, unlock, wrap_directory, Seen, Session, UnlockCreds, VaultFile, WrapDirectory,
};
use zeroize::Zeroizing;

use crate::vault::chip::Chips;
use crate::vault::error::UnlockError;
use crate::vault::limits::MAX_VAULT_FILE;

/// An unlocked vault and everything that must die with it.
pub struct Vault {
    /// Keys and the decrypted frame log (wiped on drop).
    pub session: Session,
    /// The container bytes this session last wrote or opened.
    pub file: VaultFile,
    /// This device's metadata, including the rollback cursor.
    pub meta: LocalMeta,
    /// Where the files live.
    pub paths: Paths,
    /// Public wrap directory of `file`.
    pub directory: WrapDirectory,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("generation", &self.session.generation())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Write the file atomically, then advance the rollback cursor, then
    /// refresh the directory view. Call after every mutation.
    ///
    /// # Errors
    ///
    /// Storage errors from `local` (`write failed`, `rename failed`, ...).
    pub fn persist(&mut self) -> anyhow::Result<()> {
        local::write_atomic(&self.paths.vault_file, self.file.as_bytes())?;
        mark_seen(&self.paths, &mut self.meta, &self.session)?;
        self.directory = wrap_directory(&self.file)?;
        Ok(())
    }

    /// Refuse a phrase that is not this vault's. Compares the phrase's
    /// client id with the one recorded at create/restore, in constant time.
    /// A rotation re-seals the recovery wrap from the phrase, so a typo here
    /// must never reach the core.
    ///
    /// # Errors
    ///
    /// `phrase does not match this vault`.
    pub fn check_phrase(&self, phrase: &SeedPhrase) -> anyhow::Result<()> {
        use subtle::ConstantTimeEq;
        let candidate = Zeroizing::new(kdf::client_id(phrase.seed())?);
        if bool::from(candidate.as_slice().ct_eq(self.meta.client_id.as_slice())) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("phrase does not match this vault"))
        }
    }

    /// Display name, or a short id when the vault has none.
    #[must_use]
    pub fn label(&self) -> String {
        if self.meta.name.is_empty() {
            String::from("Vault")
        } else {
            self.meta.name.clone()
        }
    }
}

/// A factor presented at the unlock screen.
pub enum Credential {
    /// The human password.
    Password(Zeroizing<Vec<u8>>),
    /// The recovery phrase.
    Phrase(Box<SeedPhrase>),
    /// This process's development chip key.
    #[cfg(feature = "dev-chip")]
    Chip,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}

/// Read a vault file, refusing anything larger than [`MAX_VAULT_FILE`]
/// before allocating.
///
/// # Errors
///
/// [`UnlockError::Io`] when the file cannot be read, [`UnlockError::NotAVault`]
/// when it is too large.
pub fn read_vault_file(path: &Path) -> Result<VaultFile, UnlockError> {
    let len = std::fs::metadata(path).map_err(|_| UnlockError::Io)?.len();
    if len > MAX_VAULT_FILE {
        return Err(UnlockError::NotAVault);
    }
    std::fs::read(path)
        .map(VaultFile::new)
        .map_err(|_| UnlockError::Io)
}

/// Read the public wrap directory of a vault file.
///
/// # Errors
///
/// As [`read_vault_file`]; [`UnlockError::NotAVault`] when it does not parse.
pub fn read_directory(path: &Path) -> Result<WrapDirectory, UnlockError> {
    let file = read_vault_file(path)?;
    wrap_directory(&file).map_err(|_| UnlockError::NotAVault)
}

/// Unlock the vault at `paths` with `credential`. Runs the full unlock on
/// every attempt; the only early exits are storage failures.
///
/// # Errors
///
/// An [`UnlockError`]; authentication failures are all
/// [`UnlockError::Denied`].
pub fn unlock_vault(
    paths: Paths,
    credential: Credential,
    chips: &Chips,
) -> Result<Box<Vault>, UnlockError> {
    let file = read_vault_file(&paths.vault_file)?;
    let opened = match &credential {
        Credential::Password(password) => {
            unlock(&file, &UnlockCreds::default().with_human(password), None)
        }
        Credential::Phrase(phrase) => unlock(&file, &UnlockCreds::master(phrase.seed()), None),
        #[cfg(feature = "dev-chip")]
        Credential::Chip => chips.unlock(&file),
    };
    #[cfg(not(feature = "dev-chip"))]
    let _ = chips;
    drop(credential);
    let session = opened.map_err(|error| UnlockError::from(&error))?;
    finish_open(file, session, paths)
}

/// Apply the rollback cursor and hand back the vault.
fn finish_open(file: VaultFile, session: Session, paths: Paths) -> Result<Box<Vault>, UnlockError> {
    let key = session.local_meta_key().map_err(|_| UnlockError::Io)?;
    let mut meta =
        load_local_meta(&paths.local_meta, &key).map_err(|_| UnlockError::MetaMissing)?;
    let seen = meta.seen.map(|cursor| Seen {
        generation: cursor.generation,
        commit_tag: cursor.commit_tag,
    });
    if let Err(error) = check_seen(&session, seen) {
        let disk = session.generation();
        drop(session);
        return Err(match UnlockError::from(&error) {
            UnlockError::Rollback { .. } => UnlockError::Rollback {
                seen: seen.map_or(0, |cursor| cursor.generation),
                disk,
            },
            UnlockError::Conflict { .. } => UnlockError::Conflict { generation: disk },
            other => other,
        });
    }
    mark_seen(&paths, &mut meta, &session).map_err(|_| UnlockError::Io)?;
    let directory = wrap_directory(&file).map_err(|_| UnlockError::NotAVault)?;
    Ok(Box::new(Vault {
        session,
        file,
        meta,
        paths,
        directory,
    }))
}
