//! Every mutation of an unlocked vault, run on the worker thread.
//!
//! Each op calls the core, then [`Vault::persist`] writes the file and
//! advances the rollback cursor. The vault moves into the worker and back;
//! it is never cloned.

use local::Prefs;
use record::{Document, TAG_PASSWORD};
use seed::SeedPhrase;
use session::{
    clear_history, delete_record, drop_recovery_wrap, remove_chip_unlock, remove_human_password,
    remove_prf_unlock, replace_human_password, restore_revision, revoke, rotate_vault_key, unlock,
    write_record, Factor, KdfProfile, Revoke, RotateCreds, UnlockCreds,
};
use zeroize::Zeroizing;

use crate::secure::health::{analyze, Candidate, HealthReport};
use crate::vault::create::{add_password, password_publics, unix_ms};
use crate::vault::device;
use crate::vault::factors::{presence, FactorKind};
use crate::vault::open::Vault;

/// A wrap addressed by kind and id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorRef {
    /// Device wrap.
    Device([u8; 16]),
    /// Hardware-key wrap.
    HwKey([u8; 16]),
}

/// A vault-key rotation, optionally revoking one factor.
pub struct Rotation {
    /// The recovery phrase (seals the new recovery wrap).
    pub phrase: Box<SeedPhrase>,
    /// The current password, when the vault has one.
    pub current: Option<Zeroizing<Vec<u8>>>,
    /// The factor to revoke.
    pub revoke: Option<FactorRef>,
}

impl std::fmt::Debug for Rotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rotation")
            .field("revoke", &self.revoke)
            .finish_non_exhaustive()
    }
}

/// A mutation.
pub enum Op {
    /// Write a new revision (or a new record when `id` is `None`).
    Write {
        /// Record id.
        id: Option<u32>,
        /// Full document.
        doc: Box<Document>,
    },
    /// Tombstone a record.
    Delete(u32),
    /// Copy an old revision into a new one.
    RestoreRevision(u32, u64),
    /// Drop superseded revisions.
    ClearHistory,
    /// Rename the vault on this device.
    Rename(String),
    /// Save this device's preferences for the vault.
    SavePrefs(Box<Prefs>),
    /// Add the password factor.
    AddPassword(Zeroizing<Vec<u8>>, KdfProfile),
    /// Replace the password wrap; the vault key stays.
    ChangePassword {
        /// The password that opens the vault now.
        current: Zeroizing<Vec<u8>>,
        /// Its replacement.
        new: Zeroizing<Vec<u8>>,
    },
    /// Drop the password wrap.
    RemovePassword,
    /// Add this device's factor, its key file sealed under this PIN.
    AddDevice(Zeroizing<Vec<u8>>, KdfProfile),
    /// Re-seal this device's key file under a new PIN.
    ChangePin {
        /// The PIN that opens the key file now.
        current: Zeroizing<Vec<u8>>,
        /// Its replacement.
        new: Zeroizing<Vec<u8>>,
        /// Argon2id preset the new PIN is stretched with.
        profile: KdfProfile,
    },
    /// Drop one wrap without rotating the vault key.
    RemoveWrap(FactorRef),
    /// Rotate the vault key.
    Rotate(Box<Rotation>),
    /// Drop the recovery wrap from this copy.
    DropRecovery,
    /// Analyze password health.
    Health,
    /// Add reviewed records from another manager, skipping duplicates.
    Import(Vec<Document>),
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Op([REDACTED])")
    }
}

/// What a successful op did.
#[derive(Debug)]
pub enum Outcome {
    /// Record written.
    Saved(u32),
    /// Record deleted.
    Deleted(u32),
    /// Revision restored as a new revision.
    Restored(u32, u64),
    /// History compacted.
    HistoryCleared,
    /// Vault renamed.
    Renamed,
    /// Preferences saved.
    PrefsSaved,
    /// A factor was added.
    FactorAdded(FactorKind),
    /// A wrap was removed.
    FactorRemoved,
    /// The vault key rotated; `true` when a factor was revoked.
    Rotated(bool),
    /// The password wrap was replaced.
    PasswordChanged,
    /// The device key file was re-sealed.
    PinChanged,
    /// The recovery wrap is gone from this copy.
    RecoveryDropped,
    /// Health analysis.
    Health(Box<HealthReport>),
    /// Records imported.
    Imported(import::Merged),
}

/// Run `op` on `vault`.
///
/// # Errors
///
/// Core and storage errors; on error the core leaves the vault unchanged.
pub fn apply(vault: &mut Vault, op: Op) -> anyhow::Result<Outcome> {
    let outcome = match op {
        Op::Write { id, doc } => {
            Outcome::Saved(write_record(&mut vault.session, &mut vault.file, id, &doc)?)
        }
        Op::Delete(id) => {
            delete_record(&mut vault.session, &mut vault.file, id)?;
            Outcome::Deleted(id)
        }
        Op::RestoreRevision(id, revision) => {
            let new = restore_revision(&mut vault.session, &mut vault.file, id, revision)?;
            Outcome::Restored(id, new)
        }
        Op::ClearHistory => {
            clear_history(&mut vault.session, &mut vault.file)?;
            Outcome::HistoryCleared
        }
        Op::Rename(name) => {
            vault.meta.name = name;
            Outcome::Renamed
        }
        Op::SavePrefs(prefs) => {
            vault.meta.prefs = Some(*prefs);
            Outcome::PrefsSaved
        }
        Op::AddPassword(password, profile) => {
            if presence(&vault.directory, device::owned_id(&vault.paths)).password {
                anyhow::bail!("this vault already has a password factor");
            }
            add_password(&mut vault.session, &mut vault.file, &password, profile)?;
            Outcome::FactorAdded(FactorKind::Password)
        }
        Op::ChangePassword { current, new } => change_password(vault, &current, &new)?,
        Op::RemovePassword => {
            remove_human_password(&mut vault.session, &mut vault.file)?;
            Outcome::FactorRemoved
        }
        Op::AddDevice(pin, profile) => {
            if presence(&vault.directory, device::owned_id(&vault.paths)).owned_devices > 0 {
                anyhow::bail!("this device is already enrolled");
            }
            device::enroll(
                &mut vault.session,
                &mut vault.file,
                &vault.paths,
                &pin,
                profile,
            )?;
            Outcome::FactorAdded(FactorKind::Device)
        }
        Op::ChangePin {
            current,
            new,
            profile,
        } => {
            device::change_pin(
                &vault.paths,
                vault.session.vault_id(),
                &current,
                &new,
                profile,
            )?;
            Outcome::PinChanged
        }
        Op::RemoveWrap(factor) => {
            match factor {
                FactorRef::Device(id) => {
                    remove_chip_unlock(&mut vault.session, &mut vault.file, &id)?;
                    device::forget(&vault.paths, &id);
                }
                FactorRef::HwKey(id) => {
                    remove_prf_unlock(&mut vault.session, &mut vault.file, &id)?;
                }
            }
            Outcome::FactorRemoved
        }
        Op::Rotate(rotation) => rotate(vault, &rotation)?,
        Op::DropRecovery => {
            drop_recovery_wrap(&mut vault.session, &mut vault.file)?;
            Outcome::RecoveryDropped
        }
        Op::Health => return Ok(Outcome::Health(Box::new(health(vault)?))),
        Op::Import(records) => Outcome::Imported(import::into_session(
            &mut vault.session,
            &mut vault.file,
            records,
        )?),
    };
    vault.persist()?;
    Ok(outcome)
}

/// Replace the password wrap after checking the current password; the
/// Argon2id cost stays.
fn change_password(vault: &mut Vault, current: &[u8], new: &[u8]) -> anyhow::Result<Outcome> {
    check_password(vault, current)?;
    let cost = vault
        .directory
        .factors
        .iter()
        .find_map(|factor| match factor {
            Factor::Password { m_kib, t, p } => Some((*m_kib, *t, *p)),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("this vault has no password factor"))?;
    let publics = password_publics(new, cost)?;
    replace_human_password(&mut vault.session, &mut vault.file, &publics)?;
    Ok(Outcome::PasswordChanged)
}

fn rotate(vault: &mut Vault, rotation: &Rotation) -> anyhow::Result<Outcome> {
    vault.check_phrase(&rotation.phrase)?;
    let has_password = presence(&vault.directory, device::owned_id(&vault.paths)).password;
    if has_password {
        let current = rotation
            .current
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("the current password is needed"))?;
        check_password(vault, current)?;
    }
    let human: Option<&[u8]> = rotation
        .current
        .as_deref()
        .map(Vec::as_slice)
        .filter(|_| has_password);
    let creds = RotateCreds {
        master: rotation.phrase.seed(),
        prfs: &[],
        human_password: human,
    };
    match rotation.revoke {
        Some(FactorRef::Device(id)) => {
            revoke(
                &mut vault.session,
                &mut vault.file,
                &Revoke::Chip(&id),
                &creds,
            )?;
            device::forget(&vault.paths, &id);
        }
        Some(FactorRef::HwKey(id)) => revoke(
            &mut vault.session,
            &mut vault.file,
            &Revoke::Prf(&id),
            &creds,
        )?,
        None => rotate_vault_key(&mut vault.session, &mut vault.file, &creds)?,
    }
    Ok(Outcome::Rotated(rotation.revoke.is_some()))
}

/// A wrong current password would otherwise be re-sealed or replaced.
fn check_password(vault: &Vault, current: &[u8]) -> anyhow::Result<()> {
    unlock(
        &vault.file,
        &UnlockCreds::default().with_human(current),
        None,
    )
    .map(drop)
    .map_err(|_| anyhow::anyhow!("the current password is not correct"))
}

/// Open every record's password and analyze it. The documents stay owned
/// here (they wipe on drop); only record ids leave.
fn health(vault: &Vault) -> anyhow::Result<HealthReport> {
    let rows = session::list_records(&vault.session)?;
    let docs: Vec<(u32, u64, Option<Document>)> = rows
        .iter()
        .map(|row| {
            (
                row.id,
                row.timestamp_ms,
                session::open_record(&vault.session, row.id).ok(),
            )
        })
        .collect();
    let candidates: Vec<Candidate<'_>> = docs
        .iter()
        .map(|(id, timestamp_ms, doc)| Candidate {
            id: *id,
            timestamp_ms: *timestamp_ms,
            password: doc
                .as_ref()
                .and_then(|doc| doc.data(TAG_PASSWORD).ok().flatten()),
        })
        .collect();
    Ok(analyze(&candidates, unix_ms()))
}
