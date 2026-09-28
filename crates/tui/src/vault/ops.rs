//! Every mutation of an unlocked vault, run on the worker thread.
//!
//! Each op calls the core, then [`Vault::persist`] writes the file and
//! advances the rollback cursor. The vault moves into the worker and back;
//! it is never cloned.

use std::path::PathBuf;

use record::{Document, TAG_PASSWORD};
use seed::SeedPhrase;
use session::{
    clear_history, delete_record, drop_recovery_wrap, remove_chip_unlock, remove_device,
    remove_prf_unlock, restore_revision, revoke, rotate_vault_key, unlock, write_record,
    KdfProfile, Revoke, RotateCreds, UnlockCreds,
};
use zeroize::Zeroizing;

use crate::secure::health::{analyze, Candidate, HealthReport};
use crate::vault::chip::Chips;
use crate::vault::create::{add_password, unix_ms};
use crate::vault::factors::{presence, FactorKind};
use crate::vault::open::Vault;
use crate::vault::sync::{export, import, ExportReport, ImportReport};

/// A wrap addressed by kind and id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorRef {
    /// Device wrap.
    Device([u8; 16]),
    /// Chip wrap.
    Chip([u8; 16]),
    /// Hardware-key wrap.
    HwKey([u8; 16]),
}

/// A vault-key rotation, optionally revoking one factor and/or changing the
/// password.
pub struct Rotation {
    /// The recovery phrase (seals the new recovery wrap).
    pub phrase: Box<SeedPhrase>,
    /// The current password, when the vault has one.
    pub current: Option<Zeroizing<Vec<u8>>>,
    /// A new password to seal instead of the current one.
    pub new_password: Option<Zeroizing<Vec<u8>>>,
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
    /// Add the password factor.
    AddPassword(Zeroizing<Vec<u8>>, KdfProfile),
    /// Add a development chip factor.
    #[cfg(feature = "dev-chip")]
    AddChip,
    /// Drop one wrap without rotating the vault key.
    RemoveWrap(FactorRef),
    /// Rotate the vault key.
    Rotate(Box<Rotation>),
    /// Drop the recovery wrap from this copy.
    DropRecovery,
    /// Analyze password health.
    Health,
    /// Export signed frames.
    Export(Box<SeedPhrase>, Box<[u32]>, PathBuf),
    /// Import signed frames.
    Import(Box<SeedPhrase>, PathBuf),
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
    /// A factor was added.
    FactorAdded(FactorKind),
    /// A wrap was removed.
    FactorRemoved,
    /// The vault key rotated.
    Rotated {
        /// A factor was revoked.
        revoked: bool,
        /// The password changed.
        password_changed: bool,
    },
    /// The recovery wrap is gone from this copy.
    RecoveryDropped,
    /// Health analysis.
    Health(Box<HealthReport>),
    /// Frames exported.
    Exported(Box<ExportReport>),
    /// Frames imported.
    Imported(Box<ImportReport>),
}

/// Run `op` on `vault`.
///
/// # Errors
///
/// Core and storage errors; on error the core leaves the vault unchanged.
pub fn apply(vault: &mut Vault, op: Op, chips: &Chips) -> anyhow::Result<Outcome> {
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
        Op::AddPassword(password, profile) => {
            if presence(&vault.directory, chips).password {
                anyhow::bail!("this vault already has a password factor");
            }
            add_password(&mut vault.session, &mut vault.file, &password, profile)?;
            Outcome::FactorAdded(FactorKind::Password)
        }
        #[cfg(feature = "dev-chip")]
        Op::AddChip => {
            chips.enroll(&mut vault.session, &mut vault.file)?;
            Outcome::FactorAdded(FactorKind::Chip)
        }
        Op::RemoveWrap(factor) => {
            match factor {
                FactorRef::Device(id) => remove_device(&mut vault.session, &mut vault.file, &id)?,
                FactorRef::Chip(id) => {
                    remove_chip_unlock(&mut vault.session, &mut vault.file, &id)?;
                    chips.forget(&id);
                }
                FactorRef::HwKey(id) => {
                    remove_prf_unlock(&mut vault.session, &mut vault.file, &id)?;
                }
            }
            Outcome::FactorRemoved
        }
        Op::Rotate(rotation) => rotate(vault, &rotation, chips)?,
        Op::DropRecovery => {
            drop_recovery_wrap(&mut vault.session, &mut vault.file)?;
            Outcome::RecoveryDropped
        }
        Op::Health => return Ok(Outcome::Health(Box::new(health(vault)?))),
        Op::Export(phrase, ids, path) => {
            return Ok(Outcome::Exported(Box::new(export(
                vault, &phrase, &ids, &path,
            )?)))
        }
        Op::Import(phrase, path) => {
            return Ok(Outcome::Imported(Box::new(import(vault, &phrase, &path)?)))
        }
    };
    vault.persist()?;
    Ok(outcome)
}

fn rotate(vault: &mut Vault, rotation: &Rotation, chips: &Chips) -> anyhow::Result<Outcome> {
    vault.check_phrase(&rotation.phrase)?;
    let has_password = presence(&vault.directory, chips).password;
    if has_password {
        let current = rotation
            .current
            .as_deref()
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow::anyhow!("the current password is needed"))?;
        // A wrong current password would otherwise be sealed as the new one.
        unlock(
            &vault.file,
            &UnlockCreds::default().with_human(current),
            None,
        )
        .map_err(|_| anyhow::anyhow!("the current password is not correct"))?;
    }
    let human: Option<&[u8]> = rotation
        .new_password
        .as_deref()
        .or(rotation.current.as_deref())
        .map(Vec::as_slice)
        .filter(|_| has_password);
    let skip = match rotation.revoke {
        Some(FactorRef::Chip(id)) => Some(id),
        Some(FactorRef::Device(_) | FactorRef::HwKey(_)) | None => None,
    };
    let material = chips.rotation_material(&vault.directory, skip)?;
    let creds = RotateCreds {
        master: rotation.phrase.seed(),
        devices: &[],
        chips: material.as_slice(),
        prfs: &[],
        human_password: human,
    };
    match rotation.revoke {
        Some(FactorRef::Device(id)) => revoke(
            &mut vault.session,
            &mut vault.file,
            &Revoke::Device(&id),
            &creds,
        )?,
        Some(FactorRef::Chip(id)) => {
            revoke(
                &mut vault.session,
                &mut vault.file,
                &Revoke::Chip(&id),
                &creds,
            )?;
            chips.forget(&id);
        }
        Some(FactorRef::HwKey(id)) => revoke(
            &mut vault.session,
            &mut vault.file,
            &Revoke::Prf(&id),
            &creds,
        )?,
        None => rotate_vault_key(&mut vault.session, &mut vault.file, &creds)?,
    }
    Ok(Outcome::Rotated {
        revoked: rotation.revoke.is_some(),
        password_changed: rotation.new_password.is_some() && has_password,
    })
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
