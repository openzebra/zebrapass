//! What a device does with a shared vault to keep it in step with the
//! others: say what it holds, hand out a revision with its signature, keep a
//! revision a peer sent if the signature and the role hold, and write as a
//! writer.
//!
//! Every revision that enters a vault carries an attestation by the device
//! that wrote it. A device accepts one only from an account the member log
//! lists as a writer, so a reader, a removed member or an outsider cannot add
//! to the vault even though a reader holds the vault key.

use std::collections::HashSet;

use memberlog::{Action, MemberLog, Role};
use record::Document;
use session::{
    accept_revision, attest_latest, delete_record, frontier, latest_frame, open_record,
    verify_snapshot, write_record, Accepted, Attestation, Session, SessionError, TrustedAccount,
};
use syncwire::{decode_bundle, encode_bundle, encode_frontier};

use crate::attest_store::AttestStore;
use crate::now_ms;
use crate::shared::SharedVault;
use crate::shared_ref::SharedRef;
use crate::sync_identity::SyncIdentity;

fn unavailable() -> anyhow::Error {
    anyhow::anyhow!("shared vault unavailable")
}

/// A change a writer makes.
#[derive(Debug)]
pub enum Edit {
    /// A new record, under a fresh random id.
    Create(Box<Document>),
    /// A new revision of an existing record.
    Update(u32, Box<Document>),
    /// A tombstone.
    Delete(u32),
}

/// How a node answers a revision a peer pushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Kept.
    Applied,
    /// Not newer than what this device holds.
    Stale,
    /// The sender may not write here, or its certificate does not hold.
    Refused,
    /// Malformed, or it does not describe its frame.
    Invalid,
}

/// Classify why a bundle was not accepted.
#[must_use]
pub fn verdict_of(error: &anyhow::Error) -> Verdict {
    match error.downcast_ref::<SessionError>() {
        Some(SessionError::StaleRevision) => Verdict::Stale,
        Some(
            SessionError::NotAWriter
            | SessionError::DeviceNotTrusted
            | SessionError::CertRejected
            | SessionError::CertExpired,
        ) => Verdict::Refused,
        _ => Verdict::Invalid,
    }
}

fn fresh_record_id(vault: &SharedVault) -> anyhow::Result<u32> {
    let taken: HashSet<u32> = frontier(&vault.session)?
        .into_iter()
        .map(|entry| entry.record_id)
        .collect();
    for _ in 0..32 {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes)?;
        let id = u32::from_be_bytes(bytes);
        if id != 0 && !taken.contains(&id) {
            return Ok(id);
        }
    }
    Err(anyhow::anyhow!("os entropy failed"))
}

/// Check a vault file this device did not build against the attestations
/// that came with it, and keep them. Every record's winning revision must be
/// attested by an account that was a writer in `log` at some point, removed
/// members included: their earlier records are still the vault's history.
///
/// # Errors
///
/// A record without a matching attestation, or one that does not verify; see
/// [`session::verify_snapshot`].
pub fn attested_store(
    session: &Session,
    log: &MemberLog,
    attestations: &[Attestation],
    into: AttestStore,
) -> anyhow::Result<AttestStore> {
    let accounts: Vec<TrustedAccount<'_>> = log
        .past_writers()
        .into_iter()
        .map(|(client_id, root_vk)| TrustedAccount {
            client_id: *client_id,
            root_vk,
            can_write: true,
        })
        .collect();
    verify_snapshot(session, attestations, &accounts, now_ms())?
        .into_iter()
        .try_fold(into, |mut store, attestation| {
            store.put(attestation)?;
            Ok(store)
        })
}

impl SharedVault {
    /// The attestations of every record this vault holds, as a device that
    /// takes the whole vault needs them. A revision this device wrote and
    /// never attested is attested now.
    ///
    /// # Errors
    ///
    /// A record another device wrote whose attestation was not kept; indexing,
    /// signing and storage errors.
    pub fn attestations(
        &mut self,
        reference: &SharedRef,
        identity: &SyncIdentity,
    ) -> anyhow::Result<Vec<Attestation>> {
        frontier(&self.session)?
            .into_iter()
            .map(|entry| {
                let id = entry.record_id;
                self.bundle(reference, identity, id)?
                    .ok_or_else(unavailable)?;
                self.attest.get(id).cloned().ok_or_else(unavailable)
            })
            .collect()
    }

    /// What this device may do here.
    #[must_use]
    pub fn role_of(&self, identity: &SyncIdentity) -> Option<Role> {
        let own = identity.devices().first()?;
        self.log.role_of(&own.client_id)
    }

    /// The frontier a peer compares with its own.
    ///
    /// # Errors
    ///
    /// Indexing and encoding errors.
    pub fn frontier_wire(&self) -> anyhow::Result<Vec<u8>> {
        encode_frontier(&frontier(&self.session)?)
    }

    /// The winning revision of `record_id` with its attestation, as a peer
    /// asks for it. A revision this device wrote and never attested is
    /// attested now; one written by another device is served only if its
    /// attestation was kept.
    ///
    /// # Errors
    ///
    /// Indexing, signing, storage and encoding errors.
    pub fn bundle(
        &mut self,
        reference: &SharedRef,
        identity: &SyncIdentity,
        record_id: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let Ok(frame_bytes) = latest_frame(&self.session, record_id) else {
            return Ok(None);
        };
        let header = frame::parse(&frame_bytes)?;
        let held = self.attest.get(record_id).filter(|held| {
            held.revision == header.revision && held.origin_device == header.origin_device
        });
        if let Some(held) = held {
            return Ok(Some(encode_bundle(held, &frame_bytes)?));
        }
        let own = identity.devices().first().ok_or_else(unavailable)?;
        if header.origin_device != own.device_id {
            return Ok(None);
        }
        let (attestation, frame_bytes) =
            attest_latest(&self.session, &identity.sign_key(), own, record_id)?;
        let bundle = encode_bundle(&attestation, &frame_bytes)?;
        self.attest.put(attestation)?;
        self.persist(&reference.seed)?;
        Ok(Some(bundle))
    }

    /// Keep a revision a peer sent, if its attestation holds and its writer
    /// is a writer of this vault.
    ///
    /// # Errors
    ///
    /// The reasons [`session::accept_revision`] gives, wrapped as
    /// [`SessionError`]; decoding and storage errors. See [`verdict_of`].
    pub fn accept(&mut self, reference: &SharedRef, bundle: &[u8]) -> anyhow::Result<Accepted> {
        let (attestation, frame_bytes) = decode_bundle(bundle)?;
        let accounts: Vec<TrustedAccount<'_>> = self
            .log
            .members()
            .iter()
            .map(|member| TrustedAccount {
                client_id: member.client_id,
                root_vk: &member.root_vk,
                can_write: member.role.can_write(),
            })
            .collect();
        let seen = &self.state.last_seen;
        let accepted = accept_revision(
            &mut self.session,
            &mut self.file,
            frame_bytes,
            &attestation,
            &accounts,
            now_ms(),
            |record| seen.get(record),
        )?;
        self.attest.put(attestation)?;
        // A full table only weakens replay protection for new records; the
        // frame itself is already kept and the local index still guards it.
        let _ = self
            .state
            .last_seen
            .note(accepted.record_id, accepted.revision);
        self.persist(&reference.seed)?;
        Ok(accepted)
    }

    /// Give `target` another role. Owners only; the log refuses a change
    /// that leaves the vault without an owner. The seed stays, so a person
    /// made a reader can still read, and cannot write.
    ///
    /// # Errors
    ///
    /// `only owners can change roles`, `not a member` for an account the log
    /// does not list, the log's own refusals, and signing and storage errors.
    pub fn set_role(
        &mut self,
        reference: &SharedRef,
        identity: &SyncIdentity,
        target: [u8; 64],
        role: Role,
    ) -> anyhow::Result<()> {
        let own = identity.devices().first().ok_or_else(unavailable)?;
        if self.log.role_of(&own.client_id) != Some(Role::Owner) {
            anyhow::bail!("only owners can change roles");
        }
        match self.log.role_of(&target) {
            None => anyhow::bail!("not a member"),
            Some(held) if held == role => return Ok(()),
            Some(_) => {}
        }
        let entry = self.log.propose(
            &identity.sign_key(),
            own,
            Action::SetRole {
                client_id: target,
                role,
            },
            now_ms(),
        )?;
        self.log.append(entry)?;
        self.save_log(&reference.seed)
    }

    /// Whether this account has left: the log no longer lists it.
    #[must_use]
    pub fn has_left(&self, identity: &SyncIdentity) -> bool {
        identity
            .devices()
            .first()
            .is_some_and(|own| self.log.role_of(&own.client_id).is_none())
    }

    /// Leave the vault: sign an entry that removes this account. The entry
    /// carries no new seed, so an owner still has to replace the key; until
    /// then the person keeps what they have seen. The device stays able to
    /// serve the log so the others can pick the entry up.
    ///
    /// # Errors
    ///
    /// `not a member` when the account is not listed; the log's refusal when
    /// this is the only owner; signing and storage errors.
    pub fn leave(&mut self, reference: &SharedRef, identity: &SyncIdentity) -> anyhow::Result<()> {
        let own = identity.devices().first().ok_or_else(unavailable)?;
        if self.log.role_of(&own.client_id).is_none() {
            anyhow::bail!("not a member");
        }
        let entry = self.log.propose(
            &identity.sign_key(),
            own,
            Action::Remove {
                client_id: own.client_id,
                commit: [0u8; 32],
            },
            now_ms(),
        )?;
        self.log.append(entry)?;
        self.save_log(&reference.seed)
    }

    /// Make a change as a writer: write it, sign it, remember its signature
    /// and its revision, and persist. Returns the record id.
    ///
    /// # Errors
    ///
    /// `not a writer` for a reader; `record not found` for an update of a
    /// missing record; writing, signing and storage errors.
    pub fn edit(
        &mut self,
        reference: &SharedRef,
        identity: &SyncIdentity,
        edit: Edit,
    ) -> anyhow::Result<u32> {
        if !self.role_of(identity).is_some_and(Role::can_write) {
            return Err(SessionError::NotAWriter.into());
        }
        let own = identity.devices().first().ok_or_else(unavailable)?;
        let id = match edit {
            Edit::Create(doc) => {
                let id = fresh_record_id(self)?;
                write_record(&mut self.session, &mut self.file, Some(id), &doc)?;
                id
            }
            Edit::Update(id, doc) => {
                open_record(&self.session, id)?;
                write_record(&mut self.session, &mut self.file, Some(id), &doc)?;
                id
            }
            Edit::Delete(id) => {
                delete_record(&mut self.session, &mut self.file, id)?;
                id
            }
        };
        let (attestation, _) = attest_latest(&self.session, &identity.sign_key(), own, id)?;
        let revision = attestation.revision;
        self.attest.put(attestation)?;
        self.state.last_seen.note(id, revision)?;
        self.persist(&reference.seed)?;
        Ok(id)
    }
}
