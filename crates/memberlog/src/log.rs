//! The member list and the rules for changing it.
//!
//! The log is replayed from its first entry. The first entry creates the
//! vault: its signer's own account becomes the first owner, certified under
//! the root key the entry itself carries. That entry's hash is the trust
//! anchor, handed to every invitee, so nobody can substitute another log.
//! Every later entry must chain to the one before it and be signed by a
//! device of a current owner (or by a member removing itself).

use anyhow::{anyhow, Result};
use pq::{sync_verify, MEMBER_LOG_CTX, SYNC_VK_LEN};
use secret::ct_eq_32;
use session::{DeviceCert, DeviceSignKey};

use crate::entry::{sign_entry, Action, Entry};
use crate::role::Role;

/// Most entries one log holds; it bounds both storage and replay time.
pub const MAX_ENTRIES: usize = 1024;

/// Most members of one shared vault.
pub const MAX_MEMBERS: usize = 64;

fn rejected() -> anyhow::Error {
    anyhow!("member log rejected")
}

/// One member account of a shared vault.
#[derive(Debug, Eq, PartialEq)]
pub struct Member {
    /// The account id every certificate of this member carries.
    pub client_id: [u8; 64],
    /// The root key those certificates chain to.
    pub root_vk: Box<[u8; SYNC_VK_LEN]>,
    /// What the member may do.
    pub role: Role,
}

/// A verified member log and the member list it yields.
#[derive(Debug)]
pub struct MemberLog {
    vault_id: [u8; 16],
    entries: Vec<Entry>,
    members: Vec<Member>,
    head: [u8; 32],
    anchor: [u8; 32],
    rotations: Vec<[u8; 32]>,
}

impl MemberLog {
    /// Start a log: the creating device's account becomes the first owner.
    ///
    /// # Errors
    ///
    /// Signing failure, or a certificate that does not chain to `root_vk`.
    pub fn genesis(
        vault_id: [u8; 16],
        key: &DeviceSignKey,
        cert: &DeviceCert,
        root_vk: &[u8; SYNC_VK_LEN],
        at_ms: u64,
    ) -> Result<Self> {
        let entry = sign_entry(
            key,
            Entry {
                vault_id,
                seq: 0,
                prev_hash: [0u8; 32],
                at_ms,
                action: Action::Add {
                    client_id: cert.client_id,
                    root_vk: Box::new(*root_vk),
                    role: Role::Owner,
                },
                signer: cert.clone(),
                signature: Vec::new(),
            },
        )?;
        let anchor = entry.hash()?;
        Self::from_entries(vault_id, &[entry], &anchor)
    }

    /// Verify and replay `entries` from the first one.
    ///
    /// # Errors
    ///
    /// `member log rejected` when the first entry is not the one with hash
    /// `anchor`, or any entry fails [`MemberLog::append`]'s checks.
    pub fn from_entries(vault_id: [u8; 16], entries: &[Entry], anchor: &[u8; 32]) -> Result<Self> {
        let (first, rest) = entries.split_first().ok_or_else(rejected)?;
        if !ct_eq_32(&first.hash()?, anchor) {
            return Err(rejected());
        }
        let mut log = Self::from_genesis(vault_id, first)?;
        for entry in rest {
            log.append(entry.clone())?;
        }
        Ok(log)
    }

    fn from_genesis(vault_id: [u8; 16], entry: &Entry) -> Result<Self> {
        let Action::Add {
            client_id,
            root_vk,
            role: Role::Owner,
        } = &entry.action
        else {
            return Err(rejected());
        };
        let shape = entry.vault_id == vault_id
            && entry.seq == 0
            && entry.prev_hash == [0u8; 32]
            && entry.signer.client_id == *client_id;
        if !shape {
            return Err(rejected());
        }
        verify_signature(entry, &entry.signer, root_vk)?;
        let head = entry.hash()?;
        Ok(Self {
            vault_id,
            entries: vec![entry.clone()],
            members: vec![Member {
                client_id: *client_id,
                root_vk: root_vk.clone(),
                role: Role::Owner,
            }],
            head,
            anchor: head,
            rotations: Vec::new(),
        })
    }

    /// Append the next entry after checking everything about it.
    ///
    /// An entry already in the log is accepted again without effect.
    ///
    /// # Errors
    ///
    /// `member log fork` for a different entry at a known position;
    /// `member log gap` for a position past the head; `member log rejected`
    /// for a broken chain, a signer who may not do this, a certificate that
    /// does not verify, or a change that breaks a rule (an unknown or
    /// duplicate member, the last owner leaving, a full log).
    pub fn append(&mut self, entry: Entry) -> Result<()> {
        let known = usize::try_from(entry.seq)
            .ok()
            .and_then(|at| self.entries.get(at));
        if let Some(existing) = known {
            return if existing.hash()? == entry.hash()? {
                Ok(())
            } else {
                Err(anyhow!("member log fork"))
            };
        }
        if usize::try_from(entry.seq).map_or(true, |seq| seq > self.entries.len()) {
            return Err(anyhow!("member log gap"));
        }
        if self.entries.len() >= MAX_ENTRIES
            || entry.vault_id != self.vault_id
            || !ct_eq_32(&entry.prev_hash, &self.head)
        {
            return Err(rejected());
        }
        let signer = self.member(&entry.signer.client_id).ok_or_else(rejected)?;
        verify_signature(&entry, &entry.signer, &signer.root_vk)?;
        Self::check_authority(&entry, signer.role)?;
        let head = entry.hash()?;
        self.apply(&entry.action)?;
        self.entries.push(entry);
        self.head = head;
        Ok(())
    }

    /// Verify and append every entry of `entries`, in order.
    ///
    /// # Errors
    ///
    /// The first error of [`MemberLog::append`].
    pub fn merge(&mut self, entries: &[Entry]) -> Result<()> {
        entries
            .iter()
            .try_for_each(|entry| self.append(entry.clone()))
    }

    /// Build and sign the next entry; it is not appended until it is passed
    /// to [`MemberLog::append`], so a peer can be handed it first.
    ///
    /// # Errors
    ///
    /// Signing failure.
    pub fn propose(
        &self,
        key: &DeviceSignKey,
        cert: &DeviceCert,
        action: Action,
        at_ms: u64,
    ) -> Result<Entry> {
        sign_entry(
            key,
            Entry {
                vault_id: self.vault_id,
                seq: u64::try_from(self.entries.len())?,
                prev_hash: self.head,
                at_ms,
                action,
                signer: cert.clone(),
                signature: Vec::new(),
            },
        )
    }

    /// Who may do what. An owner's removal and every rotation must commit to
    /// the new seed; a member leaving by itself cannot rotate, so it commits
    /// to nothing and an owner rotates afterwards.
    fn check_authority(entry: &Entry, role: Role) -> Result<()> {
        let commits = entry.action.commit() != [0u8; 32];
        let allowed = match &entry.action {
            Action::Remove { client_id, .. } => {
                let leaving = *client_id == entry.signer.client_id;
                if role.can_manage() {
                    commits
                } else {
                    leaving && !commits
                }
            }
            Action::Rotate { .. } => role.can_manage() && commits,
            Action::Add { .. } | Action::SetRole { .. } => role.can_manage(),
        };
        if allowed {
            Ok(())
        } else {
            Err(rejected())
        }
    }

    fn apply(&mut self, action: &Action) -> Result<()> {
        let owners = self
            .members
            .iter()
            .filter(|member| member.role == Role::Owner)
            .count();
        match action {
            Action::Add {
                client_id,
                root_vk,
                role,
            } => {
                if self.member(client_id).is_some() || self.members.len() >= MAX_MEMBERS {
                    return Err(rejected());
                }
                self.members.push(Member {
                    client_id: *client_id,
                    root_vk: root_vk.clone(),
                    role: *role,
                });
            }
            Action::Remove { client_id, commit } => {
                let target = self.member(client_id).ok_or_else(rejected)?;
                if target.role == Role::Owner && owners <= 1 {
                    return Err(rejected());
                }
                self.members.retain(|member| member.client_id != *client_id);
                if *commit != [0u8; 32] {
                    self.rotations.push(*commit);
                }
            }
            Action::Rotate { commit } => self.rotations.push(*commit),
            Action::SetRole { client_id, role } => {
                let last_owner = owners <= 1;
                let target = self
                    .members
                    .iter_mut()
                    .find(|member| member.client_id == *client_id)
                    .ok_or_else(rejected)?;
                if target.role == Role::Owner && *role != Role::Owner && last_owner {
                    return Err(rejected());
                }
                target.role = *role;
            }
        }
        Ok(())
    }

    fn member(&self, client_id: &[u8; 64]) -> Option<&Member> {
        self.members
            .iter()
            .find(|member| member.client_id == *client_id)
    }

    /// The shared vault this log belongs to.
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// Current members.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The role of `client_id`, if it is a member.
    #[must_use]
    pub fn role_of(&self, client_id: &[u8; 64]) -> Option<Role> {
        self.member(client_id).map(|member| member.role)
    }

    /// Whether `client_id` is a member who may write records.
    #[must_use]
    pub fn may_write(&self, client_id: &[u8; 64]) -> bool {
        self.role_of(client_id).is_some_and(Role::can_write)
    }

    /// How many times the shared seed has been replaced: the number of
    /// removals by owners and rotations in the log. A device whose seed is
    /// from an earlier epoch is behind and has to fetch the new one.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        u32::try_from(self.rotations.len()).unwrap_or(u32::MAX)
    }

    /// How many members have left on their own since the seed was last
    /// replaced. A leave carries no new seed, so until an owner replaces it
    /// the people who left still hold the one in use.
    #[must_use]
    pub fn leaves_since_rotation(&self) -> usize {
        self.entries.iter().fold(0, |leaves, entry| {
            let own_exit = matches!(
                &entry.action,
                Action::Remove { client_id, .. } if *client_id == entry.signer.client_id
            );
            if entry.action.commit() == [0u8; 32] {
                leaves + usize::from(own_exit)
            } else {
                0
            }
        })
    }

    /// The commitment to the seed of `epoch` (1 is the first replacement).
    #[must_use]
    pub fn commit_for(&self, epoch: u32) -> Option<&[u8; 32]> {
        usize::try_from(epoch)
            .ok()
            .and_then(|at| at.checked_sub(1))
            .and_then(|at| self.rotations.get(at))
    }

    /// Every account that held a writing role at some point, with its root
    /// key, removed members included: the accounts whose signed records the
    /// vault may legitimately hold.
    #[must_use]
    pub fn past_writers(&self) -> Vec<(&[u8; 64], &[u8; SYNC_VK_LEN])> {
        let keys: Vec<(&[u8; 64], &[u8; SYNC_VK_LEN])> = self
            .entries
            .iter()
            .filter_map(|entry| match &entry.action {
                Action::Add {
                    client_id, root_vk, ..
                } => Some((client_id, &**root_vk)),
                Action::Remove { .. } | Action::SetRole { .. } | Action::Rotate { .. } => None,
            })
            .collect();
        let mut writers: Vec<&[u8; 64]> = self
            .entries
            .iter()
            .filter_map(|entry| match &entry.action {
                Action::Add {
                    client_id, role, ..
                }
                | Action::SetRole { client_id, role } => role.can_write().then_some(client_id),
                Action::Remove { .. } | Action::Rotate { .. } => None,
            })
            .collect();
        writers.sort_unstable();
        writers.dedup();
        writers
            .into_iter()
            .filter_map(|id| keys.iter().find(|(known, _)| *known == id).copied())
            .collect()
    }

    /// The hash of the latest entry.
    #[must_use]
    pub const fn head(&self) -> &[u8; 32] {
        &self.head
    }

    /// The hash of the first entry: the trust anchor.
    #[must_use]
    pub const fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }

    /// Every entry, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

fn verify_signature(entry: &Entry, signer: &DeviceCert, root_vk: &[u8; SYNC_VK_LEN]) -> Result<()> {
    signer
        .verify(root_vk, entry.at_ms)
        .map_err(|_| rejected())?;
    let message = entry.signed_message().map_err(|_| rejected())?;
    sync_verify(
        &signer.device_vk,
        MEMBER_LOG_CTX,
        &message,
        &entry.signature,
    )
    .map_err(|_| rejected())
}
