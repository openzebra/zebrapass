//! One signed membership change.

use anyhow::{anyhow, Result};
use pq::{sync_sign, MEMBER_LOG_CTX, SYNC_VK_LEN};
use session::{frame_parts, DeviceCert, DeviceSignKey};
use sha2::{Digest, Sha256};

use crate::role::Role;

const DOMAIN_ENTRY: &[u8] = b"brby/v2/member-entry";

/// A change to the member list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Add an account with its root verifying key and a role.
    Add {
        client_id: [u8; 64],
        root_vk: Box<[u8; SYNC_VK_LEN]>,
        role: Role,
    },
    /// Remove an account. An owner's removal carries the commitment to the
    /// new shared seed that replaces the one the account knew; a member
    /// leaving by itself carries none (all zero) and an owner rotates after.
    Remove {
        client_id: [u8; 64],
        commit: [u8; 32],
    },
    /// Change an account's role.
    SetRole { client_id: [u8; 64], role: Role },
    /// Replace the shared seed without removing anyone, committing to the
    /// new one. Owner only.
    Rotate { commit: [u8; 32] },
}

const NO_ACCOUNT: [u8; 64] = [0; 64];

const DOMAIN_COMMIT: &[u8] = b"brby/v2/rotation-commit";

/// What an owner signs to commit to a new shared seed.
///
/// Members accept a seed only if it hashes to the commitment of the log entry
/// that announced it, so a member cannot hand out a forked vault under a seed
/// of their choosing.
#[must_use]
pub fn rotation_commit(vault_id: &[u8; 16], epoch: u32, seed: &[u8; 64]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_COMMIT)
        .chain_update(vault_id)
        .chain_update(epoch.to_be_bytes())
        .chain_update(seed)
        .finalize()
        .into()
}

impl Action {
    /// The account the action is about.
    #[must_use]
    pub const fn client_id(&self) -> &[u8; 64] {
        match self {
            Self::Add { client_id, .. }
            | Self::Remove { client_id, .. }
            | Self::SetRole { client_id, .. } => client_id,
            Self::Rotate { .. } => &NO_ACCOUNT,
        }
    }

    pub(crate) const fn code(&self) -> u8 {
        match self {
            Self::Add { .. } => 1,
            Self::Remove { .. } => 2,
            Self::SetRole { .. } => 3,
            Self::Rotate { .. } => 4,
        }
    }

    pub(crate) fn role_code(&self) -> u8 {
        match self {
            Self::Add { role, .. } | Self::SetRole { role, .. } => u8::from(*role),
            Self::Remove { .. } | Self::Rotate { .. } => 0,
        }
    }

    /// The rotation commitment, or zeros when the action carries none.
    #[must_use]
    pub const fn commit(&self) -> [u8; 32] {
        match self {
            Self::Remove { commit, .. } | Self::Rotate { commit } => *commit,
            Self::Add { .. } | Self::SetRole { .. } => [0; 32],
        }
    }

    pub(crate) fn root_vk_bytes(&self) -> &[u8] {
        match self {
            Self::Add { root_vk, .. } => root_vk.as_slice(),
            Self::Remove { .. } | Self::SetRole { .. } | Self::Rotate { .. } => &[],
        }
    }
}

/// A signed, chained entry of the member log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// The shared vault this log belongs to.
    pub vault_id: [u8; 16],
    /// Position in the log, starting at zero.
    pub seq: u64,
    /// SHA-256 of the previous entry's wire bytes; zero for the first entry.
    pub prev_hash: [u8; 32],
    /// When the entry was signed, in unix milliseconds. Also the time the
    /// signer's certificate is checked at.
    pub at_ms: u64,
    /// The change.
    pub action: Action,
    /// Certificate of the device that signed.
    pub signer: DeviceCert,
    /// ML-DSA-65 signature over [`Entry::signed_message`].
    pub signature: Vec<u8>,
}

impl Entry {
    /// Bytes the signer signs.
    ///
    /// # Errors
    ///
    /// `sync field too long` when a part does not fit a `u16` length.
    pub fn signed_message(&self) -> Result<Vec<u8>> {
        frame_parts(&[
            DOMAIN_ENTRY,
            &self.vault_id,
            &self.seq.to_be_bytes(),
            &self.prev_hash,
            &self.at_ms.to_be_bytes(),
            &[self.action.code()],
            &[self.action.role_code()],
            self.action.client_id(),
            &self.action.commit(),
            self.action.root_vk_bytes(),
            &self.signer.device_id,
            &self.signer.serial.to_be_bytes(),
            &self.signer.client_id,
        ])
    }

    /// SHA-256 of the wire bytes: what the next entry chains to.
    ///
    /// # Errors
    ///
    /// The entry does not encode.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}

/// Sign `entry` with a device key; any existing signature is replaced.
///
/// # Errors
///
/// `member log rejected` when signing fails.
pub fn sign_entry(key: &DeviceSignKey, entry: Entry) -> Result<Entry> {
    let unsigned = Entry {
        signature: Vec::new(),
        ..entry
    };
    let message = unsigned.signed_message()?;
    let signature = sync_sign(key.seed(), MEMBER_LOG_CTX, &message)
        .map_err(|_| anyhow!("member log rejected"))?;
    Ok(Entry {
        signature,
        ..unsigned
    })
}
