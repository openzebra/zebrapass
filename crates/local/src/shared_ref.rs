//! The record a personal vault keeps for each shared vault it belongs to: the
//! vault's number, its seed and the hash of its first member log entry. It is
//! an ordinary record, so it syncs to all of the owner's devices and is
//! sealed under the personal vault's key.

use memberlog::MemberLog;
use pq::SYNC_VK_LEN;
use record::{
    Document, ValueType, SHARED_RETIRED_TAGS, TAG_SHARED_ANCHOR, TAG_SHARED_EPOCH, TAG_SHARED_HEAD,
    TAG_SHARED_HINTS, TAG_SHARED_INTRODUCER, TAG_SHARED_MARK, TAG_SHARED_RETIRED_MIN,
    TAG_SHARED_SEED, TAG_SHARED_VAULT_ID, TAG_TITLE,
};
use secret::{ct_eq_32, Secret};

use crate::limits::{SHARED_HINTS_MAX, SHARED_HINT_MAX, SHARED_NAME_MAX};

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// What an invitation proved about the member log before the log itself was
/// fetched: the hash of its newest entry and the account that invited this
/// device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Introduction {
    /// Hash of the newest log entry the inviter signed for.
    pub head: [u8; 32],
    /// The inviter's account id.
    pub inviter_id: [u8; 64],
    /// The inviter's root key.
    pub inviter_vk: Box<[u8; SYNC_VK_LEN]>,
}

impl Introduction {
    /// Whether `log` is the log the inviter signed for: it contains the head
    /// they saw, and the inviter is a member with the key they presented.
    #[must_use]
    pub fn confirms(&self, log: &MemberLog) -> bool {
        let reaches_head = log
            .entries()
            .iter()
            .any(|entry| entry.hash().is_ok_and(|hash| ct_eq_32(&hash, &self.head)));
        let inviter_listed = log
            .members()
            .iter()
            .any(|member| member.client_id == self.inviter_id && member.root_vk == self.inviter_vk);
        reaches_head && inviter_listed
    }
}

/// A shared vault this account belongs to.
#[derive(Debug)]
pub struct SharedRef {
    /// The vault's number.
    pub vault_id: [u8; 16],
    /// Hash of the first member log entry: what the log is verified against.
    pub anchor: [u8; 32],
    /// The vault's seed: unlock the vault with it.
    pub seed: Secret<[u8; 64]>,
    /// The vault's name.
    pub name: String,
    /// Where a member's device can be reached (`host:port`), best first;
    /// used to fetch the vault file and to retry after a restart.
    pub hints: Vec<String>,
    /// How many times the seed was replaced when this one became current.
    pub epoch: u32,
    /// Earlier seeds, newest first, kept to open what was sealed before a
    /// rotation reached this device.
    pub retired: Vec<Secret<[u8; 64]>>,
    /// What the invitation proved; the full member log has to reach it before
    /// the vault opens. `None` for a vault this device created.
    pub introduction: Option<Introduction>,
}

impl SharedRef {
    /// Every seed this device knows, the current one first.
    pub fn seeds(&self) -> impl Iterator<Item = &Secret<[u8; 64]>> {
        std::iter::once(&self.seed).chain(self.retired.iter())
    }

    /// An explicit copy. `SharedRef` is not `Clone`: it holds seeds, so a
    /// copy is something to ask for by name.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            vault_id: self.vault_id,
            anchor: self.anchor,
            seed: Secret::new(*self.seed.expose()),
            name: self.name.clone(),
            hints: self.hints.clone(),
            epoch: self.epoch,
            retired: self
                .retired
                .iter()
                .map(|old| Secret::new(*old.expose()))
                .collect(),
            introduction: self.introduction.clone(),
        }
    }

    /// The reference once the vault is open: the introduction has done its
    /// work and is forgotten.
    #[must_use]
    pub fn settled(&self) -> Self {
        Self {
            introduction: None,
            ..self.duplicate()
        }
    }

    /// The reference after a rotation: `seed` becomes current at `epoch`, the
    /// seed it replaces is retired (the oldest are forgotten past the
    /// bound).
    #[must_use]
    pub fn rotated(&self, seed: Secret<[u8; 64]>, epoch: u32) -> Self {
        let mut retired = Vec::with_capacity(SHARED_RETIRED_TAGS);
        retired.push(Secret::new(*self.seed.expose()));
        retired.extend(
            self.retired
                .iter()
                .take(SHARED_RETIRED_TAGS - 1)
                .map(|old| Secret::new(*old.expose())),
        );
        Self {
            vault_id: self.vault_id,
            anchor: self.anchor,
            seed,
            name: self.name.clone(),
            hints: self.hints.clone(),
            epoch,
            retired,
            introduction: self.introduction.clone(),
        }
    }

    /// The record document.
    #[must_use]
    pub fn to_document(&self) -> Document {
        let mut doc = Document::new();
        doc.set_data(TAG_SHARED_MARK, ValueType::Bytes, &[1]);
        doc.set_data(TAG_SHARED_VAULT_ID, ValueType::Bytes, &self.vault_id);
        doc.set_data(TAG_SHARED_ANCHOR, ValueType::Bytes, &self.anchor);
        doc.set_data(TAG_SHARED_SEED, ValueType::Secret, self.seed.expose());
        doc.set_text(TAG_TITLE, &self.name);
        if !self.hints.is_empty() {
            doc.set_text(TAG_SHARED_HINTS, &self.hints.join("\n"));
        }
        doc.set_data(
            TAG_SHARED_EPOCH,
            ValueType::Bytes,
            &self.epoch.to_le_bytes(),
        );
        for (old, tag) in self.retired.iter().zip(TAG_SHARED_RETIRED_MIN..) {
            doc.set_data(tag, ValueType::Secret, old.expose());
        }
        if let Some(intro) = &self.introduction {
            doc.set_data(TAG_SHARED_HEAD, ValueType::Bytes, &intro.head);
            let mut who = Vec::with_capacity(64 + SYNC_VK_LEN);
            who.extend_from_slice(&intro.inviter_id);
            who.extend_from_slice(intro.inviter_vk.as_slice());
            doc.set_data(TAG_SHARED_INTRODUCER, ValueType::Bytes, &who);
        }
        doc
    }

    /// Read a shared-vault reference out of a record; `None` when the record
    /// is not one.
    ///
    /// # Errors
    ///
    /// `corrupted length` when the record is marked but a field is missing
    /// or has the wrong size.
    pub fn from_document(doc: &Document) -> anyhow::Result<Option<Self>> {
        if doc.data(TAG_SHARED_MARK)? != Some(&[1u8][..]) {
            return Ok(None);
        }
        let vault_id = doc
            .data(TAG_SHARED_VAULT_ID)?
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(corrupted)?;
        let anchor = doc
            .data(TAG_SHARED_ANCHOR)?
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(corrupted)?;
        let raw: &[u8; 64] = doc
            .data(TAG_SHARED_SEED)?
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(corrupted)?;
        let name = doc.text(TAG_TITLE)?.unwrap_or_default();
        if name.len() > SHARED_NAME_MAX {
            return Err(corrupted());
        }
        let hints: Vec<String> = doc
            .text(TAG_SHARED_HINTS)?
            .map(|joined| joined.lines().map(str::to_owned).collect())
            .unwrap_or_default();
        if hints.len() > SHARED_HINTS_MAX
            || hints
                .iter()
                .any(|hint| hint.is_empty() || hint.len() > SHARED_HINT_MAX)
        {
            return Err(corrupted());
        }
        let mut seed = Secret::new([0u8; 64]);
        seed.expose_mut().copy_from_slice(raw);
        let epoch = doc
            .data(TAG_SHARED_EPOCH)?
            .map(|bytes| <[u8; 4]>::try_from(bytes).map_err(|_| corrupted()))
            .transpose()?
            .map_or(0, u32::from_le_bytes);
        let mut retired = Vec::new();
        for tag in (TAG_SHARED_RETIRED_MIN..).take(SHARED_RETIRED_TAGS) {
            let Some(bytes) = doc.data(tag)? else {
                break;
            };
            let bytes: &[u8; 64] = bytes.try_into().map_err(|_| corrupted())?;
            let mut old = Secret::new([0u8; 64]);
            old.expose_mut().copy_from_slice(bytes);
            retired.push(old);
        }
        let stray = (TAG_SHARED_RETIRED_MIN..)
            .take(SHARED_RETIRED_TAGS)
            .skip(retired.len())
            .any(|tag| doc.get(tag).is_some());
        if stray {
            return Err(corrupted());
        }
        let introduction = read_introduction(doc)?;
        Ok(Some(Self {
            vault_id,
            anchor,
            seed,
            name: name.to_owned(),
            hints,
            epoch,
            retired,
            introduction,
        }))
    }
}

fn read_introduction(doc: &Document) -> anyhow::Result<Option<Introduction>> {
    match (doc.data(TAG_SHARED_HEAD)?, doc.data(TAG_SHARED_INTRODUCER)?) {
        (None, None) => Ok(None),
        (Some(head), Some(who)) => {
            let (inviter_id, vk) = who.split_first_chunk::<64>().ok_or_else(corrupted)?;
            Ok(Some(Introduction {
                head: head.try_into().map_err(|_| corrupted())?,
                inviter_id: *inviter_id,
                inviter_vk: Box::new(vk.try_into().map_err(|_| corrupted())?),
            }))
        }
        _ => Err(corrupted()),
    }
}
