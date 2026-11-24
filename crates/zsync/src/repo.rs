//! Verified zero-knowledge Git-like repository state and commutative CRDT
//! delta application with self-certifying repository anchors.

use std::collections::BTreeMap;

use local::{PersonalDeviceEntry, PersonalRepoAnchor, SharedRepoProof};
use memberlog::{Entry, MemberLog};
use pq::SYNC_VK_LEN;
use secret::ct_eq;
use session::{DeviceCert, Revocation};
use syncwire::{decode_cert, decode_revocation};

use crate::auth::{now_ms, verify_head, verify_record, verify_rekey};
use crate::limits::{
    MAX_CERTS_PER_REPO, MAX_INITIAL_REVISION, MAX_MEMBERS_PER_REPO, MAX_REKEYS_PER_REPO,
    MAX_REPO_RECORDS, MAX_REVISION_STEP, MAX_REVS_PER_REPO, MAX_SAFE_REVISION,
};
use crate::wire::{RecordCommit, RepoKind, SignedHead, SignedRekey, StorageId, SyncDelta};

/// Verified encrypted state of one personal or shared repository.
#[derive(Clone, Debug)]
pub struct RepoState {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub personal_anchor: Option<PersonalRepoAnchor>,
    pub client_id: Option<[u8; 64]>,
    pub root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub shared_proof: Option<SharedRepoProof>,
    pub member_entries: Vec<Entry>,
    pub devices: BTreeMap<[u8; 16], DeviceCert>,
    pub device_keys: BTreeMap<[u8; 16], PersonalDeviceEntry>,
    pub device_keys_wire: BTreeMap<[u8; 16], Vec<u8>>,
    pub revocations: Vec<Revocation>,
    pub head: Option<SignedHead>,
    pub rekeys: BTreeMap<(u64, [u8; 16]), SignedRekey>,
    pub records: BTreeMap<u32, RecordCommit>,
}

impl RepoState {
    /// Construct an empty repository state for `(kind, storage_id)`.
    #[must_use]
    pub const fn new(kind: RepoKind, storage_id: StorageId) -> Self {
        Self {
            kind,
            storage_id,
            personal_anchor: None,
            client_id: None,
            root_vk: None,
            shared_proof: None,
            member_entries: Vec::new(),
            devices: BTreeMap::new(),
            device_keys: BTreeMap::new(),
            device_keys_wire: BTreeMap::new(),
            revocations: Vec::new(),
            head: None,
            rekeys: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }

    /// Rebuild and verify the shared member log when initialized.
    #[must_use]
    pub fn member_log(&self) -> Option<MemberLog> {
        let proof = self.shared_proof.as_ref()?;
        MemberLog::from_entries(proof.vault_id, &self.member_entries, &proof.anchor).ok()
    }

    /// Check whether `device_id` has an active, non-revoked, unexpired cert.
    #[must_use]
    pub fn active_cert(&self, device_id: &[u8; 16], now: u64) -> Option<&DeviceCert> {
        let cert = self.devices.get(device_id)?;
        if self.revocations.iter().any(|r| r.covers(cert)) {
            return None;
        }
        if cert.not_after_ms != 0 && now > cert.not_after_ms {
            return None;
        }
        Some(cert)
    }

    pub(crate) fn cert_root_vk(
        &self,
        client_id: &[u8; 64],
        log: Option<&MemberLog>,
    ) -> Option<[u8; SYNC_VK_LEN]> {
        match self.kind {
            RepoKind::Personal => {
                let expected = self.client_id.as_ref()?;
                if !ct_eq(client_id, expected) {
                    return None;
                }
                self.root_vk.as_deref().copied()
            }
            RepoKind::Shared => log.and_then(|l| {
                l.members()
                    .iter()
                    .find(|m| ct_eq(&m.client_id, client_id))
                    .map(|m| *m.root_vk)
            }),
        }
    }

    fn can_write(&self, client_id: &[u8; 64], log: Option<&MemberLog>) -> bool {
        match self.kind {
            RepoKind::Personal => {
                self.root_vk.is_some()
                    && self
                        .client_id
                        .as_ref()
                        .is_some_and(|expected| ct_eq(client_id, expected))
            }
            RepoKind::Shared => log.is_some_and(|l| l.may_write(client_id)),
        }
    }

    /// Apply a `SyncDelta` strictly verifying every anchor, certificate, member
    /// entry, revocation, and ML-DSA signature.
    ///
    /// # Errors
    ///
    /// Repo identity mismatch. Individual invalid items are rejected safely.
    pub fn apply_delta(&mut self, delta: &SyncDelta) -> anyhow::Result<(SyncDelta, bool)> {
        if delta.kind != self.kind || !ct_eq(&delta.storage_id, &self.storage_id) {
            anyhow::bail!("repository delta mismatch");
        }
        let now = now_ms();
        let mut accepted = SyncDelta::empty(self.kind, self.storage_id);
        let mut changed = false;

        if self.kind == RepoKind::Personal {
            if self.try_anchor_personal(delta, now) {
                accepted.personal_anchor =
                    self.personal_anchor.as_ref().and_then(|a| a.encode().ok());
                accepted.root_vk.clone_from(&self.root_vk);
                changed = true;
            }
        } else if self.try_merge_shared_members(delta, &mut accepted) {
            changed = true;
        }

        let log = self.member_log();

        for raw_rev in &delta.revocations {
            if self.revocations.len() >= MAX_REVS_PER_REPO {
                break;
            }
            let Ok(rev) = decode_revocation(raw_rev) else {
                continue;
            };
            let Some(rvk) = self.cert_root_vk(&rev.client_id, log.as_ref()) else {
                continue;
            };
            if rev.verify(&rvk, now).is_err() {
                continue;
            }
            let dup = self
                .revocations
                .iter()
                .any(|r| r.device_id == rev.device_id && r.serial == rev.serial);
            if !dup {
                self.devices.retain(|_, d| !rev.covers(d));
                self.device_keys.retain(|_, dk| !rev.covers(&dk.cert));
                self.device_keys_wire
                    .retain(|id, _| self.device_keys.contains_key(id));
                self.revocations.push(rev);
                accepted.revocations.push(raw_rev.clone());
                changed = true;
            }
        }

        for raw_cert in &delta.certs {
            if self.devices.len() >= MAX_CERTS_PER_REPO {
                break;
            }
            let Ok(cert) = decode_cert(raw_cert) else {
                continue;
            };
            if self.insert_verified_cert(cert, log.as_ref(), now) {
                accepted.certs.push(raw_cert.clone());
                changed = true;
            }
        }

        if self.kind == RepoKind::Shared
            && let Some(proof) = &self.shared_proof
        {
            let vault_id = proof.vault_id;
            for raw_dk in &delta.device_keys {
                if self.device_keys.len() >= MAX_CERTS_PER_REPO {
                    break;
                }
                if self.try_insert_device_key(raw_dk, &vault_id, log.as_ref(), now) {
                    accepted.device_keys.push(raw_dk.clone());
                    changed = true;
                }
            }
        }

        if let Some(head) = &delta.head
            && self.try_apply_head(head, log.as_ref(), now)
        {
            accepted.head = Some(head.clone());
            changed = true;
        }

        for rekey in &delta.rekeys {
            if self.try_apply_rekey(rekey, log.as_ref(), now) {
                accepted.rekeys.push(rekey.clone());
                changed = true;
            }
        }

        for commit in &delta.records {
            if !self.records.contains_key(&commit.ver.record_id)
                && self.records.len() >= MAX_REPO_RECORDS
            {
                continue;
            }
            if self.try_apply_record(commit, log.as_ref(), now) {
                accepted.records.push(commit.clone());
                changed = true;
            }
        }

        Ok((accepted, changed))
    }

    fn try_anchor_personal(&mut self, delta: &SyncDelta, now: u64) -> bool {
        if self.root_vk.is_some() {
            return false;
        }
        let (Some(raw_anchor), Some(candidate_vk)) =
            (delta.personal_anchor.as_deref(), delta.root_vk.as_deref())
        else {
            return false;
        };
        let Ok(anchor) = PersonalRepoAnchor::decode(raw_anchor) else {
            return false;
        };
        for raw_cert in &delta.certs {
            let Ok(cert) = decode_cert(raw_cert) else {
                continue;
            };
            if anchor
                .verify(&self.storage_id, &cert.client_id, candidate_vk)
                .is_ok()
                && cert.verify(candidate_vk, now).is_ok()
            {
                self.personal_anchor = Some(anchor);
                self.client_id = Some(cert.client_id);
                self.root_vk = Some(Box::new(*candidate_vk));
                return true;
            }
        }
        false
    }

    fn try_merge_shared_members(&mut self, delta: &SyncDelta, accepted: &mut SyncDelta) -> bool {
        if self.shared_proof.is_none() {
            let (Some(raw_proof), false) = (
                delta.shared_proof.as_deref(),
                delta.member_entries.is_empty(),
            ) else {
                return false;
            };
            let Ok(proof) = SharedRepoProof::decode(raw_proof) else {
                return false;
            };
            if proof.verify(&self.storage_id).is_err() {
                return false;
            }
            let decoded: Vec<Entry> = delta
                .member_entries
                .iter()
                .take(MAX_MEMBERS_PER_REPO)
                .filter_map(|raw| Entry::decode(raw).ok())
                .collect();
            if MemberLog::from_entries(proof.vault_id, &decoded, &proof.anchor).is_err() {
                return false;
            }
            accepted.shared_proof = Some(raw_proof.to_vec());
            accepted.member_entries.clone_from(&delta.member_entries);
            self.shared_proof = Some(proof);
            self.member_entries = decoded;
            return true;
        }
        let Some(proof) = &self.shared_proof else {
            return false;
        };
        let Ok(mut log) =
            MemberLog::from_entries(proof.vault_id, &self.member_entries, &proof.anchor)
        else {
            return false;
        };
        let decoded: Vec<Entry> = delta
            .member_entries
            .iter()
            .take(MAX_MEMBERS_PER_REPO)
            .filter_map(|raw| Entry::decode(raw).ok())
            .collect();
        let before = self.member_entries.len();
        if log.merge(&decoded).is_err() {
            return false;
        }
        let after_entries = log.entries();
        if after_entries.len() > before && after_entries.len() <= MAX_MEMBERS_PER_REPO {
            let new_slice = after_entries.get(before..).unwrap_or_default();
            for e in new_slice {
                if let Ok(enc) = e.encode() {
                    accepted.member_entries.push(enc);
                }
            }
            self.member_entries = after_entries.to_vec();
            self.device_keys
                .retain(|_, dk| log.role_of(&dk.cert.client_id).is_some());
            self.device_keys_wire
                .retain(|id, _| self.device_keys.contains_key(id));
            self.devices
                .retain(|_, d| log.role_of(&d.client_id).is_some());
            true
        } else {
            false
        }
    }

    pub(crate) fn insert_verified_cert(
        &mut self,
        cert: DeviceCert,
        log: Option<&MemberLog>,
        now: u64,
    ) -> bool {
        if cert.device_id == [0u8; 16] || self.revocations.iter().any(|r| r.covers(&cert)) {
            return false;
        }
        let Some(rvk) = self.cert_root_vk(&cert.client_id, log) else {
            return false;
        };
        if cert.verify(&rvk, now).is_err() {
            return false;
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.devices.entry(cert.device_id) {
            e.insert(cert);
            true
        } else {
            false
        }
    }

    fn try_insert_device_key(
        &mut self,
        raw: &[u8],
        vault_id: &[u8; 16],
        log: Option<&MemberLog>,
        now: u64,
    ) -> bool {
        let Some(member_log) = log else {
            return false;
        };
        for member in member_log.members() {
            let Ok(entry) = PersonalDeviceEntry::verify_decode(raw, &member.root_vk, vault_id, now)
            else {
                continue;
            };
            if !ct_eq(&entry.cert.client_id, &member.client_id)
                || entry.cert.device_id == [0u8; 16]
                || self.revocations.iter().any(|r| r.covers(&entry.cert))
            {
                return false;
            }
            let dev_id = entry.cert.device_id;
            if self.device_keys.contains_key(&dev_id) {
                return false;
            }
            let _ = self.insert_verified_cert(entry.cert.clone(), log, now);
            self.device_keys.insert(dev_id, entry);
            self.device_keys_wire.insert(dev_id, raw.to_vec());
            return true;
        }
        false
    }

    fn try_apply_head(&mut self, head: &SignedHead, log: Option<&MemberLog>, now: u64) -> bool {
        let Some(cert) = self.active_cert(&head.ver.origin_device, now) else {
            return false;
        };
        if !self.can_write(&cert.client_id, log)
            || verify_head(&cert.device_vk, self.kind, &self.storage_id, head).is_err()
        {
            return false;
        }
        if self.head.as_ref().is_some_and(|cur| {
            ct_eq(&head.ver.commit_tag, &cur.ver.commit_tag)
                || head.ver.generation <= cur.ver.generation
        }) {
            return false;
        }
        self.head = Some(head.clone());
        true
    }

    fn try_apply_rekey(&mut self, rk: &SignedRekey, log: Option<&MemberLog>, now: u64) -> bool {
        let Some(cert) = self.active_cert(&rk.origin_device, now) else {
            return false;
        };
        let allowed = match self.kind {
            RepoKind::Personal => self.can_write(&cert.client_id, log),
            RepoKind::Shared => log
                .and_then(|l| l.role_of(&cert.client_id))
                .is_some_and(memberlog::Role::can_manage),
        };
        if !allowed || verify_rekey(&cert.device_vk, self.kind, &self.storage_id, rk).is_err() {
            return false;
        }
        if self
            .rekeys
            .iter()
            .any(|((g, dev), _)| *dev == rk.target_device && *g >= rk.generation)
        {
            return false;
        }
        self.rekeys
            .retain(|(g, dev), _| !(*dev == rk.target_device && *g < rk.generation));
        if self.rekeys.len() >= MAX_REKEYS_PER_REPO {
            if let Some(oldest_key) = self.rekeys.keys().next().copied()
                && oldest_key.0 < rk.generation
            {
                self.rekeys.remove(&oldest_key);
            } else {
                return false;
            }
        }
        self.rekeys
            .insert((rk.generation, rk.target_device), rk.clone());
        true
    }

    fn try_apply_record(
        &mut self,
        commit: &RecordCommit,
        log: Option<&MemberLog>,
        now: u64,
    ) -> bool {
        if commit.ver.record_id == 0
            || commit.ver.origin_device == [0u8; 16]
            || commit.ver.revision == 0
            || commit.ver.revision > MAX_SAFE_REVISION
        {
            return false;
        }
        let Some(cert) = self.active_cert(&commit.signer_device, now) else {
            return false;
        };
        if !self.can_write(&cert.client_id, log)
            || verify_record(&cert.device_vk, self.kind, &self.storage_id, commit).is_err()
        {
            return false;
        }
        match self.records.get(&commit.ver.record_id) {
            None => {
                if commit.ver.revision > MAX_INITIAL_REVISION {
                    return false;
                }
            }
            Some(cur) => {
                if commit.key_generation < cur.key_generation {
                    return false;
                }
                if commit.ver.revision > cur.ver.revision.saturating_add(MAX_REVISION_STEP) {
                    return false;
                }
                let newer = if commit.key_generation > cur.key_generation {
                    commit.ver.order_key() >= cur.ver.order_key()
                } else {
                    commit.ver.order_key() > cur.ver.order_key()
                };
                if !newer {
                    return false;
                }
            }
        }
        self.records.insert(commit.ver.record_id, commit.clone());
        true
    }
}
