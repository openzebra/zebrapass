//! Verified zero-knowledge Git-like repository state, frontier diffing, and
//! commutative CRDT delta application.

use std::collections::BTreeMap;

use memberlog::{Entry, MemberLog};
use pq::SYNC_VK_LEN;
use secret::ct_eq;
use session::{DeviceCert, Revocation};
use sha2::{Digest, Sha256};
use syncwire::{decode_cert, decode_revocation, encode_cert, encode_revocation};

use crate::auth::{now_ms, verify_head, verify_record, verify_rekey};
use crate::limits::{
    MAX_CERTS_PER_REPO, MAX_MEMBERS_PER_REPO, MAX_RECORDS_PER_MSG, MAX_REKEYS_PER_REPO,
    MAX_REVS_PER_REPO,
};
use crate::wire::{
    HeadVer, RecordCommit, RecordVer, RepoFrontier, RepoKind, SignedHead, SignedRekey, StorageId,
    SyncDelta, Wanted,
};

/// Verified encrypted state of one personal or shared repository.
#[derive(Clone, Debug)]
pub struct RepoState {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub shared_init: Option<([u8; 16], [u8; 32])>,
    pub member_entries: Vec<Entry>,
    pub devices: BTreeMap<[u8; 16], DeviceCert>,
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
            root_vk: None,
            shared_init: None,
            member_entries: Vec::new(),
            devices: BTreeMap::new(),
            revocations: Vec::new(),
            head: None,
            rekeys: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }

    /// Rebuild and verify the shared member log when initialized.
    #[must_use]
    pub fn member_log(&self) -> Option<MemberLog> {
        let (vault_id, anchor) = self.shared_init?;
        MemberLog::from_entries(vault_id, &self.member_entries, &anchor).ok()
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

    fn cert_root_vk(
        &self,
        client_id: &[u8; 64],
        log: Option<&MemberLog>,
    ) -> Option<[u8; SYNC_VK_LEN]> {
        match self.kind {
            RepoKind::Personal => {
                if !ct_eq(client_id, &self.storage_id) {
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
            RepoKind::Personal => self.root_vk.is_some() && ct_eq(client_id, &self.storage_id),
            RepoKind::Shared => log.is_some_and(|l| l.may_write(client_id)),
        }
    }

    /// Apply a `SyncDelta` strictly verifying every certificate, member entry,
    /// revocation, and ML-DSA signature. Returns `(accepted_delta, changed)`
    /// containing only items that newly advanced this repository.
    ///
    /// # Errors
    ///
    /// Repo identity mismatch. Individual invalid items are rejected safely
    /// without corrupting accepted state.
    pub fn apply_delta(&mut self, delta: &SyncDelta) -> anyhow::Result<(SyncDelta, bool)> {
        if delta.kind != self.kind || !ct_eq(&delta.storage_id, &self.storage_id) {
            anyhow::bail!("repository delta mismatch");
        }
        let now = now_ms();
        let mut accepted = SyncDelta::empty(self.kind, self.storage_id);
        let mut changed = false;

        if self.kind == RepoKind::Personal {
            if self.try_anchor_personal(delta, now) {
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

        if let Some(head) = &delta.head
            && self.try_apply_head(head, log.as_ref(), now)
        {
            accepted.head = Some(head.clone());
            changed = true;
        }

        for rekey in &delta.rekeys {
            if self.rekeys.len() >= MAX_REKEYS_PER_REPO {
                break;
            }
            if self.try_apply_rekey(rekey, log.as_ref(), now) {
                accepted.rekeys.push(rekey.clone());
                changed = true;
            }
        }

        for commit in &delta.records {
            if self.records.len() >= MAX_RECORDS_PER_MSG {
                break;
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
        let Some(candidate_vk) = delta.root_vk.as_deref() else {
            return false;
        };
        let valid_anchor = delta.certs.iter().any(|raw| {
            decode_cert(raw).is_ok_and(|c| {
                ct_eq(&c.client_id, &self.storage_id) && c.verify(candidate_vk, now).is_ok()
            })
        });
        if valid_anchor {
            self.root_vk = Some(Box::new(*candidate_vk));
            true
        } else {
            false
        }
    }

    fn try_merge_shared_members(&mut self, delta: &SyncDelta, accepted: &mut SyncDelta) -> bool {
        if self.shared_init.is_none() {
            let (Some(init), false) = (delta.shared_init, delta.member_entries.is_empty()) else {
                return false;
            };
            let decoded: Vec<Entry> = delta
                .member_entries
                .iter()
                .take(MAX_MEMBERS_PER_REPO)
                .filter_map(|raw| Entry::decode(raw).ok())
                .collect();
            if MemberLog::from_entries(init.0, &decoded, &init.1).is_err() {
                return false;
            }
            self.shared_init = Some(init);
            self.member_entries = decoded;
            accepted.shared_init = Some(init);
            accepted.member_entries.clone_from(&delta.member_entries);
            return true;
        }
        let Some((vault_id, anchor)) = self.shared_init else {
            return false;
        };
        let Ok(mut log) = MemberLog::from_entries(vault_id, &self.member_entries, &anchor) else {
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
        match self.devices.get(&cert.device_id) {
            Some(existing) if existing == &cert => false,
            Some(_) => false,
            None => {
                self.devices.insert(cert.device_id, cert);
                true
            }
        }
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
            head.ver.commit_tag == cur.ver.commit_tag || head.ver.generation <= cur.ver.generation
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
        if !self.can_write(&cert.client_id, log) {
            return false;
        }
        if verify_rekey(&cert.device_vk, self.kind, &self.storage_id, rk).is_err() {
            return false;
        }
        let key = (rk.generation, rk.target_device);
        if self.rekeys.contains_key(&key) {
            return false;
        }
        self.rekeys.insert(key, rk.clone());
        true
    }

    fn try_apply_record(
        &mut self,
        commit: &RecordCommit,
        log: Option<&MemberLog>,
        now: u64,
    ) -> bool {
        if commit.ver.record_id == 0 || commit.ver.origin_device == [0u8; 16] {
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
        if self
            .records
            .get(&commit.ver.record_id)
            .is_some_and(|cur| commit.ver.order_key() <= cur.ver.order_key())
        {
            return false;
        }
        self.records.insert(commit.ver.record_id, commit.clone());
        true
    }

    /// Reconcile local repository state against a peer's `RepoFrontier`,
    /// returning `(items_peer_lacks, items_we_want)`.
    #[must_use]
    pub fn diff_frontier(&self, peer: &RepoFrontier) -> (SyncDelta, Wanted) {
        let mut pull = SyncDelta::empty(self.kind, self.storage_id);
        let peer_has_root = peer.root_vk.is_some();
        if !peer_has_root {
            pull.root_vk.clone_from(&self.root_vk);
        }
        if peer.shared_init.is_none() {
            pull.shared_init = self.shared_init;
        }
        for (dev_id, cert) in &self.devices {
            if !peer.certs.contains(dev_id)
                && let Ok(enc) = encode_cert(cert)
            {
                pull.certs.push(enc);
            }
        }
        let rev_skip = usize::try_from(peer.rev_count).unwrap_or(usize::MAX);
        for rev in self.revocations.iter().skip(rev_skip) {
            if let Ok(enc) = encode_revocation(rev) {
                pull.revocations.push(enc);
            }
        }
        let mem_skip = usize::try_from(peer.member_count).unwrap_or(usize::MAX);
        for entry in self.member_entries.iter().skip(mem_skip) {
            if let Ok(enc) = entry.encode() {
                pull.member_entries.push(enc);
            }
        }
        if let Some(local_head) = &self.head {
            let send_head = peer.head.is_none_or(|ph| {
                ph.commit_tag != local_head.ver.commit_tag
                    && local_head.ver.generation > ph.generation
            });
            if send_head {
                pull.head = Some(local_head.clone());
            }
        }
        pull.rekeys.extend(self.rekeys.values().cloned());
        let peer_recs: BTreeMap<u32, RecordVer> =
            peer.records.iter().map(|r| (r.record_id, *r)).collect();
        for (id, commit) in &self.records {
            let send_it = peer_recs
                .get(id)
                .is_none_or(|pv| commit.ver.order_key() > pv.order_key());
            if send_it {
                pull.records.push(commit.clone());
            }
        }

        let need_head = match (&self.head, peer.head) {
            (None, Some(_)) => true,
            (Some(lh), Some(ph)) => {
                ph.commit_tag != lh.ver.commit_tag && ph.generation > lh.ver.generation
            }
            _ => false,
        };
        let need_members = peer.member_count as usize > self.member_entries.len();
        let need_revs = peer.rev_count as usize > self.revocations.len();
        let record_ids = peer
            .records
            .iter()
            .filter(|pv| {
                self.records
                    .get(&pv.record_id)
                    .is_none_or(|lc| pv.order_key() > lc.ver.order_key())
            })
            .map(|pv| pv.record_id)
            .collect();
        (
            pull,
            Wanted {
                need_head,
                need_members,
                need_revs,
                record_ids,
            },
        )
    }

    /// Build a [`RepoFrontier`] summary of this repository.
    #[must_use]
    pub fn to_frontier(&self) -> RepoFrontier {
        RepoFrontier {
            kind: self.kind,
            storage_id: self.storage_id,
            root_vk: self.root_vk.clone(),
            shared_init: self.shared_init,
            auth: None,
            certs: self.devices.keys().copied().collect(),
            rev_count: u32::try_from(self.revocations.len()).unwrap_or(u32::MAX),
            member_count: u32::try_from(self.member_entries.len()).unwrap_or(u32::MAX),
            head: self.head.as_ref().map(|h| h.ver),
            records: self.records.values().map(|c| c.ver).collect(),
        }
    }

    /// Deterministic cryptographic digest summarizing the entire versioned state.
    #[must_use]
    pub fn state_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"brby/v3/repo-digest");
        h.update([self.kind as u8]);
        h.update(self.storage_id);
        match self.head.as_ref().map(|hd| hd.ver) {
            Some(HeadVer {
                generation,
                commit_tag,
                origin_device,
            }) => {
                h.update([1]);
                h.update(generation.to_be_bytes());
                h.update(commit_tag);
                h.update(origin_device);
            }
            None => h.update([0]),
        }
        h.update((self.devices.len() as u64).to_be_bytes());
        for dev in self.devices.keys() {
            h.update(dev);
        }
        h.update((self.revocations.len() as u64).to_be_bytes());
        h.update((self.member_entries.len() as u64).to_be_bytes());
        h.update((self.rekeys.len() as u64).to_be_bytes());
        for (gen_num, target) in self.rekeys.keys() {
            h.update(gen_num.to_be_bytes());
            h.update(target);
        }
        h.update((self.records.len() as u64).to_be_bytes());
        for commit in self.records.values() {
            h.update(commit.ver.record_id.to_be_bytes());
            h.update(commit.ver.revision.to_be_bytes());
            h.update(commit.ver.origin_device);
            h.update(commit.signer_device);
            h.update(commit.ver.frame_hash);
        }
        h.finalize().into()
    }
}
