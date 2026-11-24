//! Frontier diffing, summary serialization, and deterministic state digests
//! for [`RepoState`].

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use syncwire::{decode_cert, encode_cert, encode_revocation};

use crate::limits::MAX_RECORDS_PER_MSG;
use crate::repo::RepoState;
use crate::wire::{HeadVer, RecordVer, RepoFrontier, SyncDelta, Wanted};

impl RepoState {
    /// Reconcile local repository state against a peer's `RepoFrontier`,
    /// returning `(items_peer_lacks, items_we_want)`.
    #[must_use]
    pub fn diff_frontier(&self, peer: &RepoFrontier) -> (SyncDelta, Wanted) {
        let mut pull = SyncDelta::empty(self.kind, self.storage_id);
        if peer.root_vk.is_none() {
            pull.personal_anchor = self.personal_anchor.as_ref().and_then(|a| a.encode().ok());
            pull.root_vk.clone_from(&self.root_vk);
        }
        if peer.shared_proof.is_none() {
            pull.shared_proof = self.shared_proof.as_ref().and_then(|p| p.encode().ok());
        }
        for (dev_id, cert) in &self.devices {
            if !peer.certs.contains(dev_id)
                && let Ok(enc) = encode_cert(cert)
            {
                pull.certs.push(enc);
            }
        }
        if usize::from(peer.dev_key_count) < self.device_keys_wire.len() {
            pull.device_keys
                .extend(self.device_keys_wire.values().cloned());
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
                local_head.ver.generation > ph.generation
                    || (peer.auth.is_some()
                        && !secret::ct_eq(&ph.commit_tag, &local_head.ver.commit_tag))
            });
            if send_head {
                pull.head = Some(local_head.clone());
            }
        }

        let caller_dev = peer
            .auth
            .as_ref()
            .and_then(|a| decode_cert(&a.cert_wire).ok())
            .map(|c| c.device_id);
        for rk in self.rekeys.values() {
            let include = caller_dev
                .is_none_or(|dev| rk.target_device == dev || rk.target_device == [0u8; 16]);
            if include {
                pull.rekeys.push(rk.clone());
            }
        }

        let peer_recs: BTreeMap<u32, RecordVer> =
            peer.records.iter().map(|r| (r.record_id, *r)).collect();
        for (id, commit) in &self.records {
            if pull.records.len() >= MAX_RECORDS_PER_MSG {
                break;
            }
            let send_it = peer_recs
                .get(id)
                .is_none_or(|pv| commit.ver.order_key() > pv.order_key());
            if send_it {
                pull.records.push(commit.clone());
            }
        }

        (pull, self.compute_wanted(peer))
    }

    fn compute_wanted(&self, peer: &RepoFrontier) -> Wanted {
        let need_head = match (&self.head, peer.head) {
            (None, Some(_)) => true,
            (Some(lh), Some(ph)) => {
                !secret::ct_eq(&ph.commit_tag, &lh.ver.commit_tag)
                    && ph.generation > lh.ver.generation
            }
            _ => false,
        };
        let need_members = peer.member_count as usize > self.member_entries.len();
        let need_revs = peer.rev_count as usize > self.revocations.len();
        let need_device_keys = usize::from(peer.dev_key_count) > self.device_keys_wire.len();
        let record_ids = peer
            .records
            .iter()
            .filter(|pv| {
                self.records.get(&pv.record_id).is_none_or(|lc| {
                    pv.order_key() > lc.ver.order_key()
                        || (need_head
                            && pv.order_key() == lc.ver.order_key()
                            && !secret::ct_eq_32(&pv.frame_hash, &lc.ver.frame_hash))
                })
            })
            .take(MAX_RECORDS_PER_MSG)
            .map(|pv| pv.record_id)
            .collect();
        let flags = Wanted::bit(Wanted::NEED_HEAD, need_head)
            | Wanted::bit(Wanted::NEED_MEMBERS, need_members)
            | Wanted::bit(Wanted::NEED_REVS, need_revs)
            | Wanted::bit(Wanted::NEED_DEVICE_KEYS, need_device_keys);
        Wanted { record_ids, flags }
    }

    /// Build a [`RepoFrontier`] summary of this repository.
    #[must_use]
    pub fn to_frontier(&self) -> RepoFrontier {
        RepoFrontier {
            kind: self.kind,
            storage_id: self.storage_id,
            personal_anchor: self.personal_anchor.as_ref().and_then(|a| a.encode().ok()),
            root_vk: self.root_vk.clone(),
            shared_proof: self.shared_proof.as_ref().and_then(|p| p.encode().ok()),
            auth: None,
            certs: self.devices.keys().copied().collect(),
            head: self.head.as_ref().map(|h| h.ver),
            records: self
                .records
                .values()
                .take(MAX_RECORDS_PER_MSG)
                .map(|c| c.ver)
                .collect(),
            rev_count: u32::try_from(self.revocations.len()).unwrap_or(u32::MAX),
            member_count: u32::try_from(self.member_entries.len()).unwrap_or(u32::MAX),
            dev_key_count: u16::try_from(self.device_keys_wire.len()).unwrap_or(u16::MAX),
        }
    }

    /// Deterministic cryptographic digest summarizing the entire versioned state.
    #[must_use]
    pub fn state_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"brby/v3/repo-digest-v2");
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
        h.update((self.device_keys_wire.len() as u64).to_be_bytes());
        for dev in self.device_keys_wire.keys() {
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
