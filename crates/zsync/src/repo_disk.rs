//! Sharded in-memory repository locks and per-repository atomic disk
//! persistence (`<data_dir>/repos/<kind>_<hex64>.bin`).

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};

use local::{PersonalRepoAnchor, SharedRepoProof, ensure_private_dir, write_atomic};
use tokio::sync::RwLock;

use crate::auth::{now_ms, verify_frontier, verify_watch};
use crate::limits::WATCH_MAX_SKEW_SECS;
use crate::replay::ReplayGuard;
use crate::repo::RepoState;
use crate::wire::{RepoDigest, RepoFrontier, RepoKind, StorageId, SyncDelta, Wanted, WatchSub};
use crate::wire_codec::{decode_delta, encode_delta};

type RepoKey = (RepoKind, StorageId);
type RepoIndex = BTreeMap<RepoKey, Arc<RwLock<RepoState>>>;
type RepoHandleEntry = (RepoKey, Arc<RwLock<RepoState>>);

/// Sharded zero-knowledge repository store (`StdRwLock` over index map;
/// per-repository async `tokio::sync::RwLock` so different users and mesh
/// peers run concurrently with zero global mutex blocking).
#[derive(Debug)]
pub struct RepoStore {
    repos_dir: PathBuf,
    index: StdRwLock<RepoIndex>,
    replay: ReplayGuard,
}

impl RepoStore {
    /// Open `data_dir` and reload all persisted encrypted repositories.
    ///
    /// # Errors
    ///
    /// Directory creation (`0700`) or filesystem read errors.
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let repos_dir = data_dir.join("repos");
        ensure_private_dir(&repos_dir)?;
        let mut map = BTreeMap::new();
        for entry in std::fs::read_dir(&repos_dir)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(delta) = decode_delta(&bytes) else {
                continue;
            };
            let mut state = RepoState::new(delta.kind, delta.storage_id);
            if let Ok((_, true)) = state.apply_delta(&delta) {
                map.insert((state.kind, state.storage_id), Arc::new(RwLock::new(state)));
            }
        }
        Ok(Self {
            repos_dir,
            index: StdRwLock::new(map),
            replay: ReplayGuard::default(),
        })
    }

    /// Retrieve an existing repository handle without creating an empty entry.
    #[must_use]
    pub fn get(&self, kind: RepoKind, storage_id: StorageId) -> Option<Arc<RwLock<RepoState>>> {
        self.index.read().ok()?.get(&(kind, storage_id)).cloned()
    }

    /// Number of stored repositories currently in memory.
    #[must_use]
    pub fn repo_count(&self) -> usize {
        self.index.read().map_or(0, |g| g.len())
    }

    /// Snapshot handles of all currently stored repositories.
    #[must_use]
    pub fn all_handles(&self) -> Vec<RepoHandleEntry> {
        self.index
            .read()
            .map_or_default(|g| g.iter().map(|(k, v)| (*k, Arc::clone(v))).collect())
    }

    /// Compute digests for all stored repositories.
    pub async fn all_digests(&self) -> Vec<RepoDigest> {
        let handles = self.all_handles();
        let mut out = Vec::with_capacity(handles.len());
        for ((kind, storage_id), handle) in handles {
            let guard = handle.read().await;
            out.push(RepoDigest {
                kind,
                storage_id,
                digest: guard.state_digest(),
            });
        }
        out
    }

    /// Compute one bounded page of repository digests strictly after `after`.
    pub async fn digests_page(
        &self,
        after: Option<RepoKey>,
        limit: usize,
    ) -> (Vec<RepoDigest>, Option<RepoKey>) {
        let page_handles: Vec<RepoHandleEntry> = {
            let Ok(guard) = self.index.read() else {
                return (Vec::new(), None);
            };
            let start = after.map_or(Bound::Unbounded, Bound::Excluded);
            guard
                .range((start, Bound::Unbounded))
                .take(limit.saturating_add(1))
                .map(|(k, v)| (*k, Arc::clone(v)))
                .collect()
        };
        let has_more = page_handles.len() > limit;
        let slice = page_handles
            .get(..page_handles.len().min(limit))
            .unwrap_or_default();
        let mut out = Vec::with_capacity(slice.len());
        let mut last_key = None;
        for ((kind, storage_id), handle) in slice {
            let digest = handle.read().await.state_digest();
            out.push(RepoDigest {
                kind: *kind,
                storage_id: *storage_id,
                digest,
            });
            last_key = Some((*kind, *storage_id));
        }
        (out, if has_more { last_key } else { None })
    }

    /// Apply a delta atomically without allocating any entry in `self.index`
    /// unless `apply_delta` succeeds with `changed == true`.
    ///
    /// # Errors
    ///
    /// Persistence or repo mismatch errors.
    pub async fn apply_and_save(&self, delta: &SyncDelta) -> anyhow::Result<(SyncDelta, bool)> {
        let key = (delta.kind, delta.storage_id);
        let (accepted, snapshot_bytes) =
            if let Some(handle) = self.get(delta.kind, delta.storage_id) {
                let mut repo = handle.write().await;
                let (accepted, changed) = repo.apply_delta(delta)?;
                if !changed {
                    return Ok((accepted, false));
                }
                let full = to_full_delta(&repo)?;
                drop(repo);
                (accepted, encode_delta(&full)?)
            } else {
                let mut trial = RepoState::new(delta.kind, delta.storage_id);
                let (accepted, changed) = trial.apply_delta(delta)?;
                if !changed {
                    return Ok((accepted, false));
                }
                let insert_outcome = {
                    let mut guard = self
                        .index
                        .write()
                        .map_err(|_| anyhow::anyhow!("repo index poisoned"))?;
                    if let Some(existing) = guard.get(&key).cloned() {
                        drop(guard);
                        Err(existing)
                    } else {
                        let full = to_full_delta(&trial)?;
                        let bytes = encode_delta(&full)?;
                        guard.insert(key, Arc::new(RwLock::new(trial)));
                        drop(guard);
                        Ok(bytes)
                    }
                };
                match insert_outcome {
                    Ok(bytes) => {
                        let path = repo_path(&self.repos_dir, delta.kind, &delta.storage_id);
                        tokio::task::spawn_blocking(move || write_atomic(&path, &bytes)).await??;
                        return Ok((accepted, true));
                    }
                    Err(existing) => {
                        let mut repo = existing.write().await;
                        let (acc2, ch2) = repo.apply_delta(delta)?;
                        if !ch2 {
                            return Ok((acc2, false));
                        }
                        let full = to_full_delta(&repo)?;
                        drop(repo);
                        (acc2, encode_delta(&full)?)
                    }
                }
            };

        let path = repo_path(&self.repos_dir, delta.kind, &delta.storage_id);
        tokio::task::spawn_blocking(move || write_atomic(&path, &snapshot_bytes)).await??;
        Ok((accepted, true))
    }

    /// Verify an authenticated [`WatchSub`] request: requires `!sub.repos.is_empty()`
    /// and **every** requested repository to be authorized for `cert`.
    pub async fn verify_watch_sub(&self, sub: &WatchSub) -> bool {
        if sub.repos.is_empty() {
            return false;
        }
        let now_s = now_ms() / 1000;
        if sub.timestamp_s.abs_diff(now_s) > WATCH_MAX_SKEW_SECS {
            return false;
        }
        let Ok(cert) = syncwire::decode_cert(&sub.cert_wire) else {
            return false;
        };
        if cert.device_id != sub.device_id || verify_watch(&cert.device_vk, sub).is_err() {
            return false;
        }
        if !self
            .replay
            .check_and_insert(b"watch", &sub.device_id, sub.timestamp_s, &sub.nonce)
        {
            return false;
        }

        let now = now_ms();
        let uncreated_anchor = sub
            .personal_anchor
            .as_deref()
            .and_then(|raw| PersonalRepoAnchor::decode(raw).ok());
        let shared_proofs: Vec<SharedRepoProof> = sub
            .shared_proofs
            .iter()
            .filter_map(|raw| SharedRepoProof::decode(raw).ok())
            .collect();

        for (kind, sid) in &sub.repos {
            let repo_ok = if let Some(handle) = self.get(*kind, *sid) {
                let repo = handle.read().await;
                if repo.revocations.iter().any(|r| r.covers(&cert)) {
                    false
                } else {
                    let log = repo.member_log();
                    repo.cert_root_vk(&cert.client_id, log.as_ref())
                        .is_some_and(|rvk| cert.verify(&rvk, now).is_ok())
                }
            } else {
                match kind {
                    RepoKind::Personal => {
                        if let (Some(anchor), Some(rvk)) =
                            (uncreated_anchor.as_ref(), sub.root_vk.as_deref())
                        {
                            anchor.verify(sid, &cert.client_id, rvk).is_ok()
                                && cert.verify(rvk, now).is_ok()
                        } else {
                            false
                        }
                    }
                    RepoKind::Shared => sub.root_vk.as_deref().is_some_and(|rvk| {
                        cert.verify(rvk, now).is_ok()
                            && shared_proofs.iter().any(|p| p.verify(sid).is_ok())
                    }),
                }
            };
            if !repo_ok {
                return false;
            }
        }
        true
    }

    /// Authenticate a client's [`RepoFrontier`] and compute `(pull, wanted)`.
    ///
    /// # Errors
    ///
    /// Missing/expired/replayed auth, revoked device certificate, or bad signature.
    pub async fn client_diff(&self, f: &RepoFrontier) -> anyhow::Result<(SyncDelta, Wanted)> {
        let auth = f
            .auth
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing frontier auth"))?;
        let now_s = now_ms() / 1000;
        if auth.timestamp_s.abs_diff(now_s) > WATCH_MAX_SKEW_SECS {
            anyhow::bail!("stale frontier timestamp");
        }
        let cert = syncwire::decode_cert(&auth.cert_wire)?;
        verify_frontier(&cert.device_vk, f)?;
        if !self.replay.check_and_insert(
            b"frontier",
            &cert.device_id,
            auth.timestamp_s,
            &auth.nonce,
        ) {
            anyhow::bail!("replayed frontier request");
        }

        let now = now_ms();
        if let Some(handle) = self.get(f.kind, f.storage_id) {
            let repo = handle.read().await;
            if repo.revocations.iter().any(|r| r.covers(&cert)) {
                anyhow::bail!("device revoked");
            }
            let log = repo.member_log();
            let rvk = repo
                .cert_root_vk(&cert.client_id, log.as_ref())
                .ok_or_else(|| anyhow::anyhow!("untrusted device"))?;
            cert.verify(&rvk, now)?;
            return Ok(repo.diff_frontier(f));
        }

        match f.kind {
            RepoKind::Personal => {
                let raw_anchor = f
                    .personal_anchor
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing personal repo anchor"))?;
                let anchor = PersonalRepoAnchor::decode(raw_anchor)?;
                let rvk = f
                    .root_vk
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing account root key"))?;
                anchor.verify(&f.storage_id, &cert.client_id, rvk)?;
                cert.verify(rvk, now)?;
            }
            RepoKind::Shared => {
                let raw_proof = f
                    .shared_proof
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing shared repo proof"))?;
                let proof = SharedRepoProof::decode(raw_proof)?;
                proof.verify(&f.storage_id)?;
                let rvk = f
                    .root_vk
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing member root key"))?;
                cert.verify(rvk, now)?;
            }
        }

        let wanted = Wanted {
            record_ids: f.records.iter().map(|r| r.record_id).collect(),
            flags: Wanted::bit(Wanted::NEED_HEAD, f.head.is_some())
                | Wanted::bit(
                    Wanted::NEED_MEMBERS,
                    f.kind == RepoKind::Shared && f.member_count > 0,
                )
                | Wanted::bit(Wanted::NEED_REVS, f.rev_count > 0)
                | Wanted::bit(Wanted::NEED_DEVICE_KEYS, f.dev_key_count > 0),
        };
        Ok((SyncDelta::empty(f.kind, f.storage_id), wanted))
    }
}

fn to_full_delta(repo: &RepoState) -> anyhow::Result<SyncDelta> {
    let mut certs = Vec::with_capacity(repo.devices.len());
    for cert in repo.devices.values() {
        certs.push(syncwire::encode_cert(cert)?);
    }
    let mut revocations = Vec::with_capacity(repo.revocations.len());
    for rev in &repo.revocations {
        revocations.push(syncwire::encode_revocation(rev)?);
    }
    let mut member_entries = Vec::with_capacity(repo.member_entries.len());
    for entry in &repo.member_entries {
        member_entries.push(entry.encode()?);
    }
    Ok(SyncDelta {
        kind: repo.kind,
        storage_id: repo.storage_id,
        personal_anchor: repo
            .personal_anchor
            .as_ref()
            .map(PersonalRepoAnchor::encode)
            .transpose()?,
        root_vk: repo.root_vk.clone(),
        shared_proof: repo
            .shared_proof
            .as_ref()
            .map(SharedRepoProof::encode)
            .transpose()?,
        certs,
        device_keys: repo.device_keys_wire.values().cloned().collect(),
        revocations,
        member_entries,
        head: repo.head.clone(),
        rekeys: repo.rekeys.values().cloned().collect(),
        records: repo.records.values().cloned().collect(),
    })
}

fn repo_path(dir: &Path, kind: RepoKind, storage_id: &StorageId) -> PathBuf {
    const HEX: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut name = String::with_capacity(6 + 128);
    name.push(match kind {
        RepoKind::Personal => 'p',
        RepoKind::Shared => 's',
    });
    name.push('_');
    for b in storage_id {
        name.push(HEX.get(usize::from(*b >> 4)).copied().unwrap_or('0'));
        name.push(HEX.get(usize::from(*b & 0x0F)).copied().unwrap_or('0'));
    }
    name.push_str(".bin");
    dir.join(name)
}
