//! Sharded in-memory repository locks and per-repository atomic disk
//! persistence (`<data_dir>/repos/<kind>_<hex64>.bin`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};

use local::write_atomic;
use tokio::sync::RwLock;

use crate::auth::{now_ms, verify_frontier, verify_watch};
use crate::limits::WATCH_MAX_SKEW_SECS;
use crate::repo::RepoState;
use crate::wire::{RepoDigest, RepoFrontier, RepoKind, StorageId, SyncDelta, Wanted, WatchSub};
use crate::wire_codec::{decode_delta, encode_delta};

type RepoIndex = BTreeMap<(RepoKind, StorageId), Arc<RwLock<RepoState>>>;
type RepoHandleEntry = ((RepoKind, StorageId), Arc<RwLock<RepoState>>);

/// Sharded zero-knowledge repository store (`StdRwLock` over index map;
/// per-repository async `tokio::sync::RwLock` so different users and mesh
/// peers run concurrently with zero global mutex blocking).
#[derive(Debug)]
pub struct RepoStore {
    repos_dir: PathBuf,
    index: StdRwLock<RepoIndex>,
}

impl RepoStore {
    /// Open `data_dir` and reload all persisted encrypted repositories.
    ///
    /// # Errors
    ///
    /// Directory creation or filesystem read errors.
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let repos_dir = data_dir.join("repos");
        std::fs::create_dir_all(&repos_dir)?;
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
            if state.apply_delta(&delta).is_ok() {
                map.insert((state.kind, state.storage_id), Arc::new(RwLock::new(state)));
            }
        }
        Ok(Self {
            repos_dir,
            index: StdRwLock::new(map),
        })
    }

    /// Retrieve or create the per-repository async lock handle.
    ///
    /// # Errors
    ///
    /// Poisoned index lock.
    pub fn get_or_create(
        &self,
        kind: RepoKind,
        storage_id: StorageId,
    ) -> anyhow::Result<Arc<RwLock<RepoState>>> {
        let key = (kind, storage_id);
        let existing = {
            let guard = self
                .index
                .read()
                .map_err(|_| anyhow::anyhow!("repo index poisoned"))?;
            guard.get(&key).cloned()
        };
        if let Some(found) = existing {
            return Ok(found);
        }
        let mut guard = self
            .index
            .write()
            .map_err(|_| anyhow::anyhow!("repo index poisoned"))?;
        let arc = Arc::clone(
            guard
                .entry(key)
                .or_insert_with(|| Arc::new(RwLock::new(RepoState::new(kind, storage_id)))),
        );
        drop(guard);
        Ok(arc)
    }

    /// Retrieve an existing repository handle without creating an empty entry.
    #[must_use]
    pub fn get(&self, kind: RepoKind, storage_id: StorageId) -> Option<Arc<RwLock<RepoState>>> {
        self.index.read().ok()?.get(&(kind, storage_id)).cloned()
    }

    /// Snapshot handles of all currently stored repositories.
    #[must_use]
    pub fn all_handles(&self) -> Vec<RepoHandleEntry> {
        self.index
            .read()
            .map_or_default(|g| g.iter().map(|(k, v)| (*k, Arc::clone(v))).collect())
    }

    /// Compute digests for all stored repositories (parallel mesh anti-entropy).
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

    /// Apply a delta atomically under the target repo lock and persist it if modified.
    ///
    /// # Errors
    ///
    /// Persistence or repo mismatch errors.
    pub async fn apply_and_save(&self, delta: &SyncDelta) -> anyhow::Result<(SyncDelta, bool)> {
        let handle = self.get_or_create(delta.kind, delta.storage_id)?;
        let (accepted, changed, snapshot_bytes) = {
            let mut repo = handle.write().await;
            let (accepted, changed) = repo.apply_delta(delta)?;
            if !changed {
                return Ok((accepted, false));
            }
            let full = to_full_delta(&repo)?;
            drop(repo);
            (accepted, true, encode_delta(&full)?)
        };
        let path = repo_path(&self.repos_dir, delta.kind, &delta.storage_id);
        tokio::task::spawn_blocking(move || write_atomic(&path, &snapshot_bytes)).await??;
        Ok((accepted, changed))
    }

    /// Verify an authenticated [`WatchSub`] request.
    pub async fn verify_watch_sub(&self, sub: &WatchSub) -> bool {
        let now_s = now_ms() / 1000;
        if sub.timestamp_s.abs_diff(now_s) > WATCH_MAX_SKEW_SECS {
            return false;
        }
        let Ok(cert) = syncwire::decode_cert(&sub.cert_wire) else {
            return false;
        };
        if cert.device_id != sub.device_id {
            return false;
        }
        let now = now_ms();
        let mut authorized = false;
        for (kind, sid) in &sub.repos {
            if let Some(handle) = self.get(*kind, *sid) {
                let repo = handle.read().await;
                if repo.active_cert(&sub.device_id, now).is_some() {
                    authorized = true;
                    break;
                }
            } else if *kind == RepoKind::Personal
                && let Some(root_vk) = sub.root_vk.as_deref()
                && secret::ct_eq(&cert.client_id, sid)
                && cert.verify(root_vk, now).is_ok()
            {
                authorized = true;
                break;
            }
        }
        authorized && verify_watch(&cert.device_vk, sub).is_ok()
    }

    /// Authenticate a client's [`RepoFrontier`] and compute `(pull, wanted)`.
    ///
    /// # Errors
    ///
    /// Missing/expired auth, revoked device certificate, or bad signature.
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
        let now = now_ms();
        if let Some(handle) = self.get(f.kind, f.storage_id) {
            let repo = handle.read().await;
            if repo.revocations.iter().any(|r| r.covers(&cert)) {
                anyhow::bail!("device revoked");
            }
            let rvk = match repo.kind {
                RepoKind::Personal => {
                    if !secret::ct_eq(&cert.client_id, &repo.storage_id) {
                        anyhow::bail!("wrong account");
                    }
                    repo.root_vk.as_deref().copied()
                }
                RepoKind::Shared => repo.member_log().and_then(|l| {
                    l.members()
                        .iter()
                        .find(|m| secret::ct_eq(&m.client_id, &cert.client_id))
                        .map(|m| *m.root_vk)
                }),
            }
            .ok_or_else(|| anyhow::anyhow!("untrusted device"))?;
            cert.verify(&rvk, now)?;
            verify_frontier(&cert.device_vk, f)?;
            return Ok(repo.diff_frontier(f));
        }
        match f.kind {
            RepoKind::Personal => {
                let rvk = f
                    .root_vk
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing account root key"))?;
                if !secret::ct_eq(&cert.client_id, &f.storage_id) {
                    anyhow::bail!("wrong account");
                }
                cert.verify(rvk, now)?;
            }
            RepoKind::Shared => {
                if f.shared_init.is_none() {
                    anyhow::bail!("missing shared vault anchor");
                }
                cert.verify(
                    f.root_vk
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("missing member root key"))?,
                    now,
                )?;
            }
        }
        verify_frontier(&cert.device_vk, f)?;
        let wanted = Wanted {
            need_head: f.head.is_some(),
            need_members: f.kind == RepoKind::Shared && f.member_count > 0,
            need_revs: f.rev_count > 0,
            record_ids: f.records.iter().map(|r| r.record_id).collect(),
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
        root_vk: repo.root_vk.clone(),
        shared_init: repo.shared_init,
        certs,
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
