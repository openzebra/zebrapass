//! Asynchronous PQ TLS 1.3 versioned sync and live relay bridge connecting
//! an unlocked vault to [`zsync`] endpoints (`[ru, eu, zh].zebra.sh` or custom
//! self-hosted servers).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock, mpsc};
use std::time::Duration;

use local::{
    DEFAULT_SYNC_SERVERS, PersonalDeviceEntry, Prefs, SharedRepoProof, SyncIdentity,
    encode_personal_head, load_master_grant, parse_sync_server_url,
};
use secret::Secret;
use session::{FrontierEntry, Revocation};
use tokio::sync::watch;
use zeroize::Zeroizing;
use zsync::{
    PersonalStateInput, PulledPersonal, PulledShared, RelayCredentials, RepoKind, WatchedRepo,
    WorkerEvent, WorkerMode, ZebraClient, ZebraWorker, device_announce_record_id, hold_relay_slot,
    personal_storage_id, relay_sync_responder, wraps_tag,
};

use crate::app::ctx::Ctx;
use crate::cli::Flags;
use crate::vault::Vault;
use crate::vault::adopt::is_placeholder;
use crate::vault::device;
use crate::vault::shared::SharedItem;

pub(super) type RelayPersonalSnapshot = (Vec<FrontierEntry>, Vec<(u32, Vec<u8>)>);

/// Owned personal vault state passed safely into background Tokio tasks.
pub struct OwnedPersonalInput {
    pub vk: Secret<[u8; 32]>,
    pub master_grant: Option<Vec<u8>>,
    pub vault_bytes: Zeroizing<Vec<u8>>,
    pub head_meta_plain: Vec<u8>,
    pub generation: u64,
    pub head_epoch: u64,
    pub records: Vec<(u32, u64, [u8; 16], Vec<u8>)>,
    pub revocations: Vec<Revocation>,
    pub rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
    pub push_head_always: bool,
}

/// Queue state of background personal reconciliation (avoids bool soup).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PersonalQueue {
    #[default]
    Idle,
    Running {
        dirty: bool,
        force_head: bool,
    },
}

/// Events sent back from background `zsync` tasks to the UI tick loop.
pub enum ZSyncMsg {
    PersonalReconciled {
        pulled: PulledPersonal,
        initial_check: bool,
    },
    PersonalFailed {
        err: String,
        rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
        force_head: bool,
    },
    SharedReconciled {
        vault_id: [u8; 16],
        pulled: PulledShared,
    },
    RelayedFrames(Vec<Vec<u8>>),
    Error(String),
}

impl std::fmt::Debug for ZSyncMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersonalReconciled { .. } => f.write_str("ZSyncMsg::PersonalReconciled"),
            Self::PersonalFailed { err, .. } => f
                .debug_tuple("ZSyncMsg::PersonalFailed")
                .field(err)
                .finish(),
            Self::SharedReconciled { vault_id, .. } => f
                .debug_struct("ZSyncMsg::SharedReconciled")
                .field("vault_id", vault_id)
                .finish(),
            Self::RelayedFrames(frames) => f
                .debug_tuple("ZSyncMsg::RelayedFrames")
                .field(&frames.len())
                .finish(),
            Self::Error(msg) => f.debug_tuple("ZSyncMsg::Error").field(msg).finish(),
        }
    }
}

/// Active background `zsync` client, push watcher, and live relay responder.
pub struct ZebraSync {
    pub(super) rt: tokio::runtime::Runtime,
    pub client: Arc<ZebraClient>,
    pub worker: ZebraWorker,
    pub worker_rx: tokio::sync::mpsc::UnboundedReceiver<WorkerEvent>,
    pub msg_tx: mpsc::Sender<ZSyncMsg>,
    pub msg_rx: mpsc::Receiver<ZSyncMsg>,
    pub identity: Arc<SyncIdentity>,
    pub vault_id: [u8; 16],
    pub wrap_id: Option<[u8; 16]>,
    pub head_epoch: u64,
    pub last_wraps_tag: [u8; 32],
    pub shared_epochs: BTreeMap<[u8; 16], u64>,
    pub shared_wraps: BTreeMap<[u8; 16], [u8; 32]>,
    pub shared_member_devices: BTreeMap<[u8; 16], Vec<PersonalDeviceEntry>>,
    pub peer_devices: Vec<PersonalDeviceEntry>,
    pub pending_rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
    pub personal_queue: PersonalQueue,
    pub last_mode: WorkerMode,
    pub endpoints: Vec<String>,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
    pub(super) relay_snap: Arc<RwLock<RelayPersonalSnapshot>>,
    relay_stop: watch::Sender<bool>,
}

impl Drop for ZebraSync {
    fn drop(&mut self) {
        let _ = self.relay_stop.send(true);
        self.worker.stop();
    }
}

impl std::fmt::Debug for ZebraSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZebraSync")
            .field("endpoints", &self.endpoints)
            .field("mode", &self.last_mode)
            .field("head_epoch", &self.head_epoch)
            .finish_non_exhaustive()
    }
}

fn push_sync_server(out: &mut Vec<String>, raw: &str, allow_private: bool) {
    if out.len() >= local::SYNC_SERVERS_MAX {
        return;
    }
    if let Ok(norm) = parse_sync_server_url(raw, allow_private) {
        let owned = norm.into_string();
        if !out.contains(&owned) {
            out.push(owned);
        }
    }
}

/// Resolve the active sync endpoints strictly from local prefs, CLI flags, or
/// the default Zebra mesh (never from untrusted external shared-vault hints).
#[must_use]
pub fn resolve_sync_servers(
    prefs: Option<&Prefs>,
    ctx: &Ctx,
    _shared: &[SharedItem],
) -> Vec<String> {
    if prefs.is_some_and(|p| !p.server_sync) {
        return Vec::new();
    }
    let allow_private = ctx.flags.has(Flags::ALLOW_PRIVATE_SYNC);
    let mut out = Vec::new();
    if let Some(urls) = prefs.filter(|p| !p.sync_servers.is_empty()) {
        for u in &urls.sync_servers {
            push_sync_server(&mut out, u, allow_private);
        }
    } else if !ctx.sync_servers.is_empty() {
        for u in &ctx.sync_servers {
            push_sync_server(&mut out, u, allow_private);
        }
    } else if ctx.flags.has(Flags::NET_SYNC) {
        for u in DEFAULT_SYNC_SERVERS {
            push_sync_server(&mut out, u, false);
        }
    }
    out
}

/// Build the deduplicated list of watched personal and shared repositories.
#[must_use]
pub fn build_watched_repos(
    identity: &SyncIdentity,
    vault_id: [u8; 16],
    shared: &[SharedItem],
) -> Vec<WatchedRepo> {
    let mut repos = Vec::new();
    let mut seen: BTreeSet<(u8, [u8; 64])> = BTreeSet::new();
    if let Some(sid) = personal_storage_id(identity)
        && seen.insert((RepoKind::Personal as u8, sid))
    {
        repos.push(WatchedRepo {
            kind: RepoKind::Personal,
            storage_id: sid,
            vault_id,
            shared_proof: None,
        });
    }
    for item in shared {
        if item.my_role.is_none() && item.ready() {
            continue;
        }
        if let Ok((proof, sid)) = SharedRepoProof::issue(
            item.reference.seed.expose(),
            item.reference.vault_id,
            item.reference.anchor,
        ) && let Ok(proof_wire) = proof.encode()
            && seen.insert((RepoKind::Shared as u8, sid))
        {
            repos.push(WatchedRepo {
                kind: RepoKind::Shared,
                storage_id: sid,
                vault_id: item.reference.vault_id,
                shared_proof: Some(proof_wire),
            });
        }
    }
    repos
}

/// Collect current personal records plus this device's signed announcement frame.
#[must_use]
pub fn collect_personal_records(
    vault: &Vault,
    identity: &SyncIdentity,
    wrap_id: Option<[u8; 16]>,
) -> Vec<(u32, u64, [u8; 16], Vec<u8>)> {
    let mut out = Vec::new();
    for entry in session::frontier(&vault.session).unwrap_or_default() {
        if let Ok(raw) = session::latest_frame(&vault.session, entry.record_id) {
            out.push((entry.record_id, entry.revision, entry.origin_device, raw));
        }
    }
    if let Some(dev_id) = identity.device_id()
        && let Ok(entry_wire) =
            PersonalDeviceEntry::issue(identity, vault.session.vault_id(), wrap_id)
    {
        let ann_id = device_announce_record_id(&dev_id);
        let ann_rev = if wrap_id.is_some() { 2 } else { 1 };
        out.push((ann_id, ann_rev, dev_id, entry_wire));
    }
    out
}

impl ZebraSync {
    /// Start background `zsync` client, watch worker, and live P2P relay holder
    /// for `vault`, or return `None` when disabled or placeholder.
    #[must_use]
    pub fn start(
        vault: &Vault,
        identity: Arc<SyncIdentity>,
        shared: &[SharedItem],
        ctx: &Ctx,
    ) -> Option<Box<Self>> {
        if is_placeholder(&vault.paths) || identity.account_gate().is_none() {
            return None;
        }
        let endpoints = resolve_sync_servers(vault.meta.prefs.as_ref(), ctx, shared);
        if endpoints.is_empty() {
            return None;
        }
        let allow_private = ctx.flags.has(Flags::ALLOW_PRIVATE_SYNC);
        let client = Arc::new(
            ZebraClient::new(&endpoints, ctx.extra_ca_pem.as_deref(), allow_private).ok()?,
        );
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .ok()?;
        let vault_id = *vault.session.vault_id();
        let wrap_id = device::owned_id(&vault.paths);
        let repos = build_watched_repos(&identity, vault_id, shared);
        let (worker, worker_rx) = ZebraWorker::spawn(
            rt.handle(),
            Arc::clone(&client),
            Arc::clone(&identity),
            repos,
            Duration::from_millis(800),
        );
        let (msg_tx, msg_rx) = mpsc::channel();
        let initial_frontier = session::frontier(&vault.session).unwrap_or_default();
        let initial_frames = raw_record_pairs(&vault.session);
        let relay_snap = Arc::new(RwLock::new((initial_frontier, initial_frames)));
        let (relay_stop, relay_stop_rx) = watch::channel(false);

        if let (Some(ep), Some(gate), Some(sid)) = (
            client.preferred_endpoint().cloned(),
            identity.account_gate(),
            personal_storage_id(&identity),
        ) && let Ok(creds) = RelayCredentials::derive(gate.expose(), &sid)
        {
            let tls_cfg = Arc::clone(client.tls_config());
            let creds = Arc::new(creds);
            let r_id = Arc::clone(&identity);
            let r_snap = Arc::clone(&relay_snap);
            let r_tx = msg_tx.clone();
            rt.spawn(async move {
                hold_relay_slot(ep, tls_cfg, creds, relay_stop_rx, move |stream| {
                    let id2 = Arc::clone(&r_id);
                    let snap2 = Arc::clone(&r_snap);
                    let tx2 = r_tx.clone();
                    async move {
                        let (mine, frames) = snap2
                            .read()
                            .map_or_else(|_| (Vec::new(), Vec::new()), |g| g.clone());
                        if let Ok(pushed) = relay_sync_responder(stream, &id2, &mine, &frames).await
                            && !pushed.is_empty()
                        {
                            let _ = tx2.send(ZSyncMsg::RelayedFrames(pushed));
                        }
                    }
                })
                .await;
            });
        }

        let last_wraps_tag = wraps_tag(vault.file.as_bytes()).unwrap_or([0u8; 32]);
        let mut sync = Box::new(Self {
            rt,
            client,
            worker,
            worker_rx,
            msg_tx,
            msg_rx,
            identity,
            vault_id,
            wrap_id,
            head_epoch: 0,
            last_wraps_tag,
            shared_epochs: BTreeMap::new(),
            shared_wraps: BTreeMap::new(),
            shared_member_devices: BTreeMap::new(),
            peer_devices: Vec::new(),
            pending_rekeys: Vec::new(),
            personal_queue: PersonalQueue::Idle,
            last_mode: WorkerMode::PollFallback,
            endpoints,
            last_sync_ms: None,
            last_error: None,
            relay_snap,
            relay_stop,
        });
        sync.trigger_reconcile_personal(vault, false, true);
        Some(sync)
    }

    /// Update watched repository list when shared vaults are added or removed.
    pub fn update_watched(&self, shared: &[SharedItem]) {
        self.worker
            .set_repos(build_watched_repos(&self.identity, self.vault_id, shared));
    }

    /// Update the live relay responder snapshot after local personal vault edits.
    pub fn refresh_relay_snapshot(&self, vault: &Vault) {
        let frontier = session::frontier(&vault.session).unwrap_or_default();
        let frames = raw_record_pairs(&vault.session);
        if let Ok(mut guard) = self.relay_snap.write() {
            *guard = (frontier, frames);
        }
    }

    /// Trigger non-blocking Git-frontier reconciliation for the personal vault.
    pub fn trigger_reconcile_personal(
        &mut self,
        vault: &Vault,
        force_head: bool,
        initial_check: bool,
    ) {
        if self.identity.account_gate().is_none() {
            return;
        }
        self.refresh_relay_snapshot(vault);
        match self.personal_queue {
            PersonalQueue::Running {
                force_head: prev_force,
                ..
            } => {
                self.personal_queue = PersonalQueue::Running {
                    dirty: true,
                    force_head: prev_force || force_head,
                };
                return;
            }
            PersonalQueue::Idle => {
                self.personal_queue = PersonalQueue::Running {
                    dirty: false,
                    force_head,
                };
            }
        }
        let cur_wraps = wraps_tag(vault.file.as_bytes()).unwrap_or(self.last_wraps_tag);
        let wraps_changed = cur_wraps != self.last_wraps_tag;
        if wraps_changed || force_head {
            self.last_wraps_tag = cur_wraps;
            self.head_epoch = self
                .head_epoch
                .max(vault.session.generation())
                .saturating_add(1);
        }
        let owned = OwnedPersonalInput {
            vk: vault.session.reopen_key(),
            master_grant: load_master_grant(&vault.paths),
            vault_bytes: Zeroizing::new(vault.file.as_bytes().to_vec()),
            head_meta_plain: encode_personal_head(
                vault.session.vault_id(),
                vault.session.commit_tag(),
                vault.session.generation(),
            )
            .to_vec(),
            generation: vault.session.generation(),
            head_epoch: self.head_epoch,
            records: collect_personal_records(vault, &self.identity, self.wrap_id),
            revocations: self.identity.revocations().all().to_vec(),
            rekeys: std::mem::take(&mut self.pending_rekeys),
            push_head_always: force_head || wraps_changed,
        };
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            let input = PersonalStateInput {
                vk: Some(&owned.vk),
                master_seed: None,
                master_grant: owned.master_grant.as_deref(),
                vault_bytes: &owned.vault_bytes,
                head_meta_plain: &owned.head_meta_plain,
                generation: owned.generation,
                head_epoch: owned.head_epoch,
                records: &owned.records,
                revocations: &owned.revocations,
                rekeys: &owned.rekeys,
                push_head_always: owned.push_head_always,
            };
            match client.reconcile_personal(&identity, input).await {
                Ok(pulled) => {
                    let _ = tx.send(ZSyncMsg::PersonalReconciled {
                        pulled,
                        initial_check,
                    });
                }
                Err(err) => {
                    let _ = tx.send(ZSyncMsg::PersonalFailed {
                        err: err.to_string(),
                        rekeys: owned.rekeys,
                        force_head: owned.push_head_always,
                    });
                }
            }
        });
    }
}

fn raw_record_pairs(session: &session::Session) -> Vec<(u32, Vec<u8>)> {
    session::frontier(session)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            session::latest_frame(session, entry.record_id)
                .ok()
                .map(|raw| (entry.record_id, raw))
        })
        .collect()
}
