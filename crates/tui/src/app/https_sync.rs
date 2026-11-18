//! Asynchronous HTTPS/WSS + `SplitHTTP` sync bridge connecting an unlocked
//! vault to self-hosted or remote [`sync_https`] relay endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use kdf::{personal_mailbox_id, shared_mailbox_id};
use local::{
    PersonalDeviceEntry, Prefs, SharedRef, SyncIdentity, encode_personal_head,
    parse_sync_server_url,
};
use session::Revocation;
use sync_https::{
    MailboxKind, PulledPersonal, PulledShared, ServerSyncWorker, SyncClient, WatchedBox,
    WorkerEvent, WorkerTransport, limits::MAX_SUB_BOXES,
};
use zeroize::Zeroizing;

use crate::app::ctx::Ctx;
use crate::vault::Vault;
use crate::vault::adopt::is_placeholder;
use crate::vault::device;
use crate::vault::shared::SharedItem;

/// Events sent back from background Tokio HTTPS tasks to the UI tick loop.
pub enum HttpsMsg {
    PersonalPulled {
        pulled: Option<PulledPersonal>,
        initial_check: bool,
    },
    SharedPulled {
        vault_id: [u8; 16],
        pulled: Option<PulledShared>,
    },
    CloudBackupPushed,
    CloudBackupPulled(Zeroizing<Vec<u8>>),
    Error(String),
}

impl std::fmt::Debug for HttpsMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersonalPulled { .. } => f.write_str("HttpsMsg::PersonalPulled"),
            Self::SharedPulled { vault_id, .. } => f
                .debug_struct("HttpsMsg::SharedPulled")
                .field("vault_id", vault_id)
                .finish(),
            Self::CloudBackupPushed => f.write_str("HttpsMsg::CloudBackupPushed"),
            Self::CloudBackupPulled(_) => f.write_str("HttpsMsg::CloudBackupPulled([REDACTED])"),
            Self::Error(msg) => f.debug_tuple("HttpsMsg::Error").field(msg).finish(),
        }
    }
}

/// Active background HTTPS/WSS + `SplitHTTP` client and worker for one unlocked vault.
pub struct HttpsSync {
    pub(super) rt: tokio::runtime::Runtime,
    pub client: Arc<SyncClient>,
    pub worker: ServerSyncWorker,
    pub worker_rx: tokio::sync::mpsc::UnboundedReceiver<WorkerEvent>,
    pub msg_tx: mpsc::Sender<HttpsMsg>,
    pub msg_rx: mpsc::Receiver<HttpsMsg>,
    pub identity: Arc<SyncIdentity>,
    pub vault_id: [u8; 16],
    pub wrap_id: Option<[u8; 16]>,
    pub personal_seq: u64,
    pub shared_seqs: BTreeMap<[u8; 16], u64>,
    pub peer_devices: Vec<PersonalDeviceEntry>,
    pub announced_self: bool,
    pub last_transport: WorkerTransport,
    pub endpoints: Vec<String>,
    pub last_sync_ms: Option<u64>,
}

impl std::fmt::Debug for HttpsSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsSync")
            .field("endpoints", &self.endpoints)
            .field("transport", &self.last_transport)
            .field("personal_seq", &self.personal_seq)
            .finish_non_exhaustive()
    }
}

/// Collect unique validated HTTPS/WSS server URLs from saved preferences, CLI flags,
/// and shared vault hints.
#[must_use]
pub fn collect_sync_urls(
    prefs: Option<&Prefs>,
    cli_urls: &[Box<str>],
    shared: &[SharedItem],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |raw: &str| {
        if out.len() >= local::SYNC_SERVERS_MAX {
            return;
        }
        if let Ok(norm) = parse_sync_server_url(raw, true) {
            let owned = norm.into_string();
            if !out.contains(&owned) {
                out.push(owned);
            }
        }
    };
    if let Some(urls) = prefs.filter(|p| !p.sync_servers.is_empty()) {
        for u in &urls.sync_servers {
            push(u);
        }
    } else {
        for u in cli_urls {
            push(u);
        }
    }
    for item in shared {
        for hint in &item.reference.hints {
            if hint.contains("://") {
                push(hint);
            }
        }
    }
    out
}

/// Build the deduplicated set of monitored mailboxes across all configured endpoints.
#[must_use]
pub fn build_watched_boxes(
    client: &SyncClient,
    identity: &SyncIdentity,
    shared: &[SharedItem],
) -> Vec<WatchedBox> {
    let mut boxes = Vec::new();
    let mut seen: BTreeSet<(u8, [u8; 32])> = BTreeSet::new();
    for ep in client.endpoints() {
        if let Some(gate) = identity.account_gate()
            && let Ok(box_id) = personal_mailbox_id(gate.expose(), &ep.origin)
            && seen.insert((MailboxKind::Personal as u8, box_id))
            && boxes.len() < MAX_SUB_BOXES
        {
            boxes.push(WatchedBox {
                kind: MailboxKind::Personal,
                box_id,
                vault_id: [0u8; 16],
            });
        }
        for item in shared {
            if let Ok(box_id) = shared_mailbox_id(
                item.reference.seed.expose(),
                &item.reference.vault_id,
                &ep.origin,
            ) && seen.insert((MailboxKind::Shared as u8, box_id))
                && boxes.len() < MAX_SUB_BOXES
            {
                boxes.push(WatchedBox {
                    kind: MailboxKind::Shared,
                    box_id,
                    vault_id: item.reference.vault_id,
                });
            }
        }
    }
    boxes
}

impl HttpsSync {
    /// Start background HTTPS/WSS + `SplitHTTP` sync for `vault`, or return `None` when
    /// no sync server URL is configured (or the vault is still an adoption placeholder).
    #[must_use]
    pub fn start(
        vault: &Vault,
        identity: Arc<SyncIdentity>,
        shared: &[SharedItem],
        ctx: &Ctx,
    ) -> Option<Box<Self>> {
        if is_placeholder(&vault.paths) {
            return None;
        }
        let endpoints = collect_sync_urls(vault.meta.prefs.as_ref(), &ctx.sync_servers, shared);
        if endpoints.is_empty() {
            return None;
        }
        let proxy = vault
            .meta
            .prefs
            .as_ref()
            .and_then(|p| p.sync_proxy.as_deref())
            .or(ctx.sync_proxy.as_deref());
        let client =
            Arc::new(SyncClient::new(&endpoints, proxy, ctx.extra_ca_pem.as_deref(), true).ok()?);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .ok()?;
        let boxes = build_watched_boxes(&client, &identity, shared);
        let (worker, worker_rx) = ServerSyncWorker::spawn(
            rt.handle(),
            Arc::clone(&client),
            Arc::clone(&identity),
            boxes,
            Duration::from_millis(600),
        );
        let (msg_tx, msg_rx) = mpsc::channel();
        let sync = Box::new(Self {
            rt,
            client,
            worker,
            worker_rx,
            msg_tx,
            msg_rx,
            identity,
            vault_id: *vault.session.vault_id(),
            wrap_id: device::owned_id(&vault.paths),
            personal_seq: 0,
            shared_seqs: BTreeMap::new(),
            peer_devices: Vec::new(),
            announced_self: false,
            last_transport: WorkerTransport::SplitHttpFallback,
            endpoints,
            last_sync_ms: None,
        });
        sync.trigger_pull_personal(true);
        for item in shared {
            sync.trigger_pull_shared(&item.reference);
        }
        Some(sync)
    }

    /// Refresh monitored mailbox subscriptions after shared vaults are added or removed.
    pub fn update_boxes(&self, shared: &[SharedItem]) {
        let boxes = build_watched_boxes(&self.client, &self.identity, shared);
        self.worker.set_boxes(boxes);
    }

    /// Trigger a non-blocking pull of the personal mailbox.
    pub fn trigger_pull_personal(&self, initial_check: bool) {
        if self.identity.account_gate().is_none() {
            return;
        }
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let since = self.personal_seq;
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            match client.pull_personal_state(&identity, since).await {
                Ok(pulled) => {
                    let _ = tx.send(HttpsMsg::PersonalPulled {
                        pulled,
                        initial_check,
                    });
                }
                Err(err) => {
                    let _ = tx.send(HttpsMsg::Error(err.to_string()));
                }
            }
        });
    }

    /// Trigger a non-blocking pull of one shared vault mailbox.
    pub fn trigger_pull_shared(&self, reference: &Arc<SharedRef>) {
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let reference = reference.duplicate();
        let since = self
            .shared_seqs
            .get(&reference.vault_id)
            .copied()
            .unwrap_or(0);
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            let vault_id = reference.vault_id;
            match client
                .pull_shared_state(&identity, reference.seed.expose(), vault_id, since)
                .await
            {
                Ok(pulled) => {
                    let _ = tx.send(HttpsMsg::SharedPulled { vault_id, pulled });
                }
                Err(err) => {
                    let _ = tx.send(HttpsMsg::Error(err.to_string()));
                }
            }
        });
    }

    /// Push this device's signed [`PersonalDeviceEntry`] so peer devices can seal
    /// rotated personal vault keys to us.
    pub fn announce_self(&mut self) {
        if self.announced_self || self.identity.account_gate().is_none() {
            return;
        }
        let Ok(entry_wire) =
            PersonalDeviceEntry::issue(&self.identity, &self.vault_id, self.wrap_id)
        else {
            return;
        };
        self.announced_self = true;
        self.push_personal_frame(entry_wire, 0);
    }

    /// Upload the full encrypted personal snapshot and optional latest record frame.
    pub fn push_personal_snapshot(&self, vault: &Vault) {
        if self.identity.account_gate().is_none() {
            return;
        }
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let file_bytes = vault.file.as_bytes().to_vec();
        let generation = vault.session.generation();
        let head = encode_personal_head(
            vault.session.vault_id(),
            vault.session.commit_tag(),
            generation,
        );
        self.rt.spawn(async move {
            let _ = client
                .push_personal_snapshot(&identity, &file_bytes, &head, generation)
                .await;
        });
    }

    /// Append one outer-sealed personal frame.
    pub fn push_personal_frame(&self, frame_bytes: Vec<u8>, seq_hint: u64) {
        if self.identity.account_gate().is_none() {
            return;
        }
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        self.rt.spawn(async move {
            let _ = client
                .append_personal_frame(&identity, &frame_bytes, seq_hint)
                .await;
        });
    }

    /// Publish an account-signed device revocation.
    pub fn push_personal_revocation(&self, rev: Revocation) {
        if self.identity.account_gate().is_none() {
            return;
        }
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        self.rt.spawn(async move {
            let _ = client.push_personal_revocation(&identity, &rev).await;
        });
    }

    /// Publish one hybrid-PQ encrypted `VK` rekey grant to `target_device`.
    pub fn push_personal_rekey(&self, generation: u64, target_device: [u8; 16], grant: Vec<u8>) {
        if self.identity.account_gate().is_none() {
            return;
        }
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        self.rt.spawn(async move {
            let _ = client
                .push_personal_rekey(&identity, generation, target_device, &grant)
                .await;
        });
    }
}
