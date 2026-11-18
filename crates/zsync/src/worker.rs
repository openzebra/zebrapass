//! Persistent PQ TLS 1.3 watch stream worker with automatic poll fallback.

use std::sync::Arc;
use std::time::{Duration, Instant};

use local::SyncIdentity;
use syncwire::encode_cert;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::auth::sign_watch;
use crate::client::ZebraClient;
use crate::limits::{IO_TIMEOUT, MAX_SMALL_FRAME};
use crate::tls::{Endpoint, connect_tls};
use crate::wire::{
    RepoKind, StorageId, StreamRole, TAG_ACK, TAG_WATCH_EVENT, TAG_WATCH_SUB, WatchEvent,
    read_wire, write_wire,
};
use crate::wire_codec::{decode_watch_event, encode_watch_sub};

/// Monitored repository entry mapped back to the UI's `vault_id`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchedRepo {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub vault_id: [u8; 16],
}

/// Active transport mode of [`ZebraWorker`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkerMode {
    LiveWatch,
    #[default]
    PollFallback,
}

/// Notification pushed from the background watch worker to the TUI event loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerEvent {
    ModeChanged(WorkerMode),
    RepoChanged {
        kind: RepoKind,
        storage_id: StorageId,
        vault_id: [u8; 16],
    },
}

/// Background push-notification watcher over [`StreamRole::ClientWatch`].
pub struct ZebraWorker {
    repos_tx: watch::Sender<Vec<WatchedRepo>>,
    stop_tx: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ZebraWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZebraWorker").finish_non_exhaustive()
    }
}

impl ZebraWorker {
    /// Spawn a background worker watching `repos` on the preferred endpoint.
    #[must_use]
    pub fn spawn(
        handle: &tokio::runtime::Handle,
        client: Arc<ZebraClient>,
        identity: Arc<SyncIdentity>,
        repos: Vec<WatchedRepo>,
        poll_interval: Duration,
    ) -> (Self, mpsc::UnboundedReceiver<WorkerEvent>) {
        let (repos_tx, repos_rx) = watch::channel(repos);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let state = WorkerState {
            client,
            identity,
            repos_rx,
            stop_rx,
            ev_tx,
            mode: WorkerMode::PollFallback,
        };
        let join = handle.spawn(state.run(poll_interval));
        (
            Self {
                repos_tx,
                stop_tx,
                join: Some(join),
            },
            ev_rx,
        )
    }

    /// Update the set of monitored personal and shared repositories.
    pub fn set_repos(&self, repos: Vec<WatchedRepo>) {
        let _ = self.repos_tx.send(repos);
    }

    /// Request background shutdown.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

impl Drop for ZebraWorker {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

struct WorkerState {
    client: Arc<ZebraClient>,
    identity: Arc<SyncIdentity>,
    repos_rx: watch::Receiver<Vec<WatchedRepo>>,
    stop_rx: watch::Receiver<bool>,
    ev_tx: mpsc::UnboundedSender<WorkerEvent>,
    mode: WorkerMode,
}

impl WorkerState {
    async fn run(mut self, poll_interval: Duration) {
        while !*self.stop_rx.borrow() {
            let repos = self.repos_rx.borrow_and_update().clone();
            if repos.is_empty() {
                self.wait_repos_or_stop(Duration::from_secs(60)).await;
                continue;
            }

            let mut connected = false;
            let preferred = self.client.preferred_endpoint().cloned();
            let candidates: Vec<Endpoint> = preferred
                .into_iter()
                .chain(self.client.endpoints().iter().cloned())
                .collect();

            for ep in candidates {
                if *self.stop_rx.borrow() {
                    return;
                }
                if self.watch_endpoint(&ep, &repos).await {
                    connected = true;
                    break;
                }
            }

            if !connected {
                if self.mode != WorkerMode::PollFallback {
                    self.mode = WorkerMode::PollFallback;
                    let _ = self.ev_tx.send(WorkerEvent::ModeChanged(self.mode));
                }
                emit_all(&self.ev_tx, &repos);
                self.wait_repos_or_stop(poll_interval).await;
            }
        }
    }

    async fn wait_repos_or_stop(&mut self, dur: Duration) {
        let step = Duration::from_millis(120);
        let mut elapsed = Duration::ZERO;
        while elapsed < dur {
            if *self.stop_rx.borrow() {
                return;
            }
            let wait_for = dur.saturating_sub(elapsed).min(step);
            if timeout(wait_for, self.repos_rx.changed()).await.is_ok() {
                return;
            }
            elapsed = elapsed.saturating_add(wait_for);
        }
    }

    async fn watch_endpoint(&mut self, ep: &Endpoint, repos: &[WatchedRepo]) -> bool {
        let Some(sub_bytes) = build_watch_sub(&self.identity, repos) else {
            return false;
        };
        let Ok((mut tls, _)) = connect_tls(ep, self.client.tls_config()).await else {
            return false;
        };
        if !matches!(
            timeout(IO_TIMEOUT, tls.write_all(&[StreamRole::ClientWatch as u8])).await,
            Ok(Ok(()))
        ) || !matches!(
            timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_WATCH_SUB, &sub_bytes)).await,
            Ok(Ok(()))
        ) {
            return false;
        }
        let Ok(Ok((TAG_ACK, _))) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await
        else {
            return false;
        };

        if self.mode != WorkerMode::LiveWatch {
            self.mode = WorkerMode::LiveWatch;
            let _ = self.ev_tx.send(WorkerEvent::ModeChanged(self.mode));
        }
        emit_all(&self.ev_tx, repos);

        let (mut tls_r, _tls_w) = tokio::io::split(tls);
        let (in_tx, mut in_rx) = mpsc::channel::<WatchEvent>(32);
        let read_task = tokio::spawn(async move {
            while let Ok((TAG_WATCH_EVENT, body)) = read_wire(&mut tls_r, MAX_SMALL_FRAME).await {
                if let Ok(we) = decode_watch_event(&body)
                    && in_tx.send(we).await.is_err()
                {
                    break;
                }
            }
        });

        let mut last_sync = Instant::now();
        let safety_refresh = Duration::from_secs(12);
        let res = loop {
            if *self.stop_rx.borrow() || self.repos_rx.has_changed().unwrap_or(false) {
                break true;
            }
            match timeout(Duration::from_millis(150), in_rx.recv()).await {
                Ok(Some(we)) => {
                    for r in repos {
                        if r.kind == we.kind && r.storage_id == we.storage_id {
                            let _ = self.ev_tx.send(WorkerEvent::RepoChanged {
                                kind: r.kind,
                                storage_id: r.storage_id,
                                vault_id: r.vault_id,
                            });
                        }
                    }
                    last_sync = Instant::now();
                }
                Ok(None) => break false,
                Err(_) if last_sync.elapsed() >= safety_refresh => {
                    emit_all(&self.ev_tx, repos);
                    last_sync = Instant::now();
                }
                Err(_) => {}
            }
        };
        read_task.abort();
        sleep(Duration::ZERO).await;
        res
    }
}

fn build_watch_sub(identity: &SyncIdentity, repos: &[WatchedRepo]) -> Option<Vec<u8>> {
    let cert = identity.devices().first()?;
    let cert_wire = encode_cert(cert).ok()?;
    let pairs: Vec<(RepoKind, StorageId)> = repos.iter().map(|r| (r.kind, r.storage_id)).collect();
    let sub = sign_watch(
        &identity.sign_key(),
        cert.device_id,
        pairs,
        cert_wire,
        Some(Box::new(*identity.root_vk())),
    )
    .ok()?;
    encode_watch_sub(&sub).ok()
}

fn emit_all(ev_tx: &mpsc::UnboundedSender<WorkerEvent>, repos: &[WatchedRepo]) {
    for r in repos {
        let _ = ev_tx.send(WorkerEvent::RepoChanged {
            kind: r.kind,
            storage_id: r.storage_id,
            vault_id: r.vault_id,
        });
    }
}
