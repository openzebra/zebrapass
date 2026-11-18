//! Background sync worker with persistent PQ WSS push notifications and
//! automatic TSPU-resilient `SplitHTTP` fallback polling.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use local::SyncIdentity;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::auth::sign_sub;
use crate::client::SyncClient;
use crate::http_wire::{
    WS_OP_BIN, WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG, ws_client_upgrade, ws_read_frame,
    ws_write_frame,
};
use crate::proxy::{SyncEndpoint, TransportStream, connect_transport};
use crate::wire::MailboxKind;
use crate::wire_rpc::{OpReply, OpStatus, PushEvent};

/// Active transport mode used by [`ServerSyncWorker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerTransport {
    /// Persistent PQ TLS 1.3 WebSocket live push tunnel.
    WssLive,
    /// TSPU-safe short-lived HTTPS `SplitHTTP` polling (`Connection: close`, `<= 6 KiB`).
    SplitHttpFallback,
}

/// Mailbox descriptor watched by [`ServerSyncWorker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchedBox {
    pub kind: MailboxKind,
    pub box_id: [u8; 32],
    /// Zero for personal vault; `vault_id` for shared vaults.
    pub vault_id: [u8; 16],
}

/// Event emitted when a watched mailbox changes or transport mode switches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerEvent {
    /// Remote state changed on one watched mailbox.
    MailboxUpdated {
        kind: MailboxKind,
        vault_id: [u8; 16],
        head_seq: u64,
    },
    /// Worker switched between live WSS and `SplitHTTP` fallback.
    TransportChanged(WorkerTransport),
}

/// Handle controlling a running background [`ServerSyncWorker`].
#[derive(Debug)]
pub struct ServerSyncWorker {
    boxes_tx: watch::Sender<Vec<WatchedBox>>,
    stop_tx: watch::Sender<bool>,
    wake: Arc<Notify>,
    join: Option<JoinHandle<()>>,
}

impl ServerSyncWorker {
    /// Spawn a background worker on `handle` subscribing over WSS and falling
    /// back seamlessly to `SplitHTTP` polling whenever WSS is blocked or reset.
    #[must_use]
    pub fn spawn(
        handle: &tokio::runtime::Handle,
        client: Arc<SyncClient>,
        identity: Arc<SyncIdentity>,
        initial_boxes: Vec<WatchedBox>,
        poll_interval: Duration,
    ) -> (Self, mpsc::UnboundedReceiver<WorkerEvent>) {
        let (boxes_tx, boxes_rx) = watch::channel(initial_boxes);
        let (stop_tx, stop_rx) = watch::channel(false);
        let wake = Arc::new(Notify::new());
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let join = handle.spawn(worker_loop(
            client,
            identity,
            boxes_rx,
            stop_rx,
            Arc::clone(&wake),
            ev_tx,
            poll_interval.max(Duration::from_millis(250)),
        ));
        (
            Self {
                boxes_tx,
                stop_tx,
                wake,
                join: Some(join),
            },
            ev_rx,
        )
    }

    /// Update the set of monitored mailboxes.
    pub fn set_boxes(&self, boxes: Vec<WatchedBox>) {
        let _ = self.boxes_tx.send(boxes);
        self.wake.notify_waiters();
    }

    /// Stop the worker cleanly.
    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(true);
        self.wake.notify_waiters();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl Drop for ServerSyncWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn worker_loop(
    client: Arc<SyncClient>,
    identity: Arc<SyncIdentity>,
    mut boxes_rx: watch::Receiver<Vec<WatchedBox>>,
    stop_rx: watch::Receiver<bool>,
    wake: Arc<Notify>,
    ev_tx: mpsc::UnboundedSender<WorkerEvent>,
    poll_interval: Duration,
) {
    let mut seen_seq: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut last_ws_attempt: Option<Instant> = None;
    let ws_retry_backoff = Duration::from_secs(30);

    while !*stop_rx.borrow() {
        let boxes = boxes_rx.borrow_and_update().clone();
        if boxes.is_empty() {
            let _ = timeout(Duration::from_millis(500), wake.notified()).await;
            continue;
        }

        let try_ws = last_ws_attempt.is_none_or(|t| t.elapsed() >= ws_retry_backoff);
        if try_ws {
            last_ws_attempt = Some(Instant::now());
            if run_wss_session(
                &client,
                &identity,
                &boxes_rx,
                &stop_rx,
                &wake,
                &ev_tx,
                &mut seen_seq,
            )
            .await
            .is_ok()
            {
                if *stop_rx.borrow() {
                    break;
                }
                continue;
            }
            let _ = ev_tx.send(WorkerEvent::TransportChanged(
                WorkerTransport::SplitHttpFallback,
            ));
        }

        let current_boxes = boxes_rx.borrow().clone();
        poll_once_all(&client, &identity, &current_boxes, &ev_tx, &mut seen_seq).await;
        let _ = timeout(poll_interval, wake.notified()).await;
    }
}

async fn poll_once_all(
    client: &SyncClient,
    identity: &SyncIdentity,
    boxes: &[WatchedBox],
    ev_tx: &mpsc::UnboundedSender<WorkerEvent>,
    seen_seq: &mut BTreeMap<[u8; 32], u64>,
) {
    for wb in boxes {
        for ep in client.endpoints() {
            if let Ok(summary) = client
                .post_state(ep, identity, wb.box_id, wb.kind, 0, 0)
                .await
            {
                let prev = seen_seq.get(&wb.box_id).copied().unwrap_or(0);
                if summary.exists && summary.head_seq > prev {
                    seen_seq.insert(wb.box_id, summary.head_seq);
                    let _ = ev_tx.send(WorkerEvent::MailboxUpdated {
                        kind: wb.kind,
                        vault_id: wb.vault_id,
                        head_seq: summary.head_seq,
                    });
                }
                break;
            }
        }
    }
}

async fn ws_upgrade_and_sub(
    client: &SyncClient,
    ep: &SyncEndpoint,
    identity: &SyncIdentity,
    boxes: &[WatchedBox],
) -> anyhow::Result<TransportStream> {
    for wb in boxes {
        match wb.kind {
            MailboxKind::Personal => {
                let _ = client.ensure_personal_cert(ep, identity, wb.box_id).await;
            }
            MailboxKind::Shared => {
                let _ = client
                    .ensure_shared_cert(ep, identity, wb.box_id, None)
                    .await;
            }
        }
    }
    let (mut stream, _) =
        connect_transport(ep, client.proxy().map(Arc::as_ref), client.tls_config()).await?;
    let ws_path = format!("/{}/v1/ws", ep.slug);
    ws_client_upgrade(&mut stream, &ws_path, &ep.host_header()).await?;
    let sub_boxes: Vec<(MailboxKind, [u8; 32])> =
        boxes.iter().map(|b| (b.kind, b.box_id)).collect();
    let sub = sign_sub(identity, &ep.origin, sub_boxes)?;
    ws_write_frame(&mut stream, WS_OP_BIN, &sub.encode()?, true).await?;
    let (op, ack_bytes) = ws_read_frame(&mut stream, false, Some(Duration::from_secs(10))).await?;
    if op != WS_OP_BIN || OpReply::decode(&ack_bytes)?.status != OpStatus::Ok {
        anyhow::bail!("WebSocket subscription rejected");
    }
    Ok(stream)
}

fn spawn_sub_updater(
    boxes_rx: &watch::Receiver<Vec<WatchedBox>>,
    stop_rx: &watch::Receiver<bool>,
    wake: &Arc<Notify>,
    writer: Arc<AsyncMutex<tokio::io::WriteHalf<TransportStream>>>,
    shared_boxes: Arc<Mutex<Vec<WatchedBox>>>,
    identity: Arc<SyncIdentity>,
    ep: SyncEndpoint,
) -> JoinHandle<()> {
    let mut updater_rx = boxes_rx.clone();
    let updater_stop = stop_rx.clone();
    let updater_wake = Arc::clone(wake);
    tokio::spawn(async move {
        while !*updater_stop.borrow() {
            let _ = timeout(Duration::from_millis(500), updater_wake.notified()).await;
            if *updater_stop.borrow() {
                let mut w = writer.lock().await;
                let _ = ws_write_frame(&mut *w, WS_OP_CLOSE, &[], true).await;
                drop(w);
                break;
            }
            if updater_rx.has_changed().unwrap_or(false) {
                let latest = updater_rx.borrow_and_update().clone();
                if let Ok(mut guard) = shared_boxes.lock() {
                    (*guard).clone_from(&latest);
                }
                let next_boxes: Vec<(MailboxKind, [u8; 32])> =
                    latest.iter().map(|b| (b.kind, b.box_id)).collect();
                if next_boxes.is_empty() {
                    continue;
                }
                if let Ok(new_sub) = sign_sub(&identity, &ep.origin, next_boxes)
                    && let Ok(enc) = new_sub.encode()
                {
                    let mut w = writer.lock().await;
                    if ws_write_frame(&mut *w, WS_OP_BIN, &enc, true)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    })
}

async fn run_wss_session(
    client: &SyncClient,
    identity: &Arc<SyncIdentity>,
    boxes_rx: &watch::Receiver<Vec<WatchedBox>>,
    stop_rx: &watch::Receiver<bool>,
    wake: &Arc<Notify>,
    ev_tx: &mpsc::UnboundedSender<WorkerEvent>,
    seen_seq: &mut BTreeMap<[u8; 32], u64>,
) -> anyhow::Result<()> {
    let initial_boxes = boxes_rx.borrow().clone();
    for ep in client.endpoints().to_vec() {
        let Ok(stream) = ws_upgrade_and_sub(client, &ep, identity, &initial_boxes).await else {
            continue;
        };
        let _ = ev_tx.send(WorkerEvent::TransportChanged(WorkerTransport::WssLive));

        let shared_boxes = Arc::new(Mutex::new(initial_boxes));
        let (mut ws_read, ws_write) = tokio::io::split(stream);
        let writer = Arc::new(AsyncMutex::new(ws_write));
        let updater = spawn_sub_updater(
            boxes_rx,
            stop_rx,
            wake,
            Arc::clone(&writer),
            Arc::clone(&shared_boxes),
            Arc::clone(identity),
            ep,
        );

        let mut res = Ok(());
        while !*stop_rx.borrow() {
            let frame = ws_read_frame(&mut ws_read, false, Some(Duration::from_secs(30))).await;
            let (opcode, payload) = match frame {
                Ok(pair) => pair,
                Err(err) if err.to_string().contains("timed out") => continue,
                Err(err) => {
                    res = Err(err);
                    break;
                }
            };
            match opcode {
                WS_OP_CLOSE => {
                    res = Err(anyhow::anyhow!("WSS closed by peer"));
                    break;
                }
                WS_OP_PING => {
                    let mut w = writer.lock().await;
                    if let Err(err) = ws_write_frame(&mut *w, WS_OP_PONG, &payload, true).await {
                        res = Err(err);
                        break;
                    }
                }
                WS_OP_BIN if payload.starts_with(b"ZPPW") => {
                    let ev = PushEvent::decode(&payload)?;
                    seen_seq.insert(ev.box_id, ev.head_seq);
                    let vault_id = shared_boxes
                        .lock()
                        .ok()
                        .and_then(|list| {
                            list.iter()
                                .find(|b| b.box_id == ev.box_id)
                                .map(|b| b.vault_id)
                        })
                        .unwrap_or([0u8; 16]);
                    let _ = ev_tx.send(WorkerEvent::MailboxUpdated {
                        kind: ev.kind,
                        vault_id,
                        head_seq: ev.head_seq,
                    });
                }
                _ => {}
            }
        }
        updater.abort();
        return res;
    }
    Err(anyhow::anyhow!("no WSS endpoint reachable"))
}
