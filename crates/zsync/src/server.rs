//! PQ TLS 1.3 `ZebraPass` sync, live P2P relay, and authenticated parallel mesh server.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use secret::Secret;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::limits::{IO_TIMEOUT, MAX_CONNS, MAX_SMALL_FRAME, MAX_WIRE_FRAME};
use crate::mesh::{fanout_accepted, serve_peer_mesh, spawn_mesh_loops};
use crate::mesh_auth::{MeshAuthConfig, MeshRuntime};
use crate::relay::{RelayHub, serve_relay};
use crate::replay::IpLimiter;
use crate::repo_disk::RepoStore;
use crate::tls::{client_config, server_config_pem};
use crate::wire::{
    RepoKind, StorageId, StreamRole, TAG_ACK, TAG_DELTA, TAG_DIFF, TAG_FRONTIER, TAG_WATCH_EVENT,
    TAG_WATCH_SUB, WatchEvent, read_wire, write_wire,
};
use crate::wire_codec::{
    decode_delta, decode_frontier, decode_watch_sub, encode_diff, encode_watch_event,
};

/// Configuration for running [`start_server`].
pub struct ZebraServerConfig {
    /// TCP bind socket (port `0` allowed for ephemeral tests).
    pub listen: SocketAddr,
    /// PEM-encoded leaf/chain certificate.
    pub cert_pem: Vec<u8>,
    /// Zeroizing PEM-encoded TLS private key.
    pub key_pem: Secret<Vec<u8>>,
    /// Optional extra trusted CA PEM for dialing peer mesh servers.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// Persistent repository storage directory.
    pub data_dir: PathBuf,
    /// Optional mutual `ML-DSA-65` mesh authentication & peer list. When `None`,
    /// `StreamRole::PeerMesh` is completely disabled.
    pub mesh: Option<MeshAuthConfig>,
    /// Anti-entropy bidirectional mesh sync interval.
    pub mesh_interval: Duration,
    /// Allow loopback and private/RFC1918 peer addresses (for local cluster tests).
    pub allow_private: bool,
}

impl std::fmt::Debug for ZebraServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZebraServerConfig")
            .field("listen", &self.listen)
            .field("data_dir", &self.data_dir)
            .field("has_mesh", &self.mesh.is_some())
            .field("allow_private", &self.allow_private)
            .finish_non_exhaustive()
    }
}

/// Running `ZebraPass` sync/relay server handle.
#[derive(Debug)]
pub struct ZebraServerHandle {
    pub local_addr: SocketAddr,
    pub endpoint: Box<str>,
    shutdown: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
}

impl ZebraServerHandle {
    /// Trigger graceful shutdown and await task completion.
    pub async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for ZebraServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

struct ServerCtx {
    store: Arc<RepoStore>,
    relay: Arc<RelayHub>,
    limiter: Arc<IpLimiter>,
    mesh: Option<Arc<MeshRuntime>>,
    watch_tx: broadcast::Sender<WatchEvent>,
    acceptor: TlsAcceptor,
}

/// Start the unified PQ TLS 1.3 sync, live relay, and authenticated parallel mesh server.
///
/// # Errors
///
/// Invalid TLS certs/keys, peer URL/key parse error, storage open error, or bind failure.
pub async fn start_server(cfg: ZebraServerConfig) -> anyhow::Result<ZebraServerHandle> {
    let tls_srv = server_config_pem(&cfg.cert_pem, &cfg.key_pem)?;
    let tls_cli = client_config(cfg.extra_ca_pem.as_deref())?;
    let mesh = cfg
        .mesh
        .map(|m| MeshRuntime::from_config(m, tls_cli, cfg.allow_private))
        .transpose()?;
    let store = Arc::new(RepoStore::open(&cfg.data_dir)?);
    let relay = Arc::new(RelayHub::default());
    let limiter = Arc::new(IpLimiter::default());
    let (watch_tx, _) = broadcast::channel(512);
    let (shutdown, shutdown_rx) = watch::channel(false);

    spawn_mesh_loops(
        mesh.as_ref(),
        &store,
        &watch_tx,
        cfg.mesh_interval,
        &shutdown_rx,
    );

    let listener = TcpListener::bind(cfg.listen).await?;
    let local_addr = listener.local_addr()?;
    let endpoint = format!("127.0.0.1:{}", local_addr.port()).into_boxed_str();
    let ctx = Arc::new(ServerCtx {
        store,
        relay,
        limiter,
        mesh,
        watch_tx,
        acceptor: TlsAcceptor::from(tls_srv),
    });
    let sem = Arc::new(Semaphore::new(MAX_CONNS));

    let join = tokio::spawn(async move {
        let step = Duration::from_millis(100);
        while !*shutdown_rx.borrow() {
            let Ok(Ok(permit)) = timeout(step, Arc::clone(&sem).acquire_owned()).await else {
                continue;
            };
            let Ok(Ok((tcp, peer_addr))) = timeout(step, listener.accept()).await else {
                continue;
            };
            let Some(ip_guard) = ctx.limiter.try_acquire_conn(peer_addr.ip()) else {
                continue;
            };
            let c = Arc::clone(&ctx);
            let s = shutdown_rx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ip_guard = ip_guard;
                let _ = handle_conn(tcp, peer_addr, c, s).await;
            });
        }
    });

    Ok(ZebraServerHandle {
        local_addr,
        endpoint,
        shutdown,
        join: Some(join),
    })
}

async fn handle_conn(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    ctx: Arc<ServerCtx>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let _ = tcp.set_nodelay(true);
    let mut tls = timeout(IO_TIMEOUT, ctx.acceptor.accept(tcp)).await??;
    let mut role_byte = [0u8; 1];
    timeout(IO_TIMEOUT, tls.read_exact(&mut role_byte)).await??;
    let [role] = role_byte;
    match StreamRole::try_from(role)? {
        StreamRole::ClientRpc => serve_client_rpc(ctx, tls).await,
        StreamRole::ClientWatch => serve_client_watch(ctx, tls, shutdown).await,
        StreamRole::Relay => {
            serve_relay(
                Arc::clone(&ctx.relay),
                Arc::clone(&ctx.limiter),
                tls,
                peer_addr,
            )
            .await
        }
        StreamRole::PeerMesh => {
            let Some(mesh) = ctx.mesh.clone() else {
                anyhow::bail!("peer mesh disabled");
            };
            serve_peer_mesh(mesh, Arc::clone(&ctx.store), ctx.watch_tx.clone(), tls).await
        }
    }
}

async fn serve_client_rpc(
    ctx: Arc<ServerCtx>,
    mut tls: ServerTlsStream<TcpStream>,
) -> anyhow::Result<()> {
    let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await??;
    if tag != TAG_FRONTIER {
        anyhow::bail!("expected client frontier");
    }
    let frontier = decode_frontier(&body)?;
    let (pull, wanted) = ctx.store.client_diff(&frontier).await?;
    timeout(
        IO_TIMEOUT,
        write_wire(&mut tls, TAG_DIFF, &encode_diff(&pull, &wanted)?),
    )
    .await??;

    let Ok(Ok((dtag, dbody))) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await
    else {
        return Ok(());
    };
    if dtag != TAG_DELTA {
        return Ok(());
    }
    let delta = decode_delta(&dbody)?;
    if delta.kind != frontier.kind || !secret::ct_eq(&delta.storage_id, &frontier.storage_id) {
        anyhow::bail!("delta repository mismatch");
    }
    if !delta.is_empty() {
        let (accepted, changed) = ctx.store.apply_and_save(&delta).await?;
        if changed {
            let _ = ctx.watch_tx.send(WatchEvent {
                kind: delta.kind,
                storage_id: delta.storage_id,
            });
            fanout_accepted(ctx.mesh.as_ref(), &accepted);
        }
    }
    let _ = timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_ACK, &[])).await;
    Ok(())
}

async fn serve_client_watch(
    ctx: Arc<ServerCtx>,
    mut tls: ServerTlsStream<TcpStream>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await??;
    if tag != TAG_WATCH_SUB {
        anyhow::bail!("expected watch sub");
    }
    let sub = decode_watch_sub(&body)?;
    if !ctx.store.verify_watch_sub(&sub).await {
        anyhow::bail!("watch subscription rejected");
    }
    timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_ACK, &[])).await??;

    let subs: BTreeSet<(RepoKind, StorageId)> = sub.repos.into_iter().collect();
    let mut rx = ctx.watch_tx.subscribe();
    let (mut tls_r, mut tls_w) = tokio::io::split(tls);
    let (eof_tx, mut eof_rx) = oneshot::channel::<()>();
    let read_task = tokio::spawn(async move {
        let mut buf = [0u8; 16];
        let _ = tls_r.read(&mut buf).await;
        drop(eof_tx);
    });

    while !*shutdown.borrow() {
        if matches!(eof_rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)) {
            break;
        }
        match timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(we)) if subs.contains(&(we.kind, we.storage_id)) => {
                let enc = encode_watch_event(we);
                if write_wire(&mut tls_w, TAG_WATCH_EVENT, &enc).await.is_err() {
                    break;
                }
            }
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) | Err(_) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
        }
    }
    read_task.abort();
    Ok(())
}
