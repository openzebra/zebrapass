//! Zero-knowledge PQ TLS 1.3 WebSocket + `SplitHTTP` sync and backup server
//! with `WebTunnel` active-probing camouflage.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::camouflage::{Route, classify_request, write_decoy_response, write_forbidden_response};
use crate::http_wire::{
    WS_OP_BIN, WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG, header_value, read_http_request,
    write_http_response, ws_accept_token, ws_read_frame, ws_write_frame,
};
use crate::limits::{IO_TIMEOUT_SECS, MAX_CONNECTIONS, MAX_SECRET_SLUG_LEN, MIN_SECRET_SLUG_LEN};
use crate::store::MailboxStore;
use crate::tls::server_config_pem;
use crate::wire_rpc::{ChunkQuery, OpReply, OpStatus, PushEvent, SignedOp, SignedSub, StateQuery};

/// Configuration for running an embedded or `--server` [`SyncServerHandle`].
#[derive(Clone, Debug)]
pub struct SyncServerConfig {
    /// Local TCP listen socket (port `0` allowed for ephemeral test binding).
    pub listen: SocketAddr,
    /// PEM-encoded leaf (+ intermediate chain) certificate bytes.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded TLS private key bytes.
    pub key_pem: Vec<u8>,
    /// Persistent mailbox & opaque chunk storage directory.
    pub data_dir: PathBuf,
    /// `WebTunnel` camouflage secret URL prefix segment (`>= 16` bytes).
    pub secret_slug: Box<str>,
    /// Public origin string bound inside client `ML-DSA-65` signatures
    /// (e.g. `https://sync.example.com` or `https://localhost:0`). A trailing
    /// `:0` is replaced with the actual bound TCP port.
    pub public_origin: Box<str>,
}

/// Running server instance with bound address, origin, and clean shutdown.
#[derive(Debug)]
pub struct SyncServerHandle {
    /// Actual bound listening socket address.
    pub local_addr: SocketAddr,
    /// Effective origin string bound into signed requests.
    pub origin: Box<str>,
    shutdown: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
}

impl SyncServerHandle {
    /// Full client-facing HTTPS URL including the secret `WebTunnel` slug.
    #[must_use]
    pub fn endpoint_url(&self, slug: &str) -> String {
        format!("{}/{}", self.origin, slug)
    }

    /// Trigger asynchronous shutdown and await task completion.
    pub async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for SyncServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

struct SharedState {
    slug: Box<str>,
    store: Mutex<MailboxStore>,
    push_tx: broadcast::Sender<PushEvent>,
    acceptor: TlsAcceptor,
}

fn validate_slug(slug: &str) -> anyhow::Result<()> {
    if slug.len() < MIN_SECRET_SLUG_LEN
        || slug.len() > MAX_SECRET_SLUG_LEN
        || slug.starts_with('/')
        || slug.ends_with('/')
        || slug.contains("//")
        || slug.contains("..")
        || !slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/'))
    {
        anyhow::bail!("invalid secret path slug");
    }
    Ok(())
}

fn resolve_origin(raw_origin: &str, bound: SocketAddr) -> Box<str> {
    raw_origin.strip_suffix(":0").map_or_else(
        || raw_origin.into(),
        |prefix| format!("{prefix}:{}", bound.port()).into_boxed_str(),
    )
}

/// Start the HTTPS/WSS + `SplitHTTP` zero-knowledge sync and backup server.
///
/// # Errors
///
/// Invalid secret slug, invalid TLS certificate/key PEM, store initialization
/// failure, or TCP bind failure.
pub async fn start_server(cfg: SyncServerConfig) -> anyhow::Result<SyncServerHandle> {
    validate_slug(&cfg.secret_slug)?;
    let tls_cfg = server_config_pem(&cfg.cert_pem, &cfg.key_pem)?;
    let listener = TcpListener::bind(cfg.listen).await?;
    let local_addr = listener.local_addr()?;
    let origin = resolve_origin(&cfg.public_origin, local_addr);
    let store = MailboxStore::open(cfg.data_dir, origin.clone())?;
    let (push_tx, _) = broadcast::channel(512);
    let state = Arc::new(SharedState {
        slug: cfg.secret_slug,
        store: Mutex::new(store),
        push_tx,
        acceptor: TlsAcceptor::from(tls_cfg),
    });
    let (shutdown, shutdown_rx) = watch::channel(false);
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let join = tokio::spawn(async move {
        while !*shutdown_rx.borrow() {
            if let Ok(Ok((tcp, _peer))) =
                timeout(Duration::from_millis(150), listener.accept()).await
            {
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    drop(tcp);
                    continue;
                };
                let st = Arc::clone(&state);
                let conn_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_tcp_conn(tcp, st, conn_shutdown).await;
                });
            }
        }
    });

    Ok(SyncServerHandle {
        local_addr,
        origin,
        shutdown,
        join: Some(join),
    })
}

async fn handle_tcp_conn(
    tcp: TcpStream,
    state: Arc<SharedState>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let _ = tcp.set_nodelay(true);
    let mut tls = timeout(
        Duration::from_secs(IO_TIMEOUT_SECS),
        state.acceptor.accept(tcp),
    )
    .await
    .map_err(|_| anyhow!("server TLS accept timeout"))??;

    let Some(req) = read_http_request(&mut tls).await? else {
        return Ok(());
    };
    let route = classify_request(&req.method, &req.path, &state.slug);
    match route {
        Route::DecoyHome { .. } | Route::DecoyFavicon | Route::NotFound => {
            write_decoy_response(&mut tls, route).await
        }
        Route::ApiOp => {
            let reply_bytes = match SignedOp::decode(&req.body) {
                Ok(op) => {
                    let (reply, push) = {
                        let mut guard = state
                            .store
                            .lock()
                            .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
                        guard.apply_op(&op)
                    };
                    if let Some(ev) = push {
                        let _ = state.push_tx.send(ev);
                    }
                    reply.encode()
                }
                Err(_) => OpReply {
                    status: OpStatus::Rejected,
                    head_seq: 0,
                    member_count: 0,
                }
                .encode(),
            };
            write_binary_ok(&mut tls, &reply_bytes).await
        }
        Route::ApiState => {
            let Ok(q) = StateQuery::decode(&req.body) else {
                return write_decoy_response(&mut tls, Route::NotFound).await;
            };
            let summary = {
                let mut guard = state
                    .store
                    .lock()
                    .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
                guard.query_state(&q)
            };
            write_binary_ok(&mut tls, &summary.encode()?).await
        }
        Route::ApiChunk => {
            let Ok(q) = ChunkQuery::decode(&req.body) else {
                return write_decoy_response(&mut tls, Route::NotFound).await;
            };
            let chunk = {
                let mut guard = state
                    .store
                    .lock()
                    .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
                guard.query_chunk(&q)
            };
            write_binary_ok(&mut tls, &chunk.encode()?).await
        }
        Route::ApiWs => handle_websocket(tls, &req.headers, state, shutdown).await,
    }
}

async fn write_binary_ok<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> anyhow::Result<()> {
    write_http_response(
        writer,
        200,
        "OK",
        &[
            ("Server", "nginx"),
            ("Content-Type", "application/octet-stream"),
            ("Cache-Control", "no-store"),
            ("Connection", "close"),
        ],
        body,
    )
    .await
}

async fn handle_websocket<S>(
    mut tls: S,
    headers: &[(Box<str>, Box<str>)],
    state: Arc<SharedState>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    if header_value(headers, "origin").is_some() {
        return write_forbidden_response(&mut tls).await;
    }
    let is_upgrade =
        header_value(headers, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let Some(ws_key) = header_value(headers, "sec-websocket-key") else {
        return write_decoy_response(&mut tls, Route::NotFound).await;
    };
    if !is_upgrade || ws_key.trim().is_empty() {
        return write_decoy_response(&mut tls, Route::NotFound).await;
    }
    let accept = ws_accept_token(ws_key);
    write_http_response(
        &mut tls,
        101,
        "Switching Protocols",
        &[
            ("Server", "nginx"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", &accept),
        ],
        &[],
    )
    .await?;

    let (op, first_payload) =
        ws_read_frame(&mut tls, true, Some(Duration::from_secs(IO_TIMEOUT_SECS))).await?;
    if op != WS_OP_BIN {
        return Ok(());
    }
    let sub = SignedSub::decode(&first_payload)?;
    let status = {
        let mut guard = state
            .store
            .lock()
            .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
        guard.verify_subscription(&sub)
    };
    let ack = OpReply {
        status,
        head_seq: 0,
        member_count: 0,
    };
    ws_write_frame(&mut tls, WS_OP_BIN, &ack.encode(), false).await?;
    if status != OpStatus::Ok {
        return Ok(());
    }

    let initial_set: BTreeSet<(u8, [u8; 32])> =
        sub.boxes.into_iter().map(|(k, id)| (k as u8, id)).collect();
    let subscribed = Arc::new(Mutex::new(initial_set));
    let (mut ws_read, ws_write) = tokio::io::split(tls);
    let writer = Arc::new(AsyncMutex::new(ws_write));
    let forwarder = spawn_push_forwarder(
        Arc::clone(&writer),
        Arc::clone(&subscribed),
        &state,
        shutdown.clone(),
    );
    let loop_res = run_ws_read_loop(&mut ws_read, &writer, &subscribed, &state, &shutdown).await;
    forwarder.abort();
    loop_res
}

type BoxSubs = Arc<Mutex<BTreeSet<(u8, [u8; 32])>>>;

fn spawn_push_forwarder<W>(
    push_writer: Arc<AsyncMutex<W>>,
    push_sub: BoxSubs,
    state: &SharedState,
    mut fwd_shutdown: watch::Receiver<bool>,
) -> JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut rx = state.push_tx.subscribe();
    tokio::spawn(async move {
        loop {
            match timeout(Duration::from_millis(250), rx.recv()).await {
                Ok(Ok(push)) => {
                    let interested = push_sub
                        .lock()
                        .is_ok_and(|s| s.contains(&(push.kind as u8, push.box_id)));
                    if interested {
                        let mut w = push_writer.lock().await;
                        if ws_write_frame(&mut *w, WS_OP_BIN, &push.encode(), false)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Ok(Err(broadcast::error::RecvError::Lagged(_))) | Err(_) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) => break,
            }
            if *fwd_shutdown.borrow_and_update() {
                let mut w = push_writer.lock().await;
                let _ = ws_write_frame(&mut *w, WS_OP_CLOSE, &[], false).await;
                drop(w);
                break;
            }
        }
    })
}

async fn run_ws_read_loop<R, W>(
    ws_read: &mut R,
    writer: &Arc<AsyncMutex<W>>,
    subscribed: &BoxSubs,
    state: &SharedState,
    shutdown: &watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    while !*shutdown.borrow() {
        let frame = ws_read_frame(ws_read, true, Some(Duration::from_secs(30))).await;
        let Ok((opcode, payload)) = frame else {
            if let Err(err) = frame
                && !err.to_string().contains("timed out")
            {
                break;
            }
            continue;
        };
        match opcode {
            WS_OP_CLOSE => {
                let mut w = writer.lock().await;
                let _ = ws_write_frame(&mut *w, WS_OP_CLOSE, &[], false).await;
                drop(w);
                break;
            }
            WS_OP_PING => {
                let mut w = writer.lock().await;
                if ws_write_frame(&mut *w, WS_OP_PONG, &payload, false)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WS_OP_BIN if payload.starts_with(b"ZPSO") => {
                let Ok(op_req) = SignedOp::decode(&payload) else {
                    break;
                };
                let (reply, push) = {
                    let mut guard = state
                        .store
                        .lock()
                        .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
                    guard.apply_op(&op_req)
                };
                if let Some(ev) = push {
                    let _ = state.push_tx.send(ev);
                }
                let mut w = writer.lock().await;
                if ws_write_frame(&mut *w, WS_OP_BIN, &reply.encode(), false)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WS_OP_BIN if payload.starts_with(b"ZPSB") => {
                let Ok(new_sub) = SignedSub::decode(&payload) else {
                    break;
                };
                let st = {
                    let mut guard = state
                        .store
                        .lock()
                        .map_err(|_| anyhow!("mailbox store lock poisoned"))?;
                    guard.verify_subscription(&new_sub)
                };
                if st != OpStatus::Ok {
                    break;
                }
                if let Ok(mut s) = subscribed.lock() {
                    *s = new_sub
                        .boxes
                        .into_iter()
                        .map(|(k, id)| (k as u8, id))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Ok(())
}
