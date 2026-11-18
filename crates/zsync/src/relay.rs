//! Zero-storage PQ TLS 1.3 live P2P stream relay (`StreamRole::Relay`).
//!
//! When two devices cannot connect directly over LAN or WAN NATs, one device
//! holds a deterministic slot (`Reserve`) over TLS on `:443` and the other
//! connects (`Connect`) to splice two TLS streams directly in RAM (`SpliceOk`)
//! without touching disk or seeing any unencrypted vault metadata.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::limits::{
    IO_TIMEOUT, MAX_RELAY_SLOTS, MAX_SMALL_FRAME, RELAY_MAX_BYTES, RELAY_PENDING_SECS,
    RELAY_TTL_SECS,
};
use crate::tls::{Endpoint, connect_tls};
use crate::wire::{RelayMsg, StreamRole, TAG_RELAY, read_wire, write_wire};
use crate::wire_codec::{decode_relay, encode_relay};

#[derive(Debug)]
struct PendingConn {
    tx: oneshot::Sender<ServerTlsStream<TcpStream>>,
}

/// In-memory relay rendezvous table on a Zebra server (zero disk storage).
#[derive(Debug, Default)]
pub struct RelayHub {
    slots: Mutex<HashMap<[u8; 16], mpsc::Sender<[u8; 16]>>>,
    pending: Mutex<HashMap<[u8; 16], PendingConn>>,
}

impl RelayHub {
    fn reserve(&self, slot: [u8; 16]) -> Option<mpsc::Receiver<[u8; 16]>> {
        let mut guard = self.slots.lock().ok()?;
        if !guard.contains_key(&slot) && guard.len() >= MAX_RELAY_SLOTS {
            return None;
        }
        let (tx, rx) = mpsc::channel(8);
        guard.insert(slot, tx);
        drop(guard);
        Some(rx)
    }

    fn release(&self, slot: &[u8; 16]) {
        if let Ok(mut guard) = self.slots.lock() {
            guard.remove(slot);
        }
    }

    fn take_holder(&self, slot: &[u8; 16]) -> Option<mpsc::Sender<[u8; 16]>> {
        self.slots.lock().ok()?.get(slot).cloned()
    }

    fn insert_pending(&self, conn_id: [u8; 16], tx: oneshot::Sender<ServerTlsStream<TcpStream>>) {
        if let Ok(mut guard) = self.pending.lock() {
            guard.insert(conn_id, PendingConn { tx });
        }
    }

    fn take_pending(&self, conn_id: &[u8; 16]) -> Option<PendingConn> {
        self.pending.lock().ok()?.remove(conn_id)
    }
}

/// Handle a `StreamRole::Relay` TLS connection on the server.
pub async fn serve_relay(
    hub: Arc<RelayHub>,
    mut tls: ServerTlsStream<TcpStream>,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await??;
    if tag != TAG_RELAY {
        anyhow::bail!("unexpected relay tag");
    }
    match decode_relay(&body)? {
        RelayMsg::Reserve { slot } => handle_reserve(hub, tls, peer_addr, slot).await,
        RelayMsg::Connect { slot } => handle_connect(&hub, tls, slot).await,
        RelayMsg::Accept { conn_id } => {
            handle_accept(&hub, tls, conn_id);
            Ok(())
        }
        _ => anyhow::bail!("invalid initial relay message"),
    }
}

async fn handle_reserve(
    hub: Arc<RelayHub>,
    mut tls: ServerTlsStream<TcpStream>,
    peer_addr: SocketAddr,
    slot: [u8; 16],
) -> anyhow::Result<()> {
    let Some(mut offers) = hub.reserve(slot) else {
        write_wire(&mut tls, TAG_RELAY, &encode_relay(&RelayMsg::Offline)?).await?;
        return Ok(());
    };
    let ack = encode_relay(&RelayMsg::Reserved {
        ttl_s: RELAY_TTL_SECS,
        observed: peer_addr.to_string(),
    })?;
    if write_wire(&mut tls, TAG_RELAY, &ack).await.is_err() {
        hub.release(&slot);
        return Ok(());
    }
    let keep_window = Duration::from_secs(u64::from(RELAY_TTL_SECS));
    let (mut tls_r, mut tls_w) = tokio::io::split(tls);
    let (out_tx, mut out_rx) = mpsc::channel::<RelayMsg>(16);

    let tx_offers = out_tx.clone();
    let offer_task = tokio::spawn(async move {
        while let Some(conn_id) = offers.recv().await {
            if tx_offers
                .send(RelayMsg::Incoming { conn_id })
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let read_task = tokio::spawn(async move {
        while let Ok(Ok((TAG_RELAY, raw))) =
            timeout(keep_window, read_wire(&mut tls_r, MAX_SMALL_FRAME)).await
        {
            match decode_relay(&raw) {
                Ok(RelayMsg::Ping(tok)) => {
                    if out_tx.send(RelayMsg::Pong(tok)).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    while let Some(msg) = out_rx.recv().await {
        let Ok(enc) = encode_relay(&msg) else { break };
        if write_wire(&mut tls_w, TAG_RELAY, &enc).await.is_err() {
            break;
        }
        if read_task.is_finished() {
            break;
        }
    }
    offer_task.abort();
    read_task.abort();
    hub.release(&slot);
    Ok(())
}

async fn handle_connect(
    hub: &RelayHub,
    mut tls: ServerTlsStream<TcpStream>,
    slot: [u8; 16],
) -> anyhow::Result<()> {
    let Some(holder) = hub.take_holder(&slot) else {
        write_wire(&mut tls, TAG_RELAY, &encode_relay(&RelayMsg::Offline)?).await?;
        return Ok(());
    };
    let mut conn_id = [0u8; 16];
    getrandom::fill(&mut conn_id).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let (tx, rx) = oneshot::channel();
    hub.insert_pending(conn_id, tx);
    if holder.send(conn_id).await.is_err() {
        let _ = hub.take_pending(&conn_id);
        write_wire(&mut tls, TAG_RELAY, &encode_relay(&RelayMsg::Offline)?).await?;
        return Ok(());
    }
    let Ok(Ok(mut responder)) = timeout(Duration::from_secs(RELAY_PENDING_SECS), rx).await else {
        let _ = hub.take_pending(&conn_id);
        write_wire(&mut tls, TAG_RELAY, &encode_relay(&RelayMsg::Offline)?).await?;
        return Ok(());
    };
    let splice = encode_relay(&RelayMsg::SpliceOk)?;
    if write_wire(&mut tls, TAG_RELAY, &splice).await.is_err()
        || write_wire(&mut responder, TAG_RELAY, &splice)
            .await
            .is_err()
    {
        return Ok(());
    }
    splice_streams(tls, responder).await;
    Ok(())
}

fn handle_accept(hub: &RelayHub, tls: ServerTlsStream<TcpStream>, conn_id: [u8; 16]) {
    if let Some(pending) = hub.take_pending(&conn_id) {
        let _ = pending.tx.send(tls);
    }
}

async fn splice_streams<A, B>(a: A, b: B)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let j1 = tokio::spawn(async move {
        copy_bounded(&mut ar, &mut bw, RELAY_MAX_BYTES / 2).await;
    });
    let j2 = tokio::spawn(async move {
        copy_bounded(&mut br, &mut aw, RELAY_MAX_BYTES / 2).await;
    });
    let _ = j1.await;
    let _ = j2.await;
}

async fn copy_bounded<R, W>(reader: &mut R, writer: &mut W, limit: u64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    while total < limit {
        let Ok(Ok(n)) = timeout(Duration::from_secs(120), reader.read(&mut buf)).await else {
            break;
        };
        if n == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        let Some(slice) = buf.get(..n) else { break };
        if writer.write_all(slice).await.is_err() {
            break;
        }
    }
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
}

/// Dial a live relay slot on `ep`; returns `Ok(None)` when no peer holds `slot`
/// right now (`RelayMsg::Offline`), or `Ok(Some(stream))` once spliced.
///
/// # Errors
///
/// Connection, TLS, or protocol failures.
pub async fn connect_relay_slot(
    ep: &Endpoint,
    tls_cfg: &Arc<rustls::ClientConfig>,
    slot: [u8; 16],
) -> anyhow::Result<Option<TlsStream<TcpStream>>> {
    let (mut tls, _) = connect_tls(ep, tls_cfg).await?;
    tls.write_all(&[StreamRole::Relay as u8]).await?;
    write_wire(
        &mut tls,
        TAG_RELAY,
        &encode_relay(&RelayMsg::Connect { slot })?,
    )
    .await?;
    let (tag, body) = timeout(
        Duration::from_secs(RELAY_PENDING_SECS + 3),
        read_wire(&mut tls, MAX_SMALL_FRAME),
    )
    .await??;
    if tag != TAG_RELAY {
        anyhow::bail!("unexpected relay reply");
    }
    match decode_relay(&body)? {
        RelayMsg::SpliceOk => Ok(Some(tls)),
        RelayMsg::Offline => Ok(None),
        _ => anyhow::bail!("unexpected relay response"),
    }
}

/// Hold `slot` on `ep`, yielding spliced [`TlsStream<TcpStream>`] connections
/// to `on_conn` whenever another device connects until `stop` becomes `true`.
pub async fn hold_relay_slot<F, Fut>(
    ep: Endpoint,
    tls_cfg: Arc<rustls::ClientConfig>,
    slot: [u8; 16],
    mut stop: tokio::sync::watch::Receiver<bool>,
    on_conn: F,
) where
    F: Fn(TlsStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(on_conn);
    let mut backoff = Duration::from_secs(1);
    while !*stop.borrow() {
        if let Ok((mut tls, _)) = connect_tls(&ep, &tls_cfg).await
            && tls.write_all(&[StreamRole::Relay as u8]).await.is_ok()
            && let Ok(req) = encode_relay(&RelayMsg::Reserve { slot })
            && write_wire(&mut tls, TAG_RELAY, &req).await.is_ok()
            && let Ok(Ok((TAG_RELAY, body))) =
                timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await
            && let Ok(RelayMsg::Reserved { ttl_s, .. }) = decode_relay(&body)
        {
            backoff = Duration::from_secs(1);
            let ping_every = Duration::from_secs(u64::from(ttl_s / 3).max(5));
            let (mut tls_r, mut tls_w) = tokio::io::split(tls);
            let (in_tx, mut in_rx) = mpsc::channel::<RelayMsg>(16);
            let read_task = tokio::spawn(async move {
                while let Ok((TAG_RELAY, raw)) = read_wire(&mut tls_r, MAX_SMALL_FRAME).await {
                    match decode_relay(&raw) {
                        Ok(msg) => {
                            if in_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            let mut token = 0u64;
            while !*stop.borrow() && !read_task.is_finished() {
                match timeout(ping_every, in_rx.recv()).await {
                    Ok(Some(RelayMsg::Pong(_))) => {}
                    Ok(Some(RelayMsg::Incoming { conn_id })) => {
                        let ep2 = ep.clone();
                        let cfg2 = Arc::clone(&tls_cfg);
                        let h2 = Arc::clone(&handler);
                        tokio::spawn(async move {
                            if let Ok(stream) = accept_relay_conn(&ep2, &cfg2, conn_id).await {
                                h2(stream).await;
                            }
                        });
                    }
                    Ok(Some(_) | None) => break,
                    Err(_) => {
                        token = token.wrapping_add(1);
                        let Ok(ping) = encode_relay(&RelayMsg::Ping(token)) else {
                            break;
                        };
                        if write_wire(&mut tls_w, TAG_RELAY, &ping).await.is_err() {
                            break;
                        }
                    }
                }
            }
            read_task.abort();
        }
        if timeout(backoff, stop.changed()).await.is_ok() && *stop.borrow() {
            return;
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn accept_relay_conn(
    ep: &Endpoint,
    tls_cfg: &Arc<rustls::ClientConfig>,
    conn_id: [u8; 16],
) -> anyhow::Result<TlsStream<TcpStream>> {
    let (mut tls, _) = connect_tls(ep, tls_cfg).await?;
    tls.write_all(&[StreamRole::Relay as u8]).await?;
    write_wire(
        &mut tls,
        TAG_RELAY,
        &encode_relay(&RelayMsg::Accept { conn_id })?,
    )
    .await?;
    let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await??;
    if tag != TAG_RELAY {
        anyhow::bail!("unexpected relay accept reply");
    }
    match decode_relay(&body)? {
        RelayMsg::SpliceOk => Ok(tls),
        _ => anyhow::bail!("relay accept failed"),
    }
}
