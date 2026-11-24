//! Client-side self-certifying `ML-DSA-65` relay slot credentials, slot holder,
//! and dialer (`StreamRole::Relay`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use pq::{SYNC_CTX, SYNC_SIG_LEN, SYNC_VK_LEN, sync_sign, sync_verifying_key};
use secret::Secret;
use session::frame_parts;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::auth::now_unix_secs;
use crate::limits::{IO_TIMEOUT, MAX_SMALL_FRAME, RELAY_PENDING_SECS};
use crate::tls::{Endpoint, connect_tls};
use crate::wire::{RelayMsg, StorageId, StreamRole, TAG_RELAY, read_wire, write_wire};
use crate::wire_codec::{decode_relay, encode_relay};

const DOMAIN_SLOT_VK: &[u8] = b"brby/v3/zsync-relay-slot-vk";
const DOMAIN_RESERVE_AUTH: &[u8] = b"brby/v3/zsync-relay-reserve";

/// Self-certifying relay slot credentials derived from `(secret_ikm, storage_id)`.
pub struct RelayCredentials {
    slot: [u8; 16],
    sign_seed: Secret<[u8; 32]>,
    slot_vk: Box<[u8; SYNC_VK_LEN]>,
}

impl std::fmt::Debug for RelayCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayCredentials")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl RelayCredentials {
    /// Derive deterministic self-certifying relay credentials without revealing
    /// `secret_ikm` or `storage_id` to the zero-storage relay server.
    ///
    /// # Errors
    ///
    /// KDF or ML-DSA key derivation failure.
    pub fn derive(secret_ikm: &[u8], storage_id: &StorageId) -> anyhow::Result<Self> {
        let seed_tag = kdf::zsync_relay_slot(secret_ikm, storage_id)?;
        let sign_seed = kdf::zsync_relay_auth_key(secret_ikm, &seed_tag)?;
        let raw_vk = sync_verifying_key(sign_seed.expose())?;
        let slot_vk = Box::new(
            <[u8; SYNC_VK_LEN]>::try_from(raw_vk)
                .map_err(|_| anyhow!("unexpected relay vk length"))?,
        );
        let slot = slot_from_vk(&slot_vk);
        Ok(Self {
            slot,
            sign_seed,
            slot_vk,
        })
    }

    /// Canonical 16-byte self-certifying relay slot identifier.
    #[must_use]
    pub const fn slot(&self) -> [u8; 16] {
        self.slot
    }

    fn sign_reserve(&self) -> anyhow::Result<RelayMsg> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| anyhow!("os entropy failed"))?;
        let timestamp_s = now_unix_secs();
        let msg = reserve_msg(&self.slot, timestamp_s, &nonce)?;
        let raw_sig = sync_sign(self.sign_seed.expose(), SYNC_CTX, &msg)?;
        let signature = Box::new(
            <[u8; SYNC_SIG_LEN]>::try_from(raw_sig)
                .map_err(|_| anyhow!("unexpected relay signature length"))?,
        );
        Ok(RelayMsg::Reserve {
            slot: self.slot,
            timestamp_s,
            nonce,
            slot_vk: self.slot_vk.clone(),
            signature,
        })
    }
}

pub fn slot_from_vk(slot_vk: &[u8; SYNC_VK_LEN]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN_SLOT_VK)
        .chain_update(slot_vk)
        .finalize()
        .into();
    let mut slot = [0u8; 16];
    if let Some((head, _)) = digest.split_at_checked(16) {
        slot.copy_from_slice(head);
    }
    slot
}

pub fn reserve_msg(slot: &[u8; 16], timestamp_s: u64, nonce: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
    frame_parts(&[DOMAIN_RESERVE_AUTH, slot, &timestamp_s.to_be_bytes(), nonce])
}

/// Dial a live relay slot on `ep`; returns `Ok(None)` when no peer holds `slot`.
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

/// Hold `creds.slot()` on `ep` using signed self-certifying slot ownership proofs.
pub async fn hold_relay_slot<F, Fut>(
    ep: Endpoint,
    tls_cfg: Arc<rustls::ClientConfig>,
    creds: Arc<RelayCredentials>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    on_conn: F,
) where
    F: Fn(TlsStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(on_conn);
    let mut backoff = Duration::from_secs(1);
    while !*stop.borrow() {
        if let Ok(reserve_req) = creds.sign_reserve()
            && let Ok((mut tls, _)) = connect_tls(&ep, &tls_cfg).await
            && tls.write_all(&[StreamRole::Relay as u8]).await.is_ok()
            && let Ok(req) = encode_relay(&reserve_req)
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
