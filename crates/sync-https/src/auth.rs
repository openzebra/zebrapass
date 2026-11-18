//! Domain-separated `ML-DSA-65` signatures, device/revocation/member checks,
//! and bounded timestamp + nonce replay protection for `sync-https`.

use std::collections::{HashSet, VecDeque};

use local::SyncIdentity;
use pq::{SYNC_CTX, SYNC_VK_LEN, sync_sign, sync_verify};
use session::frame_parts;
use sha2::{Digest, Sha256};

use crate::limits::{MAX_NONCE_CACHE, MAX_ORIGIN_LEN, MAX_TIME_SKEW_SECS};
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};
use crate::wire_rpc::{ChunkQuery, SignedOp, SignedSub, StateQuery};

const DOMAIN_OP: &[u8] = b"zebrapass/sync-https/op/v1";
const DOMAIN_STATE: &[u8] = b"zebrapass/sync-https/state/v1";
const DOMAIN_CHUNK: &[u8] = b"zebrapass/sync-https/chunk/v1";
const DOMAIN_SUB: &[u8] = b"zebrapass/sync-https/sub/v1";

/// Current UNIX timestamp in milliseconds.
#[must_use]
pub(crate) fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Current UNIX timestamp in seconds.
#[must_use]
pub fn now_unix_secs() -> u64 {
    now_ms() / 1_000
}

fn fresh_nonce_and_ts() -> anyhow::Result<(u64, [u8; 16])> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok((now_unix_secs(), nonce))
}

fn op_message(
    origin: &str,
    box_id: &[u8; 32],
    kind: MailboxKind,
    device_id: &[u8; 16],
    ts: u64,
    nonce: &[u8; 16],
    payload_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if origin.len() > MAX_ORIGIN_LEN {
        anyhow::bail!("server origin exceeds limit");
    }
    let payload_hash: [u8; 32] = Sha256::digest(payload_bytes).into();
    frame_parts(&[
        DOMAIN_OP,
        origin.as_bytes(),
        box_id,
        &[kind as u8],
        device_id,
        &ts.to_be_bytes(),
        nonce,
        &payload_hash,
    ])
}

fn state_message(origin: &str, q: &StateQuery) -> anyhow::Result<Vec<u8>> {
    if origin.len() > MAX_ORIGIN_LEN {
        anyhow::bail!("server origin exceeds limit");
    }
    frame_parts(&[
        DOMAIN_STATE,
        origin.as_bytes(),
        &q.box_id,
        &[q.kind as u8],
        &q.device_id,
        &q.timestamp_secs.to_be_bytes(),
        &q.nonce,
        &q.since_seq.to_be_bytes(),
        &q.since_member_seq.to_be_bytes(),
    ])
}

fn chunk_message(origin: &str, q: &ChunkQuery) -> anyhow::Result<Vec<u8>> {
    if origin.len() > MAX_ORIGIN_LEN {
        anyhow::bail!("server origin exceeds limit");
    }
    frame_parts(&[
        DOMAIN_CHUNK,
        origin.as_bytes(),
        &q.box_id,
        &[q.kind as u8],
        &q.device_id,
        &q.timestamp_secs.to_be_bytes(),
        &q.nonce,
        &[q.target as u8],
        &q.object_id,
        &q.index.to_be_bytes(),
        &q.offset.to_be_bytes(),
        &q.max_len.to_be_bytes(),
    ])
}

fn sub_message(origin: &str, sub: &SignedSub) -> anyhow::Result<Vec<u8>> {
    if origin.len() > MAX_ORIGIN_LEN {
        anyhow::bail!("server origin exceeds limit");
    }
    let mut flat_boxes = Vec::with_capacity(sub.boxes.len() * 33);
    for (kind, id) in &sub.boxes {
        flat_boxes.push(*kind as u8);
        flat_boxes.extend_from_slice(id);
    }
    frame_parts(&[
        DOMAIN_SUB,
        origin.as_bytes(),
        &sub.device_id,
        &sub.timestamp_secs.to_be_bytes(),
        &sub.nonce,
        &flat_boxes,
    ])
}

/// Sign a mailbox operation using this device's certified ML-DSA-65 key.
///
/// # Errors
///
/// Missing device certificate, entropy failure, or signing failure.
pub fn sign_op(
    identity: &SyncIdentity,
    origin: &str,
    box_id: [u8; 32],
    kind: MailboxKind,
    payload: &OpPayload,
) -> anyhow::Result<SignedOp> {
    let device_id = identity
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device certificate missing"))?;
    let payload_bytes = payload.encode()?;
    let (ts, nonce) = fresh_nonce_and_ts()?;
    let msg = op_message(
        origin,
        &box_id,
        kind,
        &device_id,
        ts,
        &nonce,
        &payload_bytes,
    )?;
    let sig = sync_sign(identity.sign_key().seed(), SYNC_CTX, &msg)?;
    Ok(SignedOp {
        box_id,
        kind,
        device_id,
        timestamp_secs: ts,
        nonce,
        payload_bytes,
        sig,
    })
}

/// Sign a `StateQuery`.
///
/// # Errors
///
/// Missing device certificate, entropy failure, or signing failure.
pub fn sign_state_query(
    identity: &SyncIdentity,
    origin: &str,
    box_id: [u8; 32],
    kind: MailboxKind,
    since_seq: u64,
    since_member_seq: u64,
) -> anyhow::Result<StateQuery> {
    let device_id = identity
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device certificate missing"))?;
    let (timestamp_secs, nonce) = fresh_nonce_and_ts()?;
    let mut query = StateQuery {
        box_id,
        kind,
        device_id,
        timestamp_secs,
        nonce,
        since_seq,
        since_member_seq,
        sig: Vec::new(),
    };
    let msg = state_message(origin, &query)?;
    query.sig = sync_sign(identity.sign_key().seed(), SYNC_CTX, &msg)?;
    Ok(query)
}

/// Sign a `ChunkQuery`.
///
/// # Errors
///
/// Missing device certificate, entropy failure, or signing failure.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit chunk slice coordinates"
)]
pub fn sign_chunk_query(
    identity: &SyncIdentity,
    origin: &str,
    box_id: [u8; 32],
    kind: MailboxKind,
    target: ChunkTarget,
    object_id: [u8; 32],
    index: u32,
    offset: u32,
    max_len: u32,
) -> anyhow::Result<ChunkQuery> {
    let device_id = identity
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device certificate missing"))?;
    let (timestamp_secs, nonce) = fresh_nonce_and_ts()?;
    let mut query = ChunkQuery {
        box_id,
        kind,
        device_id,
        timestamp_secs,
        nonce,
        target,
        object_id,
        index,
        offset,
        max_len,
        sig: Vec::new(),
    };
    let msg = chunk_message(origin, &query)?;
    query.sig = sync_sign(identity.sign_key().seed(), SYNC_CTX, &msg)?;
    Ok(query)
}

/// Sign a `SignedSub` for WebSocket live push subscription.
///
/// # Errors
///
/// Missing device certificate, entropy failure, or signing failure.
pub fn sign_sub(
    identity: &SyncIdentity,
    origin: &str,
    boxes: Vec<(MailboxKind, [u8; 32])>,
) -> anyhow::Result<SignedSub> {
    let device_id = identity
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device certificate missing"))?;
    let (timestamp_secs, nonce) = fresh_nonce_and_ts()?;
    let mut sub = SignedSub {
        device_id,
        timestamp_secs,
        nonce,
        boxes,
        sig: Vec::new(),
    };
    let msg = sub_message(origin, &sub)?;
    sub.sig = sync_sign(identity.sign_key().seed(), SYNC_CTX, &msg)?;
    Ok(sub)
}

/// Verify a `SignedOp` signature against `device_vk`.
///
/// # Errors
///
/// Signature mismatch under `origin`.
pub fn verify_signed_op(
    origin: &str,
    op: &SignedOp,
    device_vk: &[u8; SYNC_VK_LEN],
) -> anyhow::Result<()> {
    let msg = op_message(
        origin,
        &op.box_id,
        op.kind,
        &op.device_id,
        op.timestamp_secs,
        &op.nonce,
        &op.payload_bytes,
    )?;
    sync_verify(device_vk, SYNC_CTX, &msg, &op.sig)
}

/// Verify a `StateQuery` signature against `device_vk`.
///
/// # Errors
///
/// Signature mismatch under `origin`.
pub fn verify_state_query(
    origin: &str,
    q: &StateQuery,
    device_vk: &[u8; SYNC_VK_LEN],
) -> anyhow::Result<()> {
    let msg = state_message(origin, q)?;
    sync_verify(device_vk, SYNC_CTX, &msg, &q.sig)
}

/// Verify a `ChunkQuery` signature against `device_vk`.
///
/// # Errors
///
/// Signature mismatch under `origin`.
pub fn verify_chunk_query(
    origin: &str,
    q: &ChunkQuery,
    device_vk: &[u8; SYNC_VK_LEN],
) -> anyhow::Result<()> {
    let msg = chunk_message(origin, q)?;
    sync_verify(device_vk, SYNC_CTX, &msg, &q.sig)
}

/// Verify a `SignedSub` signature against `device_vk`.
///
/// # Errors
///
/// Signature mismatch under `origin`.
pub fn verify_sub(
    origin: &str,
    sub: &SignedSub,
    device_vk: &[u8; SYNC_VK_LEN],
) -> anyhow::Result<()> {
    let msg = sub_message(origin, sub)?;
    sync_verify(device_vk, SYNC_CTX, &msg, &sub.sig)
}

/// Bounded anti-replay guard checking timestamp skew and recent `(device_id, nonce)`.
#[derive(Debug, Default)]
pub struct NonceReplayGuard {
    order: VecDeque<([u8; 16], [u8; 16])>,
    seen: HashSet<([u8; 16], [u8; 16])>,
}

impl NonceReplayGuard {
    /// Reject replayed nonces or timestamps outside `±MAX_TIME_SKEW_SECS`.
    ///
    /// # Errors
    ///
    /// Clock skew exceeded or duplicate nonce within cache window.
    pub fn check_and_insert(
        &mut self,
        device_id: [u8; 16],
        nonce: [u8; 16],
        ts_secs: u64,
        now_secs: u64,
    ) -> anyhow::Result<()> {
        if ts_secs.abs_diff(now_secs) > MAX_TIME_SKEW_SECS {
            anyhow::bail!("timestamp skew out of bounds");
        }
        let key = (device_id, nonce);
        if self.seen.contains(&key) {
            anyhow::bail!("replayed request nonce");
        }
        while self.order.len() >= MAX_NONCE_CACHE {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(key);
        self.order.push_back(key);
        Ok(())
    }
}
