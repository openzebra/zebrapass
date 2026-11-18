//! Zero-knowledge verified mailbox store: request routing, state/chunk
//! queries, WebSocket subscription verification, and strict read/write policy.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

use session::DeviceCert;
use syncwire::encode_revocation;

use crate::auth::{
    NonceReplayGuard, now_ms, now_unix_secs, verify_chunk_query, verify_state_query, verify_sub,
};
use crate::limits::{MAX_STATE_FRAMES_PAGE, SPLIT_TRANSFER_CHUNK};
use crate::store_disk::{MailboxState, box_dir, hex_encode, load_all_mailboxes, read_chunk_slice};
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};
use crate::wire_rpc::{
    ChunkQuery, ChunkReply, FrameItem, MailboxSummary, OpReply, OpStatus, PushEvent, SignedOp,
    SignedSub, StateQuery,
};

const SUMMARY_FRAME_INLINE_BUDGET: usize = 3_072;

#[derive(Debug)]
pub struct MailboxStore {
    pub data_dir: PathBuf,
    pub origin: Box<str>,
    pub mailboxes: BTreeMap<(u8, [u8; 32]), MailboxState>,
    pub pending_order: VecDeque<(u8, [u8; 32], [u8; 16])>,
    pub pending_certs: BTreeMap<(u8, [u8; 32], [u8; 16]), DeviceCert>,
    pub replay: NonceReplayGuard,
}

impl MailboxStore {
    pub fn open(data_dir: PathBuf, origin: Box<str>) -> anyhow::Result<Self> {
        let mailboxes = load_all_mailboxes(&data_dir)?;
        Ok(Self {
            data_dir,
            origin,
            mailboxes,
            pending_order: VecDeque::new(),
            pending_certs: BTreeMap::new(),
            replay: NonceReplayGuard::default(),
        })
    }

    pub fn apply_op(&mut self, op: &SignedOp) -> (OpReply, Option<PushEvent>) {
        if !self.check_replay_op(op) {
            return (rejected_reply(), None);
        }
        let Ok(payload) = OpPayload::decode(&op.payload_bytes) else {
            return (rejected_reply(), None);
        };
        let key = (op.kind as u8, op.box_id);
        match payload {
            OpPayload::StageCert { cert_wire } => self.handle_stage_cert(op, &cert_wire),
            OpPayload::AnchorPersonalRoot { root_vk } => self.handle_anchor_personal(op, &root_vk),
            OpPayload::CommitInitShared {
                vault_id,
                anchor,
                chunk_id,
                total_chunks,
            } => self.handle_init_shared(op, vault_id, anchor, chunk_id, total_chunks),
            OpPayload::PutChunk {
                chunk_id,
                index,
                total,
                data,
            } => {
                let unanchored_shared = op.kind == MailboxKind::Shared
                    && self
                        .mailboxes
                        .get(&key)
                        .is_none_or(|m| m.member_log.is_none());
                if unanchored_shared {
                    let reply =
                        self.stage_unanchored_shared_chunk(op, chunk_id, index, total, data);
                    (reply, None)
                } else {
                    self.handle_mailbox_op(
                        op,
                        OpPayload::PutChunk {
                            chunk_id,
                            index,
                            total,
                            data,
                        },
                    )
                }
            }
            other => self.handle_mailbox_op(op, other),
        }
    }

    pub fn query_state(&mut self, q: &StateQuery) -> MailboxSummary {
        if !verify_op_replay(
            &mut self.replay,
            q.device_id,
            q.nonce,
            q.timestamp_secs,
            now_unix_secs(),
        ) {
            return empty_summary(OpStatus::Rejected);
        }
        let uninitialized = self
            .mailboxes
            .get(&(q.kind as u8, q.box_id))
            .is_none_or(|m| q.kind == MailboxKind::Shared && m.member_log.is_none());
        if uninitialized {
            let Some(cert) = self
                .pending_certs
                .get(&(q.kind as u8, q.box_id, q.device_id))
            else {
                return empty_summary(OpStatus::NeedCert);
            };
            return if verify_state_query(&self.origin, q, &cert.device_vk).is_ok() {
                empty_summary(OpStatus::Ok)
            } else {
                empty_summary(OpStatus::Rejected)
            };
        }
        let Some(m) = self.mailboxes.get(&(q.kind as u8, q.box_id)) else {
            return empty_summary(OpStatus::NeedCert);
        };
        let Some(cert) = active_cert(m, q.device_id) else {
            return empty_summary(OpStatus::NeedCert);
        };
        if !can_read_mailbox(m, &cert.client_id)
            || verify_state_query(&self.origin, q, &cert.device_vk).is_err()
        {
            return empty_summary(OpStatus::Rejected);
        }
        build_summary(m, q)
    }

    pub fn query_chunk(&mut self, q: &ChunkQuery) -> ChunkReply {
        if !verify_op_replay(
            &mut self.replay,
            q.device_id,
            q.nonce,
            q.timestamp_secs,
            now_unix_secs(),
        ) {
            return rejected_chunk();
        }
        let Some(m) = self.mailboxes.get(&(q.kind as u8, q.box_id)) else {
            return ChunkReply {
                status: OpStatus::NeedCert,
                total_len: 0,
                data: Vec::new(),
            };
        };
        let Some(cert) = active_cert(m, q.device_id) else {
            return ChunkReply {
                status: OpStatus::NeedCert,
                total_len: 0,
                data: Vec::new(),
            };
        };
        if !can_read_mailbox(m, &cert.client_id)
            || verify_chunk_query(&self.origin, q, &cert.device_vk).is_err()
        {
            return rejected_chunk();
        }
        read_target_chunk(&self.data_dir, m, q)
    }

    pub fn verify_subscription(&mut self, sub: &SignedSub) -> OpStatus {
        if !verify_op_replay(
            &mut self.replay,
            sub.device_id,
            sub.nonce,
            sub.timestamp_secs,
            now_unix_secs(),
        ) {
            return OpStatus::Rejected;
        }
        let mut device_vk = None;
        for (kind, box_id) in &sub.boxes {
            if let Some(m) = self.mailboxes.get(&(*kind as u8, *box_id))
                && let Some(cert) = active_cert(m, sub.device_id)
                && can_read_mailbox(m, &cert.client_id)
            {
                device_vk = Some(cert.device_vk);
                break;
            }
        }
        if device_vk.is_none() {
            for (kind, box_id) in &sub.boxes {
                if let Some(cert) = self
                    .pending_certs
                    .get(&(*kind as u8, *box_id, sub.device_id))
                {
                    device_vk = Some(cert.device_vk);
                    break;
                }
            }
        }
        let Some(vk) = device_vk else {
            return OpStatus::NeedCert;
        };
        if verify_sub(&self.origin, sub, &vk).is_err() {
            return OpStatus::Rejected;
        }
        OpStatus::Ok
    }
}

fn build_summary(m: &MailboxState, q: &StateQuery) -> MailboxSummary {
    let mut frames = Vec::new();
    let mut inline_used = 0usize;
    let mut has_more_frames = false;
    for f in m.frames.iter().filter(|f| f.seq > q.since_seq) {
        if frames.len() >= MAX_STATE_FRAMES_PAGE {
            has_more_frames = true;
            break;
        }
        match (f.chunk_id, &f.envelope) {
            (None, Some(env))
                if inline_used.saturating_add(env.len()) <= SUMMARY_FRAME_INLINE_BUDGET =>
            {
                inline_used = inline_used.saturating_add(env.len());
                frames.push(FrameItem::Inline {
                    seq: f.seq,
                    envelope: env.clone(),
                });
            }
            (Some(chunk_id), None) => {
                frames.push(FrameItem::External {
                    seq: f.seq,
                    chunk_id,
                    total_len: f.total_len,
                });
            }
            (None, Some(_)) => {
                has_more_frames = true;
                break;
            }
            _ => {}
        }
    }
    let rekeys = m
        .rekeys
        .iter()
        .filter(|(_, target, _)| *target == q.device_id || *target == [0u8; 16])
        .map(|(key_gen, _, env)| (*key_gen, env.clone()))
        .collect();
    MailboxSummary {
        status: OpStatus::Ok,
        exists: true,
        snap_id: m.snap_id,
        snap_chunks: m.snap_chunks,
        snap_generation: m.snap_generation,
        head_meta: m.head_meta.clone(),
        head_seq: m.head_seq,
        frames,
        has_more_frames,
        rekeys,
        revocation_count: u32::try_from(m.revocations.len()).unwrap_or(u32::MAX),
        member_count: u32::try_from(m.member_entries.len()).unwrap_or(u32::MAX),
        backup_id: m.backup_id,
        backup_chunks: m.backup_chunks,
    }
}

fn read_target_chunk(data_dir: &std::path::Path, m: &MailboxState, q: &ChunkQuery) -> ChunkReply {
    let max_len = usize::try_from(q.max_len)
        .unwrap_or(SPLIT_TRANSFER_CHUNK)
        .min(SPLIT_TRANSFER_CHUNK);
    let dir = box_dir(data_dir, m.kind, &m.box_id);
    match q.target {
        ChunkTarget::Snapshot => {
            if m.snap_id != Some(q.object_id) || q.index >= m.snap_chunks {
                return rejected_chunk();
            }
            read_chunk_slice(&dir, "snap", &format!("{}.bin", q.index), q.offset, max_len)
                .map_or_else(
                    |_| rejected_chunk(),
                    |(total_len, data)| ChunkReply {
                        status: OpStatus::Ok,
                        total_len,
                        data,
                    },
                )
        }
        ChunkTarget::Backup => {
            if m.backup_id != Some(q.object_id) || q.index >= m.backup_chunks {
                return rejected_chunk();
            }
            read_chunk_slice(
                &dir,
                "backup",
                &format!("{}.bin", q.index),
                q.offset,
                max_len,
            )
            .map_or_else(
                |_| rejected_chunk(),
                |(total_len, data)| ChunkReply {
                    status: OpStatus::Ok,
                    total_len,
                    data,
                },
            )
        }
        ChunkTarget::Frame => {
            if !m.frames.iter().any(|f| f.chunk_id == Some(q.object_id)) {
                return rejected_chunk();
            }
            let fname = format!("{}.bin", hex_encode(&q.object_id));
            read_chunk_slice(&dir, "frames", &fname, q.offset, max_len).map_or_else(
                |_| rejected_chunk(),
                |(total_len, data)| ChunkReply {
                    status: OpStatus::Ok,
                    total_len,
                    data,
                },
            )
        }
        ChunkTarget::Members => {
            let idx = usize::try_from(q.index).unwrap_or(usize::MAX);
            let Some(entry) = m.member_entries.get(idx) else {
                return rejected_chunk();
            };
            entry.encode().map_or_else(
                |_| rejected_chunk(),
                |bytes| slice_in_memory(&bytes, q.offset, max_len),
            )
        }
        ChunkTarget::Revocation => {
            let idx = usize::try_from(q.index).unwrap_or(usize::MAX);
            let Some(rev) = m.revocations.get(idx) else {
                return rejected_chunk();
            };
            encode_revocation(rev).map_or_else(
                |_| rejected_chunk(),
                |bytes| slice_in_memory(&bytes, q.offset, max_len),
            )
        }
    }
}

pub fn verify_op_replay(
    replay: &mut NonceReplayGuard,
    device_id: [u8; 16],
    nonce: [u8; 16],
    ts_secs: u64,
    now_secs: u64,
) -> bool {
    replay
        .check_and_insert(device_id, nonce, ts_secs, now_secs)
        .is_ok()
}

pub fn active_cert(m: &MailboxState, device_id: [u8; 16]) -> Option<&DeviceCert> {
    let cert = m.devices.iter().find(|c| c.device_id == device_id)?;
    if m.revocations.iter().any(|r| r.covers(cert)) {
        return None;
    }
    if cert.not_after_ms != 0 && now_ms() > cert.not_after_ms {
        return None;
    }
    Some(cert)
}

pub fn can_read_mailbox(m: &MailboxState, client_id: &[u8; 64]) -> bool {
    match m.kind {
        MailboxKind::Personal => m.account_vk.is_some(),
        MailboxKind::Shared => m
            .member_log
            .as_ref()
            .is_some_and(|log| log.role_of(client_id).is_some()),
    }
}

pub fn may_write_data(m: &MailboxState, client_id: &[u8; 64]) -> bool {
    match m.kind {
        MailboxKind::Personal => m.account_vk.is_some(),
        MailboxKind::Shared => m
            .member_log
            .as_ref()
            .is_some_and(|log| log.may_write(client_id)),
    }
}

pub const fn rejected_reply() -> OpReply {
    OpReply {
        status: OpStatus::Rejected,
        head_seq: 0,
        member_count: 0,
    }
}

pub fn status_reply(status: OpStatus, m: &MailboxState) -> OpReply {
    OpReply {
        status,
        head_seq: m.head_seq,
        member_count: u32::try_from(m.member_entries.len()).unwrap_or(u32::MAX),
    }
}

const fn rejected_chunk() -> ChunkReply {
    ChunkReply {
        status: OpStatus::Rejected,
        total_len: 0,
        data: Vec::new(),
    }
}

const fn empty_summary(status: OpStatus) -> MailboxSummary {
    MailboxSummary {
        status,
        exists: false,
        snap_id: None,
        snap_chunks: 0,
        snap_generation: 0,
        head_meta: Vec::new(),
        head_seq: 0,
        frames: Vec::new(),
        has_more_frames: false,
        rekeys: Vec::new(),
        revocation_count: 0,
        member_count: 0,
        backup_id: None,
        backup_chunks: 0,
    }
}

fn slice_in_memory(bytes: &[u8], offset: u32, max_len: usize) -> ChunkReply {
    let total_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    if start >= bytes.len() {
        return ChunkReply {
            status: OpStatus::Ok,
            total_len,
            data: Vec::new(),
        };
    }
    let end = start.saturating_add(max_len).min(bytes.len());
    let data = bytes.get(start..end).map_or_else(Vec::new, <[u8]>::to_vec);
    ChunkReply {
        status: OpStatus::Ok,
        total_len,
        data,
    }
}
