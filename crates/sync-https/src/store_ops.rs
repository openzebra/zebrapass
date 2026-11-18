//! Authenticated certificate staging, anchoring, and operation dispatch on [`MailboxStore`].

use memberlog::{MemberLog, Role};
use pq::SYNC_VK_LEN;
use secret::ct_eq;
use session::DeviceCert;
use syncwire::decode_cert;

use crate::auth::{now_ms, now_unix_secs, verify_signed_op};
use crate::limits::{MAX_ENVELOPE_BYTES, MAX_PENDING_CERTS, MAX_REKEYS};
use crate::store::{
    MailboxStore, active_cert, may_write_data, rejected_reply, status_reply, verify_op_replay,
};
use crate::store_apply::{
    apply_append_frame, apply_commit_backup, apply_commit_chunked_frame, apply_commit_members,
    apply_commit_revocation, apply_commit_snapshot, decode_member_entries, make_push, stage_chunk,
    take_staged_bytes, upsert_device,
};
use crate::store_disk::{MailboxState, save_mailbox};
use crate::wire::{MailboxKind, OpPayload};
use crate::wire_rpc::{OpReply, OpStatus, PushEvent, SignedOp};

impl MailboxStore {
    fn insert_pending(&mut self, key: (u8, [u8; 32], [u8; 16]), cert: DeviceCert) {
        if !self.pending_certs.contains_key(&key) {
            while self.pending_order.len() >= MAX_PENDING_CERTS {
                if let Some(old) = self.pending_order.pop_front() {
                    self.pending_certs.remove(&old);
                }
            }
            self.pending_order.push_back(key);
        }
        self.pending_certs.insert(key, cert);
    }

    pub(crate) fn handle_stage_cert(
        &mut self,
        op: &SignedOp,
        cert_wire: &[u8],
    ) -> (OpReply, Option<PushEvent>) {
        let Ok(cert) = decode_cert(cert_wire) else {
            return (rejected_reply(), None);
        };
        if cert.device_id != op.device_id
            || cert.device_id == [0u8; 16]
            || verify_signed_op(&self.origin, op, &cert.device_vk).is_err()
        {
            return (rejected_reply(), None);
        }
        let m_key = (op.kind as u8, op.box_id);
        let now = now_ms();
        if let Some(m) = self.mailboxes.get_mut(&m_key) {
            if m.revocations.iter().any(|r| r.covers(&cert)) {
                return (rejected_reply(), None);
            }
            let verified = match m.kind {
                MailboxKind::Personal => {
                    if let Some(vk) = m.account_vk.as_deref() {
                        cert.verify(vk, now).is_ok()
                    } else {
                        let reply = status_reply(OpStatus::NeedAnchor, m);
                        self.insert_pending((op.kind as u8, op.box_id, op.device_id), cert);
                        return (reply, None);
                    }
                }
                MailboxKind::Shared => {
                    if let Some(log) = m.member_log.as_ref() {
                        let Some(member) = log
                            .members()
                            .iter()
                            .find(|mb| mb.client_id == cert.client_id)
                        else {
                            return (rejected_reply(), None);
                        };
                        cert.verify(&member.root_vk, now).is_ok()
                    } else {
                        let reply = status_reply(OpStatus::NeedAnchor, m);
                        self.insert_pending((op.kind as u8, op.box_id, op.device_id), cert);
                        return (reply, None);
                    }
                }
            };
            if !verified
                || upsert_device(m, cert).is_err()
                || save_mailbox(&self.data_dir, m).is_err()
            {
                return (rejected_reply(), None);
            }
            return (status_reply(OpStatus::Ok, m), None);
        }
        self.insert_pending((op.kind as u8, op.box_id, op.device_id), cert);
        (
            OpReply {
                status: OpStatus::Ok,
                head_seq: 0,
                member_count: 0,
            },
            None,
        )
    }

    pub(crate) fn handle_anchor_personal(
        &mut self,
        op: &SignedOp,
        root_vk: &[u8; SYNC_VK_LEN],
    ) -> (OpReply, Option<PushEvent>) {
        if op.kind != MailboxKind::Personal {
            return (rejected_reply(), None);
        }
        let p_key = (op.kind as u8, op.box_id, op.device_id);
        let m_key = (op.kind as u8, op.box_id);
        let Some(cert) = self.pending_certs.get(&p_key).cloned().or_else(|| {
            self.mailboxes
                .get(&m_key)
                .and_then(|m| active_cert(m, op.device_id).cloned())
        }) else {
            return (
                OpReply {
                    status: OpStatus::NeedCert,
                    head_seq: 0,
                    member_count: 0,
                },
                None,
            );
        };
        if verify_signed_op(&self.origin, op, &cert.device_vk).is_err()
            || cert.verify(root_vk, now_ms()).is_err()
        {
            return (rejected_reply(), None);
        }
        let m = self
            .mailboxes
            .entry(m_key)
            .or_insert_with(|| MailboxState::new(MailboxKind::Personal, op.box_id));
        if m.revocations.iter().any(|r| r.covers(&cert)) {
            return (rejected_reply(), None);
        }
        if let Some(existing_vk) = m.account_vk.as_deref() {
            if !ct_eq(existing_vk, root_vk) {
                return (rejected_reply(), None);
            }
        } else {
            m.account_vk = Some(Box::new(*root_vk));
        }
        if upsert_device(m, cert).is_err() || save_mailbox(&self.data_dir, m).is_err() {
            return (rejected_reply(), None);
        }
        self.pending_certs.remove(&p_key);
        (status_reply(OpStatus::Ok, m), None)
    }

    pub(crate) fn handle_init_shared(
        &mut self,
        op: &SignedOp,
        vault_id: [u8; 16],
        anchor: [u8; 32],
        chunk_id: [u8; 32],
        total_chunks: u32,
    ) -> (OpReply, Option<PushEvent>) {
        if op.kind != MailboxKind::Shared {
            return (rejected_reply(), None);
        }
        let m_key = (op.kind as u8, op.box_id);
        let p_key = (op.kind as u8, op.box_id, op.device_id);
        let Some(cert) = self.pending_certs.get(&p_key).cloned().or_else(|| {
            self.mailboxes
                .get(&m_key)
                .and_then(|m| active_cert(m, op.device_id).cloned())
        }) else {
            return (
                OpReply {
                    status: OpStatus::NeedCert,
                    head_seq: 0,
                    member_count: 0,
                },
                None,
            );
        };
        if verify_signed_op(&self.origin, op, &cert.device_vk).is_err() {
            return (rejected_reply(), None);
        }
        let Some(m) = self.mailboxes.get_mut(&m_key) else {
            return (rejected_reply(), None);
        };
        if m.revocations.iter().any(|r| r.covers(&cert)) {
            return (rejected_reply(), None);
        }
        let Ok(raw) = take_staged_bytes(&mut m.staged, chunk_id, total_chunks, MAX_ENVELOPE_BYTES)
        else {
            return (rejected_reply(), None);
        };
        let Ok(entries) = decode_member_entries(&raw) else {
            return (rejected_reply(), None);
        };
        let Ok(log) = MemberLog::from_entries(vault_id, &entries, &anchor) else {
            return (rejected_reply(), None);
        };
        let Some(member) = log
            .members()
            .iter()
            .find(|mb| mb.client_id == cert.client_id)
        else {
            return (rejected_reply(), None);
        };
        if !member.role.can_manage() || cert.verify(&member.root_vk, now_ms()).is_err() {
            return (rejected_reply(), None);
        }
        if let Some(existing) = &mut m.member_log {
            if m.vault_id != vault_id || m.anchor != anchor || existing.merge(&entries).is_err() {
                return (rejected_reply(), None);
            }
            m.member_entries = existing.entries().to_vec();
        } else {
            m.vault_id = vault_id;
            m.anchor = anchor;
            m.member_entries = entries;
            m.member_log = Some(log);
        }
        if upsert_device(m, cert).is_err() || save_mailbox(&self.data_dir, m).is_err() {
            return (rejected_reply(), None);
        }
        self.pending_certs.remove(&p_key);
        (status_reply(OpStatus::Ok, m), Some(make_push(m)))
    }

    pub(crate) fn stage_unanchored_shared_chunk(
        &mut self,
        op: &SignedOp,
        chunk_id: [u8; 32],
        index: u32,
        total: u32,
        data: Vec<u8>,
    ) -> OpReply {
        if op.kind != MailboxKind::Shared || total > 256 {
            return rejected_reply();
        }
        let p_key = (op.kind as u8, op.box_id, op.device_id);
        let Some(cert) = self.pending_certs.get(&p_key).cloned() else {
            return OpReply {
                status: OpStatus::NeedCert,
                head_seq: 0,
                member_count: 0,
            };
        };
        if verify_signed_op(&self.origin, op, &cert.device_vk).is_err() {
            return rejected_reply();
        }
        let m = self
            .mailboxes
            .entry((op.kind as u8, op.box_id))
            .or_insert_with(|| MailboxState::new(MailboxKind::Shared, op.box_id));
        if stage_chunk(&mut m.staged, chunk_id, index, total, data).is_err() {
            return rejected_reply();
        }
        status_reply(OpStatus::Ok, m)
    }

    fn missing_mailbox_reply(&self, op: &SignedOp) -> OpReply {
        let has_pending =
            self.pending_certs
                .contains_key(&(op.kind as u8, op.box_id, op.device_id));
        let status = if has_pending && op.kind == MailboxKind::Personal {
            OpStatus::NeedAnchor
        } else {
            OpStatus::NeedCert
        };
        OpReply {
            status,
            head_seq: 0,
            member_count: 0,
        }
    }

    pub(crate) fn handle_mailbox_op(
        &mut self,
        op: &SignedOp,
        payload: OpPayload,
    ) -> (OpReply, Option<PushEvent>) {
        let m_key = (op.kind as u8, op.box_id);
        if !self.mailboxes.contains_key(&m_key) {
            return (self.missing_mailbox_reply(op), None);
        }
        let Some(m) = self.mailboxes.get_mut(&m_key) else {
            return (rejected_reply(), None);
        };
        let Some(cert) = active_cert(m, op.device_id).cloned() else {
            return (
                OpReply {
                    status: OpStatus::NeedCert,
                    head_seq: m.head_seq,
                    member_count: u32::try_from(m.member_entries.len()).unwrap_or(u32::MAX),
                },
                None,
            );
        };
        if verify_signed_op(&self.origin, op, &cert.device_vk).is_err() {
            return (rejected_reply(), None);
        }
        match payload {
            OpPayload::PutChunk {
                chunk_id,
                index,
                total,
                data,
            } => {
                let reader_leave = m.kind == MailboxKind::Shared
                    && total <= 32
                    && m.member_log
                        .as_ref()
                        .is_some_and(|l| l.role_of(&cert.client_id) == Some(Role::Reader));
                if !may_write_data(m, &cert.client_id) && !reader_leave {
                    return (rejected_reply(), None);
                }
                if stage_chunk(&mut m.staged, chunk_id, index, total, data).is_err() {
                    return (rejected_reply(), None);
                }
                (status_reply(OpStatus::Ok, m), None)
            }
            OpPayload::CommitSnapshot {
                snap_id,
                total_chunks,
                key_generation,
                head_meta,
            } => apply_commit_snapshot(
                &self.data_dir,
                m,
                &cert,
                snap_id,
                total_chunks,
                key_generation,
                head_meta,
            ),
            OpPayload::AppendFrame {
                frame_seq_hint: _,
                envelope,
            } => apply_append_frame(&self.data_dir, m, &cert, envelope),
            OpPayload::CommitChunkedFrame {
                chunk_id,
                total_chunks,
            } => apply_commit_chunked_frame(&self.data_dir, m, &cert, chunk_id, total_chunks),
            OpPayload::PutRekey {
                generation,
                target_device,
                envelope,
            } => {
                if m.kind != MailboxKind::Personal || m.rekeys.len() >= MAX_REKEYS {
                    return (rejected_reply(), None);
                }
                m.rekeys.push((generation, target_device, envelope));
                m.head_seq = m.head_seq.saturating_add(1);
                if save_mailbox(&self.data_dir, m).is_err() {
                    return (rejected_reply(), None);
                }
                (status_reply(OpStatus::Ok, m), Some(make_push(m)))
            }
            OpPayload::CommitRevocation {
                chunk_id,
                total_chunks,
            } => apply_commit_revocation(&self.data_dir, m, &cert, chunk_id, total_chunks),
            OpPayload::CommitMembers {
                chunk_id,
                total_chunks,
            } => apply_commit_members(&self.data_dir, m, &cert, chunk_id, total_chunks),
            OpPayload::CommitBackup {
                backup_id,
                total_chunks,
            } => apply_commit_backup(&self.data_dir, m, backup_id, total_chunks),
            OpPayload::StageCert { .. }
            | OpPayload::AnchorPersonalRoot { .. }
            | OpPayload::CommitInitShared { .. } => (rejected_reply(), None),
        }
    }

    pub(crate) fn check_replay_op(&mut self, op: &SignedOp) -> bool {
        verify_op_replay(
            &mut self.replay,
            op.device_id,
            op.nonce,
            op.timestamp_secs,
            now_unix_secs(),
        )
    }
}
