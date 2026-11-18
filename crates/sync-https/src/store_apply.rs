//! Concrete commit handlers and staged chunk assembly helpers for [`crate::store::MailboxStore`].

use std::collections::BTreeMap;
use std::path::Path;

use memberlog::{ENTRY_WIRE_LEN, Entry};
use session::DeviceCert;
use syncwire::{REVOCATION_WIRE_LEN, decode_revocation};

use crate::auth::now_ms;
use crate::limits::{
    MAX_ENVELOPE_BYTES, MAX_FRAMES_LOG, MAX_MAILBOX_DEVICES, MAX_MEMBER_ENTRIES, MAX_REVOCATIONS,
    MAX_STAGED_UPLOADS, SPLIT_CHUNK_MAX,
};
use crate::store::{may_write_data, rejected_reply, status_reply};
use crate::store_disk::{
    MailboxState, StoredFrame, box_dir, hex_encode, save_mailbox, write_chunk_file,
};
use crate::wire::MailboxKind;
use crate::wire_rpc::{OpReply, OpStatus, PushEvent};

pub fn apply_commit_snapshot(
    data_dir: &Path,
    m: &mut MailboxState,
    cert: &DeviceCert,
    snap_id: [u8; 32],
    total_chunks: u32,
    key_generation: u64,
    head_meta: Vec<u8>,
) -> (OpReply, Option<PushEvent>) {
    if !may_write_data(m, &cert.client_id) {
        return (rejected_reply(), None);
    }
    let Ok(chunks) = take_staged_chunks(&mut m.staged, snap_id, total_chunks) else {
        return (rejected_reply(), None);
    };
    let dir = box_dir(data_dir, m.kind, &m.box_id);
    for (idx, bytes) in chunks.iter().enumerate() {
        if write_chunk_file(&dir, "snap", &format!("{idx}.bin"), bytes).is_err() {
            return (rejected_reply(), None);
        }
    }
    m.snap_id = Some(snap_id);
    m.snap_chunks = total_chunks;
    m.snap_generation = key_generation;
    m.head_meta = head_meta;
    m.head_seq = m.head_seq.saturating_add(1);
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), Some(make_push(m)))
}

pub fn apply_append_frame(
    data_dir: &Path,
    m: &mut MailboxState,
    cert: &DeviceCert,
    envelope: Vec<u8>,
) -> (OpReply, Option<PushEvent>) {
    if !may_write_data(m, &cert.client_id) || m.frames.len() >= MAX_FRAMES_LOG {
        return (rejected_reply(), None);
    }
    let seq = m.head_seq.saturating_add(1);
    let total_len = u32::try_from(envelope.len()).unwrap_or(u32::MAX);
    m.frames.push(StoredFrame {
        seq,
        chunk_id: None,
        total_len,
        envelope: Some(envelope),
    });
    m.head_seq = seq;
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), Some(make_push(m)))
}

pub fn apply_commit_chunked_frame(
    data_dir: &Path,
    m: &mut MailboxState,
    cert: &DeviceCert,
    chunk_id: [u8; 32],
    total_chunks: u32,
) -> (OpReply, Option<PushEvent>) {
    if !may_write_data(m, &cert.client_id) || m.frames.len() >= MAX_FRAMES_LOG {
        return (rejected_reply(), None);
    }
    let Ok(bytes) = take_staged_bytes(&mut m.staged, chunk_id, total_chunks, MAX_ENVELOPE_BYTES)
    else {
        return (rejected_reply(), None);
    };
    let dir = box_dir(data_dir, m.kind, &m.box_id);
    let fname = format!("{}.bin", hex_encode(&chunk_id));
    if write_chunk_file(&dir, "frames", &fname, &bytes).is_err() {
        return (rejected_reply(), None);
    }
    let seq = m.head_seq.saturating_add(1);
    let total_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    m.frames.push(StoredFrame {
        seq,
        chunk_id: Some(chunk_id),
        total_len,
        envelope: None,
    });
    m.head_seq = seq;
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), Some(make_push(m)))
}

pub fn apply_commit_revocation(
    data_dir: &Path,
    m: &mut MailboxState,
    cert: &DeviceCert,
    chunk_id: [u8; 32],
    total_chunks: u32,
) -> (OpReply, Option<PushEvent>) {
    let Some(vk) = m.account_vk.as_deref() else {
        return (rejected_reply(), None);
    };
    if m.kind != MailboxKind::Personal || m.revocations.len() >= MAX_REVOCATIONS {
        return (rejected_reply(), None);
    }
    let Ok(raw) = take_staged_bytes(&mut m.staged, chunk_id, total_chunks, REVOCATION_WIRE_LEN)
    else {
        return (rejected_reply(), None);
    };
    let Ok(rev) = decode_revocation(&raw) else {
        return (rejected_reply(), None);
    };
    if rev.client_id != cert.client_id || rev.verify(vk, now_ms()).is_err() {
        return (rejected_reply(), None);
    }
    if !m
        .revocations
        .iter()
        .any(|r| r.device_id == rev.device_id && r.serial == rev.serial)
    {
        m.devices.retain(|d| !rev.covers(d));
        m.revocations.push(rev);
    }
    m.head_seq = m.head_seq.saturating_add(1);
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), Some(make_push(m)))
}

pub fn apply_commit_members(
    data_dir: &Path,
    m: &mut MailboxState,
    cert: &DeviceCert,
    chunk_id: [u8; 32],
    total_chunks: u32,
) -> (OpReply, Option<PushEvent>) {
    if m.kind != MailboxKind::Shared {
        return (rejected_reply(), None);
    }
    let Some(log) = &mut m.member_log else {
        return (rejected_reply(), None);
    };
    if log.role_of(&cert.client_id).is_none() {
        return (rejected_reply(), None);
    }
    let Ok(raw) = take_staged_bytes(&mut m.staged, chunk_id, total_chunks, MAX_ENVELOPE_BYTES)
    else {
        return (rejected_reply(), None);
    };
    let Ok(entries) = decode_member_entries(&raw) else {
        return (rejected_reply(), None);
    };
    if m.member_entries.len().saturating_add(entries.len()) > MAX_MEMBER_ENTRIES
        || log.merge(&entries).is_err()
    {
        return (rejected_reply(), None);
    }
    m.member_entries = log.entries().to_vec();
    m.head_seq = m.head_seq.saturating_add(1);
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), Some(make_push(m)))
}

pub fn apply_commit_backup(
    data_dir: &Path,
    m: &mut MailboxState,
    backup_id: [u8; 32],
    total_chunks: u32,
) -> (OpReply, Option<PushEvent>) {
    if m.kind != MailboxKind::Personal {
        return (rejected_reply(), None);
    }
    let Ok(chunks) = take_staged_chunks(&mut m.staged, backup_id, total_chunks) else {
        return (rejected_reply(), None);
    };
    let dir = box_dir(data_dir, m.kind, &m.box_id);
    for (idx, bytes) in chunks.iter().enumerate() {
        if write_chunk_file(&dir, "backup", &format!("{idx}.bin"), bytes).is_err() {
            return (rejected_reply(), None);
        }
    }
    m.backup_id = Some(backup_id);
    m.backup_chunks = total_chunks;
    if save_mailbox(data_dir, m).is_err() {
        return (rejected_reply(), None);
    }
    (status_reply(OpStatus::Ok, m), None)
}

pub fn upsert_device(m: &mut MailboxState, cert: DeviceCert) -> anyhow::Result<()> {
    if let Some(existing) = m.devices.iter().find(|d| d.device_id == cert.device_id) {
        if existing.device_vk == cert.device_vk && existing.serial == cert.serial {
            return Ok(());
        }
        anyhow::bail!("conflicting cert for known device");
    }
    if m.devices.len() >= MAX_MAILBOX_DEVICES {
        anyhow::bail!("mailbox device directory full");
    }
    m.devices.push(cert);
    Ok(())
}

pub fn make_push(m: &MailboxState) -> PushEvent {
    PushEvent {
        box_id: m.box_id,
        kind: m.kind,
        head_seq: m.head_seq,
        member_count: u32::try_from(m.member_entries.len()).unwrap_or(u32::MAX),
        revocation_count: u32::try_from(m.revocations.len()).unwrap_or(u32::MAX),
    }
}

pub fn stage_chunk(
    staged: &mut BTreeMap<[u8; 32], BTreeMap<u32, Vec<u8>>>,
    chunk_id: [u8; 32],
    index: u32,
    total: u32,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    if index >= total || data.len() > SPLIT_CHUNK_MAX {
        anyhow::bail!("invalid staged chunk");
    }
    if !staged.contains_key(&chunk_id)
        && staged.len() >= MAX_STAGED_UPLOADS
        && let Some(first_key) = staged.keys().next().copied()
    {
        staged.remove(&first_key);
    }
    staged.entry(chunk_id).or_default().insert(index, data);
    Ok(())
}

pub fn take_staged_chunks(
    staged: &mut BTreeMap<[u8; 32], BTreeMap<u32, Vec<u8>>>,
    chunk_id: [u8; 32],
    total: u32,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let map = staged
        .remove(&chunk_id)
        .ok_or_else(|| anyhow::anyhow!("missing staged upload"))?;
    let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    for idx in 0..total {
        let chunk = map
            .get(&idx)
            .ok_or_else(|| anyhow::anyhow!("incomplete staged upload"))?;
        out.push(chunk.clone());
    }
    Ok(out)
}

pub fn take_staged_bytes(
    staged: &mut BTreeMap<[u8; 32], BTreeMap<u32, Vec<u8>>>,
    chunk_id: [u8; 32],
    total: u32,
    max_total_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let chunks = take_staged_chunks(staged, chunk_id, total)?;
    let total_len: usize = chunks.iter().map(Vec::len).sum();
    if total_len > max_total_bytes {
        anyhow::bail!("assembled upload exceeds limit");
    }
    let mut out = Vec::with_capacity(total_len);
    for c in chunks {
        out.extend_from_slice(&c);
    }
    Ok(out)
}

pub fn decode_member_entries(raw: &[u8]) -> anyhow::Result<Vec<Entry>> {
    if raw.is_empty() || !raw.len().is_multiple_of(ENTRY_WIRE_LEN) {
        anyhow::bail!("invalid member entries byte length");
    }
    let count = raw.len() / ENTRY_WIRE_LEN;
    if count > MAX_MEMBER_ENTRIES {
        anyhow::bail!("too many member entries");
    }
    let (slices, _) = raw.as_chunks::<ENTRY_WIRE_LEN>();
    let mut out = Vec::with_capacity(count);
    for slice in slices {
        out.push(Entry::decode(slice)?);
    }
    Ok(out)
}
