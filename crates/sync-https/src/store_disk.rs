//! Atomic on-disk persistence for `sync-https` mailboxes and opaque chunks.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use local::write_atomic;
use memberlog::{ENTRY_WIRE_LEN, Entry};
use pq::SYNC_VK_LEN;
use session::{DeviceCert, Revocation};
use syncwire::reader::Reader;
use syncwire::{
    CERT_WIRE_LEN, REVOCATION_WIRE_LEN, decode_cert, decode_revocation, encode_cert,
    encode_revocation,
};

use crate::limits::{
    MAX_BACKUP_CHUNKS, MAX_ENVELOPE_BYTES, MAX_FRAMES_LOG, MAX_HEAD_META, MAX_MAILBOX_DEVICES,
    MAX_MEMBER_ENTRIES, MAX_REKEYS, MAX_REVOCATIONS, MAX_SNAPSHOT_CHUNKS, SPLIT_CHUNK_MAX,
};
use crate::wire::{MailboxKind, push_bytes_u16};

const DISK_MAGIC: [u8; 4] = *b"ZPMS";
const DISK_VERSION: u16 = 1;

#[derive(Debug)]
pub struct StoredFrame {
    pub seq: u64,
    pub chunk_id: Option<[u8; 32]>,
    pub total_len: u32,
    pub envelope: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct MailboxState {
    pub kind: MailboxKind,
    pub box_id: [u8; 32],
    pub account_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub vault_id: [u8; 16],
    pub anchor: [u8; 32],
    pub member_log: Option<memberlog::MemberLog>,
    pub member_entries: Vec<Entry>,
    pub devices: Vec<DeviceCert>,
    pub revocations: Vec<Revocation>,
    pub snap_id: Option<[u8; 32]>,
    pub snap_chunks: u32,
    pub snap_generation: u64,
    pub head_meta: Vec<u8>,
    pub head_seq: u64,
    pub frames: Vec<StoredFrame>,
    pub rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
    pub backup_id: Option<[u8; 32]>,
    pub backup_chunks: u32,
    pub staged: BTreeMap<[u8; 32], BTreeMap<u32, Vec<u8>>>,
}

impl MailboxState {
    pub const fn new(kind: MailboxKind, box_id: [u8; 32]) -> Self {
        Self {
            kind,
            box_id,
            account_vk: None,
            vault_id: [0u8; 16],
            anchor: [0u8; 32],
            member_log: None,
            member_entries: Vec::new(),
            devices: Vec::new(),
            revocations: Vec::new(),
            snap_id: None,
            snap_chunks: 0,
            snap_generation: 0,
            head_meta: Vec::new(),
            head_seq: 0,
            frames: Vec::new(),
            rekeys: Vec::new(),
            backup_id: None,
            backup_chunks: 0,
            staged: BTreeMap::new(),
        }
    }
}

#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        if let Some(&hi) = HEX.get(usize::from(b >> 4)) {
            out.push(char::from(hi));
        }
        if let Some(&lo) = HEX.get(usize::from(b & 0x0F)) {
            out.push(char::from(lo));
        }
    }
    out
}

pub fn box_dir(root: &Path, kind: MailboxKind, box_id: &[u8; 32]) -> PathBuf {
    let tag = match kind {
        MailboxKind::Personal => "personal",
        MailboxKind::Shared => "shared",
    };
    root.join(format!("{tag}_{}", hex_encode(box_id)))
}

pub fn write_chunk_file(dir: &Path, subdir: &str, name: &str, data: &[u8]) -> anyhow::Result<()> {
    write_atomic(&dir.join(subdir).join(name), data)
}

pub fn read_chunk_slice(
    dir: &Path,
    subdir: &str,
    name: &str,
    offset: u32,
    max_len: usize,
) -> anyhow::Result<(u32, Vec<u8>)> {
    let bytes = fs::read(dir.join(subdir).join(name))?;
    let total = u32::try_from(bytes.len()).map_err(|_| anyhow!("chunk exceeds u32"))?;
    let start = usize::try_from(offset).map_err(|_| anyhow!("offset overflow"))?;
    if start >= bytes.len() {
        return Ok((total, Vec::new()));
    }
    let end = start.saturating_add(max_len).min(bytes.len());
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| anyhow!("chunk slice bounds error"))?;
    Ok((total, slice.to_vec()))
}

pub fn save_mailbox(root: &Path, m: &MailboxState) -> anyhow::Result<()> {
    let dir = box_dir(root, m.kind, &m.box_id);
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(&DISK_MAGIC);
    out.extend_from_slice(&DISK_VERSION.to_be_bytes());
    out.push(m.kind as u8);
    out.extend_from_slice(&m.box_id);
    match &m.account_vk {
        Some(vk) => {
            out.push(1);
            out.extend_from_slice(vk.as_slice());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&m.vault_id);
    out.extend_from_slice(&m.anchor);
    out.extend_from_slice(&u16::try_from(m.member_entries.len())?.to_be_bytes());
    for entry in &m.member_entries {
        out.extend_from_slice(&entry.encode()?);
    }
    out.extend_from_slice(&u16::try_from(m.devices.len())?.to_be_bytes());
    for dev in &m.devices {
        out.extend_from_slice(&encode_cert(dev)?);
    }
    out.extend_from_slice(&u16::try_from(m.revocations.len())?.to_be_bytes());
    for rev in &m.revocations {
        out.extend_from_slice(&encode_revocation(rev)?);
    }
    match m.snap_id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&m.snap_chunks.to_be_bytes());
    out.extend_from_slice(&m.snap_generation.to_be_bytes());
    push_bytes_u16(&mut out, &m.head_meta)?;
    out.extend_from_slice(&m.head_seq.to_be_bytes());
    out.extend_from_slice(&u32::try_from(m.frames.len())?.to_be_bytes());
    for f in &m.frames {
        out.extend_from_slice(&f.seq.to_be_bytes());
        out.extend_from_slice(&f.total_len.to_be_bytes());
        if let Some(id) = f.chunk_id {
            out.push(1);
            out.extend_from_slice(&id);
        } else {
            out.push(0);
            let env = f.envelope.as_deref().unwrap_or(&[]);
            push_bytes_u16(&mut out, env)?;
        }
    }
    out.extend_from_slice(&u16::try_from(m.rekeys.len())?.to_be_bytes());
    for (key_gen, dev, env) in &m.rekeys {
        out.extend_from_slice(&key_gen.to_be_bytes());
        out.extend_from_slice(dev);
        push_bytes_u16(&mut out, env)?;
    }
    match m.backup_id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&m.backup_chunks.to_be_bytes());
    write_atomic(&dir.join("state.bin"), &out)
}

fn decode_mailbox(bytes: &[u8]) -> anyhow::Result<MailboxState> {
    let mut r = Reader::new(bytes);
    if r.array::<4>()? != DISK_MAGIC || r.u16()? != DISK_VERSION {
        anyhow::bail!("unsupported mailbox disk format");
    }
    let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
    let box_id = r.array()?;
    let mut m = MailboxState::new(kind, box_id);
    if r.array::<1>()?[0] != 0 {
        m.account_vk = Some(Box::new(r.array()?));
    }
    m.vault_id = r.array()?;
    m.anchor = r.array()?;
    let m_count = usize::from(r.u16()?);
    if m_count > MAX_MEMBER_ENTRIES {
        anyhow::bail!("stored member count over limit");
    }
    for _ in 0..m_count {
        m.member_entries
            .push(Entry::decode(r.take(ENTRY_WIRE_LEN)?)?);
    }
    if kind == MailboxKind::Shared && !m.member_entries.is_empty() {
        m.member_log = Some(memberlog::MemberLog::from_entries(
            m.vault_id,
            &m.member_entries,
            &m.anchor,
        )?);
    }
    let d_count = usize::from(r.u16()?);
    if d_count > MAX_MAILBOX_DEVICES {
        anyhow::bail!("stored devices over limit");
    }
    for _ in 0..d_count {
        m.devices.push(decode_cert(r.take(CERT_WIRE_LEN)?)?);
    }
    let rev_count = usize::from(r.u16()?);
    if rev_count > MAX_REVOCATIONS {
        anyhow::bail!("stored revocations over limit");
    }
    for _ in 0..rev_count {
        m.revocations
            .push(decode_revocation(r.take(REVOCATION_WIRE_LEN)?)?);
    }
    if r.array::<1>()?[0] != 0 {
        m.snap_id = Some(r.array()?);
    }
    m.snap_chunks = r.u32()?;
    if m.snap_chunks > MAX_SNAPSHOT_CHUNKS {
        anyhow::bail!("stored snapshot chunks over limit");
    }
    m.snap_generation = r.u64()?;
    m.head_meta = r.bytes_u16(MAX_HEAD_META)?.to_vec();
    m.head_seq = r.u64()?;
    let f_count = usize::try_from(r.u32()?).map_err(|_| anyhow!("frame count overflow"))?;
    if f_count > MAX_FRAMES_LOG {
        anyhow::bail!("stored frame count over limit");
    }
    for _ in 0..f_count {
        let seq = r.u64()?;
        let total_len = r.u32()?;
        if usize::try_from(total_len).unwrap_or(usize::MAX) > MAX_ENVELOPE_BYTES {
            anyhow::bail!("stored frame size over limit");
        }
        if r.array::<1>()?[0] != 0 {
            let chunk_id = r.array()?;
            m.frames.push(StoredFrame {
                seq,
                chunk_id: Some(chunk_id),
                total_len,
                envelope: None,
            });
        } else {
            let env = r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec();
            m.frames.push(StoredFrame {
                seq,
                chunk_id: None,
                total_len,
                envelope: Some(env),
            });
        }
    }
    let rekey_count = usize::from(r.u16()?);
    if rekey_count > MAX_REKEYS {
        anyhow::bail!("stored rekeys over limit");
    }
    for _ in 0..rekey_count {
        let key_gen = r.u64()?;
        let dev = r.array()?;
        let env = r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec();
        m.rekeys.push((key_gen, dev, env));
    }
    if r.array::<1>()?[0] != 0 {
        m.backup_id = Some(r.array()?);
    }
    m.backup_chunks = r.u32()?;
    if m.backup_chunks > MAX_BACKUP_CHUNKS {
        anyhow::bail!("stored backup chunks over limit");
    }
    r.finish()?;
    Ok(m)
}

pub fn load_all_mailboxes(root: &Path) -> anyhow::Result<BTreeMap<(u8, [u8; 32]), MailboxState>> {
    let mut map = BTreeMap::new();
    if !root.exists() {
        fs::create_dir_all(root)?;
        return Ok(map);
    }
    for entry in fs::read_dir(root)? {
        let Ok(entry) = entry else {
            continue;
        };
        let state_path = entry.path().join("state.bin");
        if !state_path.is_file() {
            continue;
        }
        let bytes = fs::read(&state_path)?;
        let m = decode_mailbox(&bytes)?;
        map.insert((m.kind as u8, m.box_id), m);
    }
    Ok(map)
}
