//! Canonical binary wire definitions for mailbox operations, transfer
//! chunks, and queries.

use anyhow::anyhow;
use memberlog::ENTRY_WIRE_LEN;
use pq::SYNC_VK_LEN;
use syncwire::reader::Reader;
use syncwire::{CERT_WIRE_LEN, REVOCATION_WIRE_LEN};

use crate::limits::{
    MAX_BACKUP_CHUNKS, MAX_HEAD_META, MAX_MEMBER_ENTRIES, MAX_SNAPSHOT_CHUNKS, SPLIT_CHUNK_MAX,
};

/// Mailbox compartment discriminant.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MailboxKind {
    /// Per-account personal vault, device revocations, rekeys, and backups.
    Personal = 1,
    /// Shared multi-user vault, member log, and shared record frames.
    Shared = 2,
}

impl TryFrom<u8> for MailboxKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Personal),
            2 => Ok(Self::Shared),
            _ => Err(anyhow!("unknown mailbox kind")),
        }
    }
}

/// Download target selector for `ChunkQuery` slice transfers.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkTarget {
    /// Committed vault snapshot chunk.
    Snapshot = 1,
    /// Large externalized frame envelope.
    Frame = 2,
    /// Encoded `memberlog::Entry` bytes by entry index.
    Members = 3,
    /// Encoded `session::Revocation` bytes by revocation index.
    Revocation = 4,
    /// Committed cloud backup chunk.
    Backup = 5,
}

impl TryFrom<u8> for ChunkTarget {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Frame),
            3 => Ok(Self::Members),
            4 => Ok(Self::Revocation),
            5 => Ok(Self::Backup),
            _ => Err(anyhow!("unknown chunk target")),
        }
    }
}

/// Wire operations accepted by `/<slug>/v1/op` and `/ws`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpPayload {
    /// Register (or stage if mailbox unanchored) this device's signed certificate.
    StageCert { cert_wire: Vec<u8> },
    /// Anchor a new personal mailbox's immutable `account_vk` (or verify against
    /// existing `account_vk`) and promote the caller's staged certificate.
    AnchorPersonalRoot { root_vk: Box<[u8; SYNC_VK_LEN]> },
    /// Upload one bounded (`<= SPLIT_CHUNK_MAX`) staging chunk under `chunk_id`.
    PutChunk {
        chunk_id: [u8; 32],
        index: u32,
        total: u32,
        data: Vec<u8>,
    },
    /// Commit a previously staged set of snapshot chunks under `snap_id`.
    CommitSnapshot {
        snap_id: [u8; 32],
        total_chunks: u32,
        key_generation: u64,
        head_meta: Vec<u8>,
    },
    /// Append a small opaque frame envelope inline.
    AppendFrame {
        frame_seq_hint: u64,
        envelope: Vec<u8>,
    },
    /// Assemble and append an opaque frame envelope previously uploaded via `PutChunk`.
    CommitChunkedFrame {
        chunk_id: [u8; 32],
        total_chunks: u32,
    },
    /// Store an encrypted `VK` rotation grant targeted at `target_device`.
    PutRekey {
        generation: u64,
        target_device: [u8; 16],
        envelope: Vec<u8>,
    },
    /// Assemble and verify a signed device revocation (`REVOCATION_WIRE_LEN`) from chunks.
    CommitRevocation {
        chunk_id: [u8; 32],
        total_chunks: u32,
    },
    /// Initialize a shared mailbox from chunked `MemberLog` genesis/history entries.
    CommitInitShared {
        vault_id: [u8; 16],
        anchor: [u8; 32],
        chunk_id: [u8; 32],
        total_chunks: u32,
    },
    /// Append chunked `MemberLog` entries to an existing shared mailbox.
    CommitMembers {
        chunk_id: [u8; 32],
        total_chunks: u32,
    },
    /// Commit an uploaded remote encrypted cloud backup.
    CommitBackup {
        backup_id: [u8; 32],
        total_chunks: u32,
    },
}

const OP_STAGE_CERT: u8 = 1;
const OP_ANCHOR_PERSONAL: u8 = 2;
const OP_PUT_CHUNK: u8 = 3;
const OP_COMMIT_SNAPSHOT: u8 = 4;
const OP_APPEND_FRAME: u8 = 5;
const OP_COMMIT_CHUNKED_FRAME: u8 = 6;
const OP_PUT_REKEY: u8 = 7;
const OP_COMMIT_REVOCATION: u8 = 8;
const OP_COMMIT_INIT_SHARED: u8 = 9;
const OP_COMMIT_MEMBERS: u8 = 10;
const OP_COMMIT_BACKUP: u8 = 11;

pub(crate) fn push_bytes_u16(out: &mut Vec<u8>, bytes: &[u8]) -> anyhow::Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| anyhow!("wire field exceeds u16"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

impl OpPayload {
    /// Encode this operation payload to canonical bytes.
    ///
    /// # Errors
    ///
    /// Length exceeds protocol bounds.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        match self {
            Self::StageCert { cert_wire } => {
                if cert_wire.len() != CERT_WIRE_LEN {
                    anyhow::bail!("invalid cert wire length");
                }
                out.push(OP_STAGE_CERT);
                push_bytes_u16(&mut out, cert_wire)?;
            }
            Self::AnchorPersonalRoot { root_vk } => {
                out.push(OP_ANCHOR_PERSONAL);
                out.extend_from_slice(root_vk.as_slice());
            }
            Self::PutChunk {
                chunk_id,
                index,
                total,
                data,
            } => {
                if data.len() > SPLIT_CHUNK_MAX {
                    anyhow::bail!("chunk exceeds SPLIT_CHUNK_MAX");
                }
                out.push(OP_PUT_CHUNK);
                out.extend_from_slice(chunk_id);
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(&total.to_be_bytes());
                push_bytes_u16(&mut out, data)?;
            }
            Self::CommitSnapshot {
                snap_id,
                total_chunks,
                key_generation,
                head_meta,
            } => {
                if head_meta.len() > MAX_HEAD_META {
                    anyhow::bail!("head_meta exceeds bound");
                }
                out.push(OP_COMMIT_SNAPSHOT);
                out.extend_from_slice(snap_id);
                out.extend_from_slice(&total_chunks.to_be_bytes());
                out.extend_from_slice(&key_generation.to_be_bytes());
                push_bytes_u16(&mut out, head_meta)?;
            }
            Self::AppendFrame {
                frame_seq_hint,
                envelope,
            } => {
                if envelope.len() > SPLIT_CHUNK_MAX {
                    anyhow::bail!("inline frame exceeds SPLIT_CHUNK_MAX");
                }
                out.push(OP_APPEND_FRAME);
                out.extend_from_slice(&frame_seq_hint.to_be_bytes());
                push_bytes_u16(&mut out, envelope)?;
            }
            Self::CommitChunkedFrame {
                chunk_id,
                total_chunks,
            } => push_chunk_commit(&mut out, OP_COMMIT_CHUNKED_FRAME, chunk_id, *total_chunks),
            Self::PutRekey {
                generation,
                target_device,
                envelope,
            } => {
                if envelope.len() > SPLIT_CHUNK_MAX {
                    anyhow::bail!("rekey envelope exceeds SPLIT_CHUNK_MAX");
                }
                out.push(OP_PUT_REKEY);
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(target_device);
                push_bytes_u16(&mut out, envelope)?;
            }
            Self::CommitRevocation {
                chunk_id,
                total_chunks,
            } => push_chunk_commit(&mut out, OP_COMMIT_REVOCATION, chunk_id, *total_chunks),
            Self::CommitInitShared {
                vault_id,
                anchor,
                chunk_id,
                total_chunks,
            } => {
                out.push(OP_COMMIT_INIT_SHARED);
                out.extend_from_slice(vault_id);
                out.extend_from_slice(anchor);
                out.extend_from_slice(chunk_id);
                out.extend_from_slice(&total_chunks.to_be_bytes());
            }
            Self::CommitMembers {
                chunk_id,
                total_chunks,
            } => push_chunk_commit(&mut out, OP_COMMIT_MEMBERS, chunk_id, *total_chunks),
            Self::CommitBackup {
                backup_id,
                total_chunks,
            } => push_chunk_commit(&mut out, OP_COMMIT_BACKUP, backup_id, *total_chunks),
        }
        Ok(out)
    }

    /// Decode and strictly bound-check an encoded `OpPayload`.
    ///
    /// # Errors
    ///
    /// Unknown tag, truncated bytes, trailing bytes, or bound violation.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        let tag = r.array::<1>()?[0];
        let op = decode_tag(tag, &mut r)?;
        r.finish()?;
        Ok(op)
    }
}

fn push_chunk_commit(out: &mut Vec<u8>, tag: u8, id: &[u8; 32], total_chunks: u32) {
    out.push(tag);
    out.extend_from_slice(id);
    out.extend_from_slice(&total_chunks.to_be_bytes());
}

fn decode_chunk_commit(r: &mut Reader<'_>, max_chunks: u32) -> anyhow::Result<([u8; 32], u32)> {
    let chunk_id = r.array()?;
    let total_chunks = r.u32()?;
    if total_chunks == 0 || total_chunks > max_chunks {
        anyhow::bail!("commit chunk count out of bounds");
    }
    Ok((chunk_id, total_chunks))
}

fn decode_tag(tag: u8, r: &mut Reader<'_>) -> anyhow::Result<OpPayload> {
    let max_member_chunks =
        u32::try_from(MAX_MEMBER_ENTRIES * ENTRY_WIRE_LEN / 512 + 4).unwrap_or(32_768);
    Ok(match tag {
        OP_STAGE_CERT => {
            let cert_wire = r.bytes_u16(CERT_WIRE_LEN)?.to_vec();
            if cert_wire.len() != CERT_WIRE_LEN {
                anyhow::bail!("invalid cert wire length");
            }
            OpPayload::StageCert { cert_wire }
        }
        OP_ANCHOR_PERSONAL => OpPayload::AnchorPersonalRoot {
            root_vk: Box::new(r.array()?),
        },
        OP_PUT_CHUNK => {
            let chunk_id = r.array()?;
            let index = r.u32()?;
            let total = r.u32()?;
            if total == 0 || index >= total || total > MAX_BACKUP_CHUNKS {
                anyhow::bail!("chunk indices out of bounds");
            }
            OpPayload::PutChunk {
                chunk_id,
                index,
                total,
                data: r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec(),
            }
        }
        OP_COMMIT_SNAPSHOT => {
            let (snap_id, total_chunks) = decode_chunk_commit(r, MAX_SNAPSHOT_CHUNKS)?;
            OpPayload::CommitSnapshot {
                snap_id,
                total_chunks,
                key_generation: r.u64()?,
                head_meta: r.bytes_u16(MAX_HEAD_META)?.to_vec(),
            }
        }
        OP_APPEND_FRAME => OpPayload::AppendFrame {
            frame_seq_hint: r.u64()?,
            envelope: r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec(),
        },
        OP_COMMIT_CHUNKED_FRAME => {
            let (chunk_id, total_chunks) = decode_chunk_commit(r, 512)?;
            OpPayload::CommitChunkedFrame {
                chunk_id,
                total_chunks,
            }
        }
        OP_PUT_REKEY => OpPayload::PutRekey {
            generation: r.u64()?,
            target_device: r.array()?,
            envelope: r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec(),
        },
        OP_COMMIT_REVOCATION => {
            let max_rev = u32::try_from(REVOCATION_WIRE_LEN).unwrap_or(10_000);
            let (chunk_id, total_chunks) = decode_chunk_commit(r, max_rev)?;
            OpPayload::CommitRevocation {
                chunk_id,
                total_chunks,
            }
        }
        OP_COMMIT_INIT_SHARED => {
            let vault_id = r.array()?;
            let anchor = r.array()?;
            let (chunk_id, total_chunks) = decode_chunk_commit(r, max_member_chunks)?;
            OpPayload::CommitInitShared {
                vault_id,
                anchor,
                chunk_id,
                total_chunks,
            }
        }
        OP_COMMIT_MEMBERS => {
            let (chunk_id, total_chunks) = decode_chunk_commit(r, max_member_chunks)?;
            OpPayload::CommitMembers {
                chunk_id,
                total_chunks,
            }
        }
        OP_COMMIT_BACKUP => {
            let (backup_id, total_chunks) = decode_chunk_commit(r, MAX_BACKUP_CHUNKS)?;
            OpPayload::CommitBackup {
                backup_id,
                total_chunks,
            }
        }
        _ => anyhow::bail!("unknown operation payload tag"),
    })
}
