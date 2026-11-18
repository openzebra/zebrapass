//! Bounded `SplitHTTP` reply and WebSocket push event codecs.

use anyhow::anyhow;
use syncwire::reader::Reader;

use crate::limits::{
    MAX_HEAD_META, MAX_REKEYS, MAX_STATE_FRAMES_PAGE, SPLIT_CHUNK_MAX, SPLIT_TRANSFER_CHUNK,
};
use crate::wire::{MailboxKind, push_bytes_u16};

/// Result status returned by `/op` and query endpoints.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpStatus {
    /// Operation verified and applied.
    Ok = 0,
    /// Calling device certificate must be staged/registered first.
    NeedCert = 1,
    /// Personal mailbox requires `AnchorPersonalRoot` before other mutations.
    NeedAnchor = 2,
    /// Verification or invariant rejected the operation.
    Rejected = 3,
}

impl TryFrom<u8> for OpStatus {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::NeedCert),
            2 => Ok(Self::NeedAnchor),
            3 => Ok(Self::Rejected),
            _ => Err(anyhow!("unknown OpStatus")),
        }
    }
}

/// Reply returned by `/op`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpReply {
    pub status: OpStatus,
    pub head_seq: u64,
    pub member_count: u32,
}

impl OpReply {
    /// Encode `OpReply` (17 bytes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.extend_from_slice(b"ZPOR");
        out.push(self.status as u8);
        out.extend_from_slice(&self.head_seq.to_be_bytes());
        out.extend_from_slice(&self.member_count.to_be_bytes());
        out
    }

    /// Decode `OpReply`.
    ///
    /// # Errors
    ///
    /// Malformed reply bytes.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPOR" {
            anyhow::bail!("invalid OpReply header");
        }
        let status = OpStatus::try_from(r.array::<1>()?[0])?;
        let head_seq = r.u64()?;
        let member_count = r.u32()?;
        r.finish()?;
        Ok(Self {
            status,
            head_seq,
            member_count,
        })
    }
}

/// Entry returned in [`MailboxSummary::frames`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameItem {
    /// Small frame delivered inline within `StateQuery`'s byte budget.
    Inline { seq: u64, envelope: Vec<u8> },
    /// Larger frame stored externally and downloaded via `/chunk` (`ChunkTarget::Frame`).
    External {
        seq: u64,
        chunk_id: [u8; 32],
        total_len: u32,
    },
}

/// Compact summary returned by `/state` (guaranteed `< 6.5 KiB` so `SplitHTTP`
/// stays cleanly below TSPU TCP caps).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxSummary {
    pub status: OpStatus,
    pub exists: bool,
    pub snap_id: Option<[u8; 32]>,
    pub snap_chunks: u32,
    pub snap_generation: u64,
    pub head_meta: Vec<u8>,
    pub head_seq: u64,
    pub frames: Vec<FrameItem>,
    pub has_more_frames: bool,
    pub rekeys: Vec<(u64, Vec<u8>)>,
    pub revocation_count: u32,
    pub member_count: u32,
    pub backup_id: Option<[u8; 32]>,
    pub backup_chunks: u32,
}

impl MailboxSummary {
    /// Encode summary to wire bytes.
    ///
    /// # Errors
    ///
    /// Field exceeds protocol bounds.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.head_meta.len() > MAX_HEAD_META
            || self.frames.len() > MAX_STATE_FRAMES_PAGE
            || self.rekeys.len() > MAX_REKEYS
        {
            anyhow::bail!("summary exceeds bounds");
        }
        let mut out = Vec::with_capacity(256 + self.head_meta.len());
        out.extend_from_slice(b"ZPSM");
        out.push(self.status as u8);
        out.push(u8::from(self.exists));
        push_opt_id(&mut out, self.snap_id);
        out.extend_from_slice(&self.snap_chunks.to_be_bytes());
        out.extend_from_slice(&self.snap_generation.to_be_bytes());
        push_bytes_u16(&mut out, &self.head_meta)?;
        out.extend_from_slice(&self.head_seq.to_be_bytes());
        out.push(u8::from(self.has_more_frames));
        out.extend_from_slice(&u16::try_from(self.frames.len())?.to_be_bytes());
        for item in &self.frames {
            match item {
                FrameItem::Inline { seq, envelope } => {
                    out.push(1);
                    out.extend_from_slice(&seq.to_be_bytes());
                    push_bytes_u16(&mut out, envelope)?;
                }
                FrameItem::External {
                    seq,
                    chunk_id,
                    total_len,
                } => {
                    out.push(2);
                    out.extend_from_slice(&seq.to_be_bytes());
                    out.extend_from_slice(chunk_id);
                    out.extend_from_slice(&total_len.to_be_bytes());
                }
            }
        }
        out.extend_from_slice(&u16::try_from(self.rekeys.len())?.to_be_bytes());
        for (key_gen, env) in &self.rekeys {
            out.extend_from_slice(&key_gen.to_be_bytes());
            push_bytes_u16(&mut out, env)?;
        }
        out.extend_from_slice(&self.revocation_count.to_be_bytes());
        out.extend_from_slice(&self.member_count.to_be_bytes());
        push_opt_id(&mut out, self.backup_id);
        out.extend_from_slice(&self.backup_chunks.to_be_bytes());
        Ok(out)
    }

    /// Decode summary.
    ///
    /// # Errors
    ///
    /// Malformed wire bytes or bound exceeded.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPSM" {
            anyhow::bail!("invalid MailboxSummary header");
        }
        let status = OpStatus::try_from(r.array::<1>()?[0])?;
        let exists = r.array::<1>()?[0] != 0;
        let snap_id = read_opt_id(&mut r)?;
        let snap_chunks = r.u32()?;
        let snap_generation = r.u64()?;
        let head_meta = r.bytes_u16(MAX_HEAD_META)?.to_vec();
        let head_seq = r.u64()?;
        let has_more_frames = r.array::<1>()?[0] != 0;
        let frames = read_frame_items(&mut r)?;
        let rekey_count = usize::from(r.u16()?);
        if rekey_count > MAX_REKEYS {
            anyhow::bail!("summary rekey count exceeded");
        }
        let mut rekeys = Vec::with_capacity(rekey_count);
        for _ in 0..rekey_count {
            let key_gen = r.u64()?;
            let env = r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec();
            rekeys.push((key_gen, env));
        }
        let revocation_count = r.u32()?;
        let member_count = r.u32()?;
        let backup_id = read_opt_id(&mut r)?;
        let backup_chunks = r.u32()?;
        r.finish()?;
        Ok(Self {
            status,
            exists,
            snap_id,
            snap_chunks,
            snap_generation,
            head_meta,
            head_seq,
            frames,
            has_more_frames,
            rekeys,
            revocation_count,
            member_count,
            backup_id,
            backup_chunks,
        })
    }
}

fn push_opt_id(out: &mut Vec<u8>, id: Option<[u8; 32]>) {
    if let Some(val) = id {
        out.push(1);
        out.extend_from_slice(&val);
    } else {
        out.push(0);
    }
}

fn read_opt_id(r: &mut Reader<'_>) -> anyhow::Result<Option<[u8; 32]>> {
    match r.array::<1>()?[0] {
        0 => Ok(None),
        1 => Ok(Some(r.array()?)),
        _ => Err(anyhow!("invalid optional id flag")),
    }
}

fn read_frame_items(r: &mut Reader<'_>) -> anyhow::Result<Vec<FrameItem>> {
    let frame_count = usize::from(r.u16()?);
    if frame_count > MAX_STATE_FRAMES_PAGE {
        anyhow::bail!("summary frame count exceeded");
    }
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        match r.array::<1>()?[0] {
            1 => frames.push(FrameItem::Inline {
                seq: r.u64()?,
                envelope: r.bytes_u16(SPLIT_CHUNK_MAX)?.to_vec(),
            }),
            2 => frames.push(FrameItem::External {
                seq: r.u64()?,
                chunk_id: r.array()?,
                total_len: r.u32()?,
            }),
            _ => anyhow::bail!("unknown frame item tag"),
        }
    }
    Ok(frames)
}

/// Reply returned by `/chunk`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkReply {
    pub status: OpStatus,
    pub total_len: u32,
    pub data: Vec<u8>,
}

impl ChunkReply {
    /// Encode chunk slice reply.
    ///
    /// # Errors
    ///
    /// Slice larger than `SPLIT_TRANSFER_CHUNK`.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.data.len() > SPLIT_TRANSFER_CHUNK {
            anyhow::bail!("chunk reply exceeds SPLIT_TRANSFER_CHUNK");
        }
        let mut out = Vec::with_capacity(11 + self.data.len());
        out.extend_from_slice(b"ZPCR");
        out.push(self.status as u8);
        out.extend_from_slice(&self.total_len.to_be_bytes());
        push_bytes_u16(&mut out, &self.data)?;
        Ok(out)
    }

    /// Decode chunk slice reply.
    ///
    /// # Errors
    ///
    /// Malformed header or oversized chunk.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPCR" {
            anyhow::bail!("invalid ChunkReply header");
        }
        let status = OpStatus::try_from(r.array::<1>()?[0])?;
        let total_len = r.u32()?;
        let data = r.bytes_u16(SPLIT_TRANSFER_CHUNK)?.to_vec();
        r.finish()?;
        Ok(Self {
            status,
            total_len,
            data,
        })
    }
}

/// Real-time notification streamed by the server over WSS `/ws`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushEvent {
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub head_seq: u64,
    pub member_count: u32,
    pub revocation_count: u32,
}

impl PushEvent {
    /// Encode notification frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(53);
        out.extend_from_slice(b"ZPPW");
        out.push(self.kind as u8);
        out.extend_from_slice(&self.box_id);
        out.extend_from_slice(&self.head_seq.to_be_bytes());
        out.extend_from_slice(&self.member_count.to_be_bytes());
        out.extend_from_slice(&self.revocation_count.to_be_bytes());
        out
    }

    /// Decode notification frame.
    ///
    /// # Errors
    ///
    /// Malformed push notification frame.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPPW" {
            anyhow::bail!("invalid PushEvent header");
        }
        let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
        let box_id = r.array()?;
        let head_seq = r.u64()?;
        let member_count = r.u32()?;
        let revocation_count = r.u32()?;
        r.finish()?;
        Ok(Self {
            box_id,
            kind,
            head_seq,
            member_count,
            revocation_count,
        })
    }
}
