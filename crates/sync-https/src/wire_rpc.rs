//! Signed RPC request codecs (`SignedOp`, `StateQuery`, `ChunkQuery`, `SignedSub`).

use pq::SYNC_SIG_LEN;
use syncwire::reader::Reader;

use crate::limits::{MAX_HTTP_BODY, MAX_SUB_BOXES, SPLIT_TRANSFER_CHUNK};
use crate::wire::{ChunkTarget, MailboxKind, OpPayload, push_bytes_u16};
pub use crate::wire_reply::{ChunkReply, FrameItem, MailboxSummary, OpReply, OpStatus, PushEvent};

/// Signed write / mutation request sent via `SplitHTTP` `/op` or WSS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedOp {
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub device_id: [u8; 16],
    pub timestamp_secs: u64,
    pub nonce: [u8; 16],
    pub payload_bytes: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SignedOp {
    /// Encode signed operation to wire bytes.
    ///
    /// # Errors
    ///
    /// Invalid signature length or oversized payload.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.sig.len() != SYNC_SIG_LEN {
            anyhow::bail!("invalid operation signature length");
        }
        if self.payload_bytes.len() > MAX_HTTP_BODY {
            anyhow::bail!("operation payload exceeds limit");
        }
        let mut out = Vec::with_capacity(72 + self.payload_bytes.len() + SYNC_SIG_LEN);
        out.extend_from_slice(b"ZPSO");
        out.push(1);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.box_id);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        push_bytes_u16(&mut out, &self.payload_bytes)?;
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    /// Decode signed operation without verifying signature.
    ///
    /// # Errors
    ///
    /// Malformed wire header, unknown mailbox kind, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPSO" || r.array::<1>()?[0] != 1 {
            anyhow::bail!("unsupported signed operation header");
        }
        let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
        let box_id = r.array()?;
        let device_id = r.array()?;
        let timestamp_secs = r.u64()?;
        let nonce = r.array()?;
        let payload_bytes = r.bytes_u16(MAX_HTTP_BODY)?.to_vec();
        let _ = OpPayload::decode(&payload_bytes)?;
        let sig = r.take(SYNC_SIG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            box_id,
            kind,
            device_id,
            timestamp_secs,
            nonce,
            payload_bytes,
            sig,
        })
    }
}

/// Signed mailbox summary query sent to `/state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateQuery {
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub device_id: [u8; 16],
    pub timestamp_secs: u64,
    pub nonce: [u8; 16],
    pub since_seq: u64,
    pub since_member_seq: u64,
    pub sig: Vec<u8>,
}

impl StateQuery {
    /// Encode signed state query.
    ///
    /// # Errors
    ///
    /// Signature length is not `SYNC_SIG_LEN`.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.sig.len() != SYNC_SIG_LEN {
            anyhow::bail!("invalid state query signature length");
        }
        let mut out = Vec::with_capacity(90 + SYNC_SIG_LEN);
        out.extend_from_slice(b"ZPSS");
        out.push(1);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.box_id);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.since_seq.to_be_bytes());
        out.extend_from_slice(&self.since_member_seq.to_be_bytes());
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    /// Decode state query.
    ///
    /// # Errors
    ///
    /// Malformed header or trailing bytes.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPSS" || r.array::<1>()?[0] != 1 {
            anyhow::bail!("unsupported state query");
        }
        let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
        let box_id = r.array()?;
        let device_id = r.array()?;
        let timestamp_secs = r.u64()?;
        let nonce = r.array()?;
        let since_seq = r.u64()?;
        let since_member_seq = r.u64()?;
        let sig = r.take(SYNC_SIG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            box_id,
            kind,
            device_id,
            timestamp_secs,
            nonce,
            since_seq,
            since_member_seq,
            sig,
        })
    }
}

/// Signed bounded slice download request sent to `/chunk`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkQuery {
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub device_id: [u8; 16],
    pub timestamp_secs: u64,
    pub nonce: [u8; 16],
    pub target: ChunkTarget,
    pub object_id: [u8; 32],
    pub index: u32,
    pub offset: u32,
    pub max_len: u32,
    pub sig: Vec<u8>,
}

impl ChunkQuery {
    /// Encode chunk query.
    ///
    /// # Errors
    ///
    /// Signature length mismatch or requested slice over `SPLIT_TRANSFER_CHUNK`.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.sig.len() != SYNC_SIG_LEN {
            anyhow::bail!("invalid chunk query signature length");
        }
        let max_u32 = u32::try_from(SPLIT_TRANSFER_CHUNK).unwrap_or(6_144);
        if self.max_len == 0 || self.max_len > max_u32 {
            anyhow::bail!("chunk max_len out of bounds");
        }
        let mut out = Vec::with_capacity(120 + SYNC_SIG_LEN);
        out.extend_from_slice(b"ZPSC");
        out.push(1);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.box_id);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.push(self.target as u8);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.max_len.to_be_bytes());
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    /// Decode chunk query.
    ///
    /// # Errors
    ///
    /// Malformed header or slice bound exceeded.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPSC" || r.array::<1>()?[0] != 1 {
            anyhow::bail!("unsupported chunk query");
        }
        let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
        let box_id = r.array()?;
        let device_id = r.array()?;
        let timestamp_secs = r.u64()?;
        let nonce = r.array()?;
        let target = ChunkTarget::try_from(r.array::<1>()?[0])?;
        let object_id = r.array()?;
        let index = r.u32()?;
        let offset = r.u32()?;
        let max_len = r.u32()?;
        let max_u32 = u32::try_from(SPLIT_TRANSFER_CHUNK).unwrap_or(6_144);
        if max_len == 0 || max_len > max_u32 {
            anyhow::bail!("chunk max_len out of bounds");
        }
        let sig = r.take(SYNC_SIG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
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
            sig,
        })
    }
}

/// Signed WebSocket subscription request (`GET /<slug>/v1/ws` first binary frame).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSub {
    pub device_id: [u8; 16],
    pub timestamp_secs: u64,
    pub nonce: [u8; 16],
    pub boxes: Vec<(MailboxKind, [u8; 32])>,
    pub sig: Vec<u8>,
}

impl SignedSub {
    /// Encode WebSocket subscription message.
    ///
    /// # Errors
    ///
    /// Empty or oversized box list or invalid signature length.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.boxes.is_empty() || self.boxes.len() > MAX_SUB_BOXES {
            anyhow::bail!("subscription box count out of bounds");
        }
        if self.sig.len() != SYNC_SIG_LEN {
            anyhow::bail!("invalid subscription signature length");
        }
        let count_u16 =
            u16::try_from(self.boxes.len()).map_err(|_| anyhow::anyhow!("sub overflow"))?;
        let mut out = Vec::with_capacity(48 + self.boxes.len() * 33 + SYNC_SIG_LEN);
        out.extend_from_slice(b"ZPSB");
        out.push(1);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&count_u16.to_be_bytes());
        for (kind, box_id) in &self.boxes {
            out.push(*kind as u8);
            out.extend_from_slice(box_id);
        }
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    /// Decode WebSocket subscription message.
    ///
    /// # Errors
    ///
    /// Malformed header or bound violation.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *b"ZPSB" || r.array::<1>()?[0] != 1 {
            anyhow::bail!("unsupported subscription header");
        }
        let device_id = r.array()?;
        let timestamp_secs = r.u64()?;
        let nonce = r.array()?;
        let count = usize::from(r.u16()?);
        if count == 0 || count > MAX_SUB_BOXES {
            anyhow::bail!("subscription count out of bounds");
        }
        let mut boxes = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = MailboxKind::try_from(r.array::<1>()?[0])?;
            let box_id = r.array()?;
            boxes.push((kind, box_id));
        }
        let sig = r.take(SYNC_SIG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            device_id,
            timestamp_secs,
            nonce,
            boxes,
            sig,
        })
    }
}
