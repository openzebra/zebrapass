//! The signed peer addresses of a shared vault, kept across restarts.
//!
//! Records are hints, not authority: a device that loads them checks each
//! again (member, signature, age, address) before it dials one, so a missing
//! or unreadable file only means the search starts again from the invitation.
//! One sealed frame per record, under a key from the shared seed.

use std::path::Path;

use frame::{
    decode_frames, encode_frames, open, parse, seal, spans, FrameMeta, ALG_CASCADE, KIND_REVISION,
};
use secret::Secret;
use session::PeerRecord;
use syncwire::{decode_peers, encode_peers};

use crate::limits::SHARED_PEERS_MAX;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// Write `records`, newest first and at most [`SHARED_PEERS_MAX`] of them.
///
/// # Errors
///
/// Encoding, sealing or write failure.
pub fn save_peers(
    path: &Path,
    key: &Secret<[u8; 32]>,
    records: &[PeerRecord],
) -> anyhow::Result<()> {
    let mut newest: Vec<&PeerRecord> = records.iter().collect();
    newest.sort_by_key(|record| std::cmp::Reverse(record.issued_ms));
    let mut frames = Vec::new();
    for (index, record) in newest.into_iter().take(SHARED_PEERS_MAX).enumerate() {
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: u32::try_from(index)?,
            revision: 1,
            origin_device: record.signer.device_id,
            timestamp_ms: record.issued_ms,
            alg: ALG_CASCADE,
        };
        let one = encode_peers(std::slice::from_ref(record))?;
        frames.extend_from_slice(&seal(key, &meta, &one)?);
    }
    crate::write_atomic(path, &encode_frames(&frames)?)
}

/// Read the stored records, unverified: the caller checks each one.
///
/// # Errors
///
/// `peer store unreadable` when the file cannot be read; frame
/// authentication failure; a frame out of place or over the bound.
pub fn load_peers(path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<Vec<PeerRecord>> {
    let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("peer store unreadable"))?;
    let frames = decode_frames(&bytes)?;
    let spans = spans(&frames)?;
    if spans.len() > SHARED_PEERS_MAX {
        return Err(corrupted());
    }
    let mut records = Vec::with_capacity(spans.len());
    for (index, (start, len)) in spans.into_iter().enumerate() {
        let frame = frames.get(start..start + len).ok_or_else(corrupted)?;
        if u64::from(parse(frame)?.record_id) != u64::try_from(index)? {
            return Err(corrupted());
        }
        let mut one = decode_peers(open(key, frame)?.expose())?;
        if one.len() != 1 {
            return Err(corrupted());
        }
        records.extend(one.pop());
    }
    Ok(records)
}
