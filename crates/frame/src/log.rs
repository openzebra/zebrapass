//! Length-delimited frame body.
//!
//! A frames body is not an AEAD. Each sealed frame is prefixed with its
//! length so one record can be copied without re-sealing the others.

use crate::header::HEADER_LEN;
use crate::limits::MAX_FRAME_PLAINTEXT;
use crate::TAG_LEN;

const LEN_LEN: usize = 4;

/// Upper bound on one sealed frame: header plus maximum plaintext plus tag.
const MAX_SEALED_FRAME: usize = HEADER_LEN + MAX_FRAME_PLAINTEXT + TAG_LEN;

/// Encode a concatenation of sealed frames as `u32le length || frame`.
///
/// # Errors
///
/// `corrupted length` when a frame is shorter than a header plus tag, or
/// longer than [`MAX_SEALED_FRAME`].
pub fn encode_frames(records: &[u8]) -> anyhow::Result<Vec<u8>> {
    let spans = spans(records)?;
    let mut out = Vec::with_capacity(records.len().saturating_add(spans.len().saturating_mul(LEN_LEN)));
    for (start, len) in spans {
        let frame = records
            .get(start..start + len)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let n = u32::try_from(len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(frame);
    }
    Ok(out)
}

/// Strip length prefixes and return the concatenated sealed frames.
///
/// # Errors
///
/// `corrupted length` when a prefix is truncated, a frame is outside the
/// header-plus-tag and [`MAX_SEALED_FRAME`] bounds, or the body ends mid-frame.
pub fn decode_frames(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    while pos < body.len() {
        let len_bytes = body
            .get(pos..pos + LEN_LEN)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let mut four = [0u8; LEN_LEN];
        four.copy_from_slice(len_bytes);
        let len = usize::try_from(u32::from_le_bytes(four))
            .map_err(|_| anyhow::anyhow!("corrupted length"))?;
        if !(HEADER_LEN + TAG_LEN..=MAX_SEALED_FRAME).contains(&len) {
            anyhow::bail!("corrupted length");
        }
        let start = pos
            .checked_add(LEN_LEN)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let frame = body
            .get(start..end)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        out.extend_from_slice(frame);
        pos = end;
    }
    Ok(out)
}

fn spans(records: &[u8]) -> anyhow::Result<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < records.len() {
        let rest = records
            .get(pos..)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let header = crate::header::parse(rest)?;
        let doc_len =
            usize::try_from(header.doc_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
        let total = HEADER_LEN
            .checked_add(doc_len)
            .and_then(|sum| sum.checked_add(TAG_LEN))
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        if total > MAX_SEALED_FRAME {
            anyhow::bail!("corrupted length");
        }
        let end = pos
            .checked_add(total)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        if end > records.len() {
            anyhow::bail!("corrupted length");
        }
        out.push((pos, total));
        pos = end;
    }
    Ok(out)
}
