//! Byte-range index over a frame body.
//!
//! The index records the wire shape of every frame without interpreting
//! it: unknown kinds and algorithms get a range exactly like known ones,
//! so a rewrite can copy them byte for byte.

use crate::header::{parse, HEADER_LEN};
use crate::{KIND_REVISION, KIND_TOMBSTONE, TAG_LEN};

/// One frame located in the body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRef {
    /// Byte offset of the frame start.
    pub start: usize,
    /// Total frame length: header, ciphertext, tag.
    pub len: usize,
    /// Frame kind.
    pub kind: u8,
    /// Record id.
    pub record_id: u32,
    /// Revision counter.
    pub revision: u64,
    /// Origin device.
    pub origin_device: [u8; 16],
    /// Advisory unix milliseconds.
    pub timestamp_ms: u64,
    /// Frame algorithm id.
    pub alg: u16,
    /// Plaintext length from the header.
    pub doc_len: u32,
}

impl FrameRef {
    /// `true` for a revision frame.
    #[must_use]
    pub const fn is_revision(self) -> bool {
        self.kind == KIND_REVISION
    }

    /// `true` for a tombstone frame.
    #[must_use]
    pub const fn is_tombstone(self) -> bool {
        self.kind == KIND_TOMBSTONE
    }

    /// `true` for a kind this build interprets.
    #[must_use]
    pub const fn known(self) -> bool {
        self.is_revision() || self.is_tombstone()
    }
}

/// Walk the body frame by frame.
///
/// An empty body is a valid, empty index.
///
/// # Errors
///
/// `corrupted length` when a frame header is truncated or a frame runs
/// past the end of the body.
pub fn parse_index(body: &[u8]) -> anyhow::Result<Vec<FrameRef>> {
    let mut refs = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let rest = body
            .get(pos..)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let header = parse(rest)?;
        let doc_len =
            usize::try_from(header.doc_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
        let total = HEADER_LEN
            .checked_add(doc_len)
            .and_then(|sum| sum.checked_add(TAG_LEN))
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let end = pos
            .checked_add(total)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        if end > body.len() {
            anyhow::bail!("corrupted length");
        }
        refs.push(FrameRef {
            start: pos,
            len: total,
            kind: header.kind,
            record_id: header.record_id,
            revision: header.revision,
            origin_device: header.origin_device,
            timestamp_ms: header.timestamp_ms,
            alg: header.alg,
            doc_len: header.doc_len,
        });
        pos = end;
    }
    Ok(refs)
}

/// Borrow the frame bytes of `reference` from `body`.
///
/// # Errors
///
/// `corrupted length` when the reference does not fit `body`.
#[allow(
    clippy::elidable_lifetime_names,
    reason = "the output borrows `body`; full elision would be ambiguous"
)]
pub fn frame_at<'a>(body: &'a [u8], reference: &FrameRef) -> anyhow::Result<&'a [u8]> {
    let end = reference
        .start
        .checked_add(reference.len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    body.get(reference.start..end)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))
}

/// The winning frame of `record_id`: the highest `(revision, origin_device)`
/// in lexicographic order. Deterministic under clock skew; the timestamp is
/// advisory.
#[must_use]
pub fn latest(frames: &[FrameRef], record_id: u32) -> Option<&FrameRef> {
    frames
        .iter()
        .filter(|frame| frame.record_id == record_id)
        .max_by(|a, b| {
            (a.revision, a.origin_device).cmp(&(b.revision, b.origin_device))
        })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "tests may unwrap, index, and panic"
    )]

    use kdf::frame_key;
    use secret::Secret;

    use crate::header::FrameMeta;
    use crate::{seal, ALG_AEGIS256, KIND_REVISION, KIND_TOMBSTONE};

    use super::{frame_at, latest, parse_index};

    fn key(record: u32) -> Secret<[u8; 32]> {
        frame_key(&[9u8; 32], &[7u8; 16], record).unwrap()
    }

    fn meta(record: u32, revision: u64, kind: u8) -> FrameMeta {
        FrameMeta {
            kind,
            record_id: record,
            revision,
            origin_device: [1; 16],
            timestamp_ms: 1,
            alg: ALG_AEGIS256,
        }
    }

    #[test]
    fn empty_body_is_an_empty_index() {
        assert!(parse_index(&[]).unwrap().is_empty());
    }

    #[test]
    fn index_round_trips_frames() {
        let mut body = Vec::new();
        body.extend_from_slice(&seal(&key(1), &meta(1, 1, KIND_REVISION), b"one").unwrap());
        body.extend_from_slice(&seal(&key(1), &meta(1, 2, KIND_REVISION), b"two").unwrap());
        body.extend_from_slice(&seal(&key(2), &meta(2, 1, KIND_TOMBSTONE), &[]).unwrap());
        let refs = parse_index(&body).unwrap();
        assert_eq!(refs.len(), 3);
        assert!(refs[0].is_revision());
        assert_eq!(refs[0].record_id, 1);
        assert_eq!(refs[1].revision, 2);
        assert!(refs[2].is_tombstone());
        // Every range carves out exactly the sealed bytes.
        for reference in &refs {
            assert_eq!(frame_at(&body, reference).unwrap().len(), reference.len);
        }
        assert_eq!(frame_at(&body, &refs[0]).unwrap(), &body[..refs[0].len]);
    }

    #[test]
    fn truncated_and_extended_bodies_rejected() {
        let frame = seal(&key(1), &meta(1, 1, KIND_REVISION), b"data").unwrap();
        // Cut into the frame: header intact, but the body runs past the end.
        let short = frame.get(..frame.len() - 1).expect("one byte less");
        assert_eq!(parse_index(short).unwrap_err().to_string(), "corrupted length");
        // Trailing bytes that cannot be a header.
        let mut extended = short.to_vec();
        extended.extend_from_slice(&[0u8; 10]);
        assert_eq!(parse_index(&extended).unwrap_err().to_string(), "corrupted length");
        // A header-sized prefix with a length that overruns the body.
        let mut overrun = short.to_vec();
        overrun.extend_from_slice(&[0xFF; 75]);
        assert_eq!(parse_index(&overrun).unwrap_err().to_string(), "corrupted length");
    }

    #[test]
    fn unknown_frames_are_indexed_and_preserved() {
        let mut body = Vec::new();
        body.extend_from_slice(&seal(&key(1), &meta(1, 1, KIND_REVISION), b"one").unwrap());
        // An unknown kind with an unknown algorithm and a plausible payload.
        let unknown_start = body.len();
        let unknown = {
            let mut frame = Vec::new();
            frame.push(0x7F); // kind
            frame.extend_from_slice(&5u32.to_le_bytes()); // record_id
            frame.extend_from_slice(&9u64.to_le_bytes()); // revision
            frame.extend_from_slice(&[4u8; 16]); // origin device
            frame.extend_from_slice(&0u64.to_le_bytes()); // timestamp
            frame.extend_from_slice(&0xBEEFu16.to_le_bytes()); // alg
            frame.extend_from_slice(&[6u8; 32]); // nonce
            frame.extend_from_slice(&3u32.to_le_bytes()); // doc_len
            frame.extend_from_slice(b"abc"); // ciphertext
            frame.extend_from_slice(&[7u8; 32]); // tag
            frame
        };
        body.extend_from_slice(&unknown);
        let refs = parse_index(&body).unwrap();
        assert_eq!(refs.len(), 2);
        let last = refs[1];
        assert!(!last.known());
        assert_eq!(last.alg, 0xBEEF);
        assert_eq!(last.record_id, 5);
        assert_eq!(frame_at(&body, &last).unwrap(), unknown.as_slice());
        assert_eq!(last.start, unknown_start);
        // A rewrite that copies both ranges reproduces the body exactly.
        let mut rewritten = Vec::new();
        for reference in &refs {
            rewritten.extend_from_slice(frame_at(&body, reference).unwrap());
        }
        assert_eq!(rewritten, body);
    }

    #[test]
    fn latest_prefers_revision_then_device() {
        let mut body = Vec::new();
        // record 1: revisions 1, 2 and a tombstone with revision 3.
        body.extend_from_slice(&seal(&key(1), &meta(1, 1, KIND_REVISION), b"a").unwrap());
        body.extend_from_slice(&seal(&key(1), &meta(1, 2, KIND_REVISION), b"b").unwrap());
        body.extend_from_slice(&seal(&key(1), &meta(1, 3, KIND_TOMBSTONE), &[]).unwrap());
        // record 2: two frames with the same revision from different devices.
        let mut tie = meta(2, 7, KIND_REVISION);
        tie.origin_device = [9; 16];
        body.extend_from_slice(&seal(&key(2), &tie, b"t2").unwrap());
        let mut tie_high = tie;
        tie_high.origin_device = [10; 16];
        body.extend_from_slice(&seal(&key(2), &tie_high, b"t2").unwrap());

        let refs = parse_index(&body).unwrap();
        let winner1 = latest(&refs, 1).unwrap();
        assert!(winner1.is_tombstone());
        assert_eq!(winner1.revision, 3);
        let winner2 = latest(&refs, 2).unwrap();
        assert_eq!(winner2.origin_device, [10; 16]);
        assert!(latest(&refs, 3).is_none());
    }
}
