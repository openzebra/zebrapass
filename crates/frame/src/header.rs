//! The 75-byte frame header codec and its associated data.
#![allow(
    clippy::indexing_slicing,
    reason = "wire offsets are const-asserted to fit HEADER_LEN"
)]

/// Frame header size in bytes.
pub const HEADER_LEN: usize = 75;

/// Associated-data domain appended to the header bytes.
pub const DOMAIN_FRAME: &[u8] = b"brby/v2/frame";

const OFF_KIND: usize = 0;
const OFF_RECORD_ID: usize = 1;
const OFF_REVISION: usize = 5;
const OFF_DEVICE: usize = 13;
const OFF_TIMESTAMP: usize = 29;

/// Byte offset of the algorithm field; used by tamper tests.
pub const OFF_ALG: usize = 37;
const OFF_NONCE: usize = 39;
const OFF_DOC_LEN: usize = 71;

const _: () = {
    assert!(OFF_KIND == 0);
    assert!(OFF_RECORD_ID == OFF_KIND + 1);
    assert!(OFF_REVISION == OFF_RECORD_ID + 4);
    assert!(OFF_DEVICE == OFF_REVISION + 8);
    assert!(OFF_TIMESTAMP == OFF_DEVICE + 16);
    assert!(OFF_ALG == OFF_TIMESTAMP + 8);
    assert!(OFF_NONCE == OFF_ALG + 2);
    assert!(OFF_DOC_LEN == OFF_NONCE + 32);
    assert!(HEADER_LEN == OFF_DOC_LEN + 4);
};

/// Everything a caller supplies to seal one frame (the nonce is drawn
/// inside [`crate::seal`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMeta {
    /// Frame kind: [`crate::KIND_REVISION`] or [`crate::KIND_TOMBSTONE`];
    /// other values are legal on the wire and preserved verbatim.
    pub kind: u8,
    /// Record this frame belongs to; `0` is vault metadata.
    pub record_id: u32,
    /// Monotonic per-record counter.
    pub revision: u64,
    /// Device that sealed the frame.
    pub origin_device: [u8; 16],
    /// Unix milliseconds; advisory, ordering uses `(revision, origin_device)`.
    pub timestamp_ms: u64,
    /// Frame algorithm id.
    pub alg: u16,
}

/// A parsed frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
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
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Plaintext length; `0` for a tombstone.
    pub doc_len: u32,
}

impl Header {
    /// The header fields without the nonce and length.
    #[must_use]
    pub const fn meta(&self) -> FrameMeta {
        FrameMeta {
            kind: self.kind,
            record_id: self.record_id,
            revision: self.revision,
            origin_device: self.origin_device,
            timestamp_ms: self.timestamp_ms,
            alg: self.alg,
        }
    }
}

/// Encode the header of one frame.
///
/// The result is little-endian: kind, record id, revision, origin device,
/// timestamp, algorithm, nonce, plaintext length.
#[must_use]
pub fn encode_header(meta: &FrameMeta, nonce: &[u8; 32], doc_len: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[OFF_KIND] = meta.kind;
    out[OFF_RECORD_ID..OFF_REVISION].copy_from_slice(&meta.record_id.to_le_bytes());
    out[OFF_REVISION..OFF_DEVICE].copy_from_slice(&meta.revision.to_le_bytes());
    out[OFF_DEVICE..OFF_TIMESTAMP].copy_from_slice(&meta.origin_device);
    out[OFF_TIMESTAMP..OFF_ALG].copy_from_slice(&meta.timestamp_ms.to_le_bytes());
    out[OFF_ALG..OFF_NONCE].copy_from_slice(&meta.alg.to_le_bytes());
    out[OFF_NONCE..OFF_DOC_LEN].copy_from_slice(nonce);
    out[OFF_DOC_LEN..HEADER_LEN].copy_from_slice(&doc_len.to_le_bytes());
    out
}

/// Associated data for the frame AEAD: the header bytes followed by the
/// domain separator. Every header byte is authenticated.
#[must_use]
pub fn aad(header_bytes: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(HEADER_LEN + DOMAIN_FRAME.len());
    ad.extend_from_slice(header_bytes);
    ad.extend_from_slice(DOMAIN_FRAME);
    ad
}

/// Parse the header at the front of `bytes`.
///
/// # Errors
///
/// `corrupted length` when `bytes` is shorter than a header.
pub fn parse(bytes: &[u8]) -> anyhow::Result<Header> {
    if bytes.len() < HEADER_LEN {
        anyhow::bail!("corrupted length");
    }
    let read = |range: std::ops::Range<usize>| -> anyhow::Result<&[u8]> {
        bytes
            .get(range)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))
    };
    let mut four = [0u8; 4];
    four.copy_from_slice(read(OFF_RECORD_ID..OFF_REVISION)?);
    let record_id = u32::from_le_bytes(four);
    let mut eight = [0u8; 8];
    eight.copy_from_slice(read(OFF_REVISION..OFF_DEVICE)?);
    let revision = u64::from_le_bytes(eight);
    let mut device = [0u8; 16];
    device.copy_from_slice(read(OFF_DEVICE..OFF_TIMESTAMP)?);
    eight.copy_from_slice(read(OFF_TIMESTAMP..OFF_ALG)?);
    let timestamp_ms = u64::from_le_bytes(eight);
    let mut two = [0u8; 2];
    two.copy_from_slice(read(OFF_ALG..OFF_NONCE)?);
    let alg = u16::from_le_bytes(two);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(read(OFF_NONCE..OFF_DOC_LEN)?);
    four.copy_from_slice(read(OFF_DOC_LEN..HEADER_LEN)?);
    let doc_len = u32::from_le_bytes(four);
    Ok(Header {
        kind: bytes
            .get(OFF_KIND)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?,
        record_id,
        revision,
        origin_device: device,
        timestamp_ms,
        alg,
        nonce,
        doc_len,
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

    use super::{aad, encode_header, parse, FrameMeta, HEADER_LEN};
    use crate::{ALG_AEGIS256, KIND_REVISION};

    fn sample_meta() -> FrameMeta {
        FrameMeta {
            kind: KIND_REVISION,
            record_id: 7,
            revision: 42,
            origin_device: [3; 16],
            timestamp_ms: 1_700_000_000_000,
            alg: ALG_AEGIS256,
        }
    }

    #[test]
    fn header_round_trips() {
        let nonce = [5u8; 32];
        let bytes = encode_header(&sample_meta(), &nonce, 12);
        assert_eq!(bytes.len(), HEADER_LEN);
        let header = parse(&bytes).unwrap();
        assert_eq!(header.meta(), sample_meta());
        assert_eq!(header.nonce, nonce);
        assert_eq!(header.doc_len, 12);
    }

    #[test]
    fn short_input_rejected() {
        let bytes = encode_header(&sample_meta(), &[5u8; 32], 0);
        assert!(parse(&bytes[..HEADER_LEN - 1]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn aad_binds_header_and_domain() {
        let bytes = encode_header(&sample_meta(), &[5u8; 32], 0);
        let ad = aad(&bytes);
        assert_eq!(ad.len(), HEADER_LEN + crate::DOMAIN_FRAME.len());
        assert!(ad.ends_with(crate::DOMAIN_FRAME));
        assert_eq!(&ad[..HEADER_LEN], &bytes);
    }

    #[test]
    fn meta_strips_nonce_and_len() {
        let header = parse(&encode_header(&sample_meta(), &[1u8; 32], 5)).unwrap();
        // The projection must not carry the nonce or the length.
        assert_eq!(header.meta(), sample_meta());
    }
}
