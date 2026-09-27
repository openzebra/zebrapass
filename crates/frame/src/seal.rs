//! Frame sealing and opening with AEGIS-256.

use ::aegis::aegis256::Aegis256;
use secret::Secret;

use crate::header::{aad, encode_header, parse, FrameMeta, HEADER_LEN};
use crate::limits::MAX_FRAME_PLAINTEXT;
use crate::{ALG_AEGIS256, TAG_LEN};

/// Seal one frame: header, then AEGIS-256 ciphertext and a 32-byte tag.
///
/// The nonce is drawn from the OS RNG for every seal. The associated data
/// is the header bytes and the frame domain, so every header field is
/// authenticated.
///
/// # Errors
///
/// `frame too large` when `plaintext` exceeds [`MAX_FRAME_PLAINTEXT`];
/// `os entropy failed` when the OS RNG fails.
pub fn seal(key: &Secret<[u8; 32]>, meta: &FrameMeta, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > MAX_FRAME_PLAINTEXT {
        anyhow::bail!("frame too large");
    }
    let doc_len = u32::try_from(plaintext.len()).map_err(|_| anyhow::anyhow!("frame too large"))?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let header_bytes = encode_header(meta, &nonce, doc_len);
    let ad = aad(&header_bytes);
    let (ct, tag) = Aegis256::<32>::new(key.expose(), &nonce).encrypt(plaintext, &ad);
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len() + TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Open one frame.
///
/// # Errors
///
/// `corrupted length` when the bytes are shorter than a header or the
/// trailing ciphertext and tag do not match the header length;
/// `unsupported frame algorithm` for an algorithm this build cannot open;
/// `frame authentication failed` when the AEGIS-256 tag does not match,
/// including when any header byte was modified.
pub fn open(key: &Secret<[u8; 32]>, frame_bytes: &[u8]) -> anyhow::Result<Secret<Vec<u8>>> {
    let header = parse(frame_bytes)?;
    let body = frame_bytes
        .get(HEADER_LEN..)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let doc_len =
        usize::try_from(header.doc_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    let expected = doc_len
        .checked_add(TAG_LEN)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    if body.len() != expected {
        anyhow::bail!("corrupted length");
    }
    if header.alg != ALG_AEGIS256 {
        anyhow::bail!("unsupported frame algorithm {:#06x}", header.alg);
    }
    let ct = body
        .get(..doc_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let tag: [u8; TAG_LEN] = body
        .get(doc_len..)
        .and_then(|tail| tail.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let ad = aad(&encode_header(&header.meta(), &header.nonce, header.doc_len));
    // Decrypt reports every failure, including a bad tag, as one error.
    Aegis256::<32>::new(key.expose(), &header.nonce)
        .decrypt(ct, &tag, &ad)
        .map(Secret::new)
        .map_err(|_| anyhow::anyhow!("frame authentication failed"))
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
    use crate::{open, seal, ALG_AEGIS256, KIND_REVISION, KIND_TOMBSTONE};

    fn key() -> Secret<[u8; 32]> {
        frame_key(&[9u8; 32], &[7u8; 16], 3).unwrap()
    }

    fn meta(kind: u8) -> FrameMeta {
        FrameMeta {
            kind,
            record_id: 3,
            revision: 8,
            origin_device: [2; 16],
            timestamp_ms: 1_700_000_000_000,
            alg: ALG_AEGIS256,
        }
    }

    #[test]
    fn round_trip() {
        let pt = b"hello frame";
        let sealed = seal(&key(), &meta(KIND_REVISION), pt).unwrap();
        let opened = open(&key(), &sealed).unwrap();
        assert_eq!(opened.expose().as_slice(), pt);
    }

    #[test]
    fn tombstone_has_empty_plaintext() {
        let sealed = seal(&key(), &meta(KIND_TOMBSTONE), &[]).unwrap();
        let opened = open(&key(), &sealed).unwrap();
        assert!(opened.expose().is_empty());
        assert_eq!(sealed.len(), crate::HEADER_LEN + crate::TAG_LEN);
    }

    #[test]
    fn wrong_key_rejected() {
        let sealed = seal(&key(), &meta(KIND_REVISION), b"secret").unwrap();
        let other = frame_key(&[9u8; 32], &[7u8; 16], 4).unwrap();
        let err = open(&other, &sealed).unwrap_err();
        assert_eq!(err.to_string(), "frame authentication failed");
    }

    #[test]
    fn flipped_header_byte_rejected() {
        let sealed = seal(&key(), &meta(KIND_REVISION), b"secret").unwrap();
        // Flip every header byte except the algorithm: an unknown algorithm
        // is rejected as unsupported before the tag check.
        for idx in 0..crate::header::HEADER_LEN {
            if idx == crate::header::OFF_ALG || idx == crate::header::OFF_ALG + 1 {
                continue;
            }
            let mut bytes = sealed.clone();
            *bytes.get_mut(idx).unwrap() ^= 0x01;
            assert!(open(&key(), &bytes).is_err(), "flipped header byte {idx} accepted");
        }
        // The algorithm bytes are bound through the AAD the same way; they
        // fail with their own stable error.
        let mut bytes = sealed;
        *bytes.get_mut(crate::header::OFF_ALG).unwrap() = 0xA2;
        let err = open(&key(), &bytes).unwrap_err();
        assert_eq!(err.to_string(), "unsupported frame algorithm 0xa0a2");
    }

    #[test]
    fn flipped_ciphertext_and_tag_rejected() {
        let sealed = seal(&key(), &meta(KIND_REVISION), b"secret").unwrap();
        let mut bytes = sealed.clone();
        let mid = bytes.len() / 2;
        *bytes.get_mut(mid).unwrap() ^= 0x01;
        assert_eq!(open(&key(), &bytes).unwrap_err().to_string(), "frame authentication failed");
        let mut bytes = sealed;
        let last = bytes.len() - 1;
        *bytes.get_mut(last).unwrap() ^= 0x01;
        assert_eq!(open(&key(), &bytes).unwrap_err().to_string(), "frame authentication failed");
    }

    #[test]
    fn truncated_and_extended_rejected() {
        let sealed = seal(&key(), &meta(KIND_REVISION), b"secret").unwrap();
        let short = sealed
            .get(..sealed.len() - 1)
            .expect("one byte less than the frame");
        assert_eq!(open(&key(), short).unwrap_err().to_string(), "corrupted length");
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(open(&key(), &long).unwrap_err().to_string(), "corrupted length");
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let blob = vec![0u8; crate::limits::MAX_FRAME_PLAINTEXT + 1];
        assert_eq!(seal(&key(), &meta(KIND_REVISION), &blob).unwrap_err().to_string(), "frame too large");
    }
}
