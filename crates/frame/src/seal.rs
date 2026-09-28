//! Frame sealing and opening: the AEGIS-256 + Kuznyechik cascade, and
//! legacy AEGIS-256-only frames.

use ::aegis::aegis256::Aegis256;
use secret::Secret;

use crate::cascade::{self, CASCADE_OVERHEAD};
use crate::header::{aad, encode_header, parse, FrameMeta, HEADER_LEN};
use crate::limits::MAX_FRAME_PLAINTEXT;
use crate::{ALG_AEGIS256, ALG_CASCADE, TAG_LEN};

/// Seal one frame under the algorithm `meta.alg` names.
///
/// The AEGIS nonce is drawn from the OS RNG for every seal. The associated
/// data is the header bytes and the frame domain, so every header field is
/// authenticated by every layer.
///
/// # Errors
///
/// `frame too large` when `plaintext` exceeds [`MAX_FRAME_PLAINTEXT`];
/// `unsupported frame algorithm` for any algorithm but [`ALG_CASCADE`] and
/// [`ALG_AEGIS256`]; `os entropy failed` when the OS RNG fails.
pub fn seal(key: &Secret<[u8; 32]>, meta: &FrameMeta, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > MAX_FRAME_PLAINTEXT {
        anyhow::bail!("frame too large");
    }
    let payload_len = match meta.alg {
        ALG_CASCADE => plaintext.len() + CASCADE_OVERHEAD,
        ALG_AEGIS256 => plaintext.len(),
        other => anyhow::bail!("unsupported frame algorithm {other:#06x}"),
    };
    let doc_len = u32::try_from(payload_len).map_err(|_| anyhow::anyhow!("frame too large"))?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let header_bytes = encode_header(meta, &nonce, doc_len);
    let ad = aad(&header_bytes);
    let mut out = Vec::with_capacity(HEADER_LEN + payload_len + TAG_LEN);
    out.extend_from_slice(&header_bytes);
    if meta.alg == ALG_CASCADE {
        out.extend_from_slice(&cascade::seal(key, &nonce, &ad, plaintext)?);
    } else {
        let (ct, tag) = Aegis256::<32>::new(key.expose(), &nonce).encrypt(plaintext, &ad);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
    }
    Ok(out)
}

/// Open one frame.
///
/// # Errors
///
/// `corrupted length` when the bytes are shorter than a header or the
/// trailing payload and tag do not match the header length;
/// `unsupported frame algorithm` for an algorithm this build cannot open;
/// `frame authentication failed` when any layer's tag does not match,
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
    let ad = aad(&encode_header(
        &header.meta(),
        &header.nonce,
        header.doc_len,
    ));
    match header.alg {
        ALG_CASCADE => cascade::open(key, &header.nonce, &ad, body),
        ALG_AEGIS256 => open_aegis(key, &header.nonce, &ad, body, doc_len),
        other => anyhow::bail!("unsupported frame algorithm {other:#06x}"),
    }
}

fn open_aegis(
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 32],
    ad: &[u8],
    body: &[u8],
    doc_len: usize,
) -> anyhow::Result<Secret<Vec<u8>>> {
    let ct = body
        .get(..doc_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let tag: [u8; TAG_LEN] = body
        .get(doc_len..)
        .and_then(|tail| tail.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    // Decrypt reports every failure, including a bad tag, as one error.
    Aegis256::<32>::new(key.expose(), nonce)
        .decrypt(ct, &tag, ad)
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
    use crate::{
        open, seal, ALG_AEGIS256, ALG_CASCADE, CASCADE_OVERHEAD, KIND_REVISION, KIND_TOMBSTONE,
    };

    fn key() -> Secret<[u8; 32]> {
        frame_key(&[9u8; 32], &[7u8; 16], 3).unwrap()
    }

    fn cascade(kind: u8) -> FrameMeta {
        FrameMeta {
            alg: ALG_CASCADE,
            ..meta(kind)
        }
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
            assert!(
                open(&key(), &bytes).is_err(),
                "flipped header byte {idx} accepted"
            );
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
        assert_eq!(
            open(&key(), &bytes).unwrap_err().to_string(),
            "frame authentication failed"
        );
        let mut bytes = sealed;
        let last = bytes.len() - 1;
        *bytes.get_mut(last).unwrap() ^= 0x01;
        assert_eq!(
            open(&key(), &bytes).unwrap_err().to_string(),
            "frame authentication failed"
        );
    }

    #[test]
    fn truncated_and_extended_rejected() {
        let sealed = seal(&key(), &meta(KIND_REVISION), b"secret").unwrap();
        let short = sealed
            .get(..sealed.len() - 1)
            .expect("one byte less than the frame");
        assert_eq!(
            open(&key(), short).unwrap_err().to_string(),
            "corrupted length"
        );
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(
            open(&key(), &long).unwrap_err().to_string(),
            "corrupted length"
        );
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let blob = vec![0u8; crate::limits::MAX_FRAME_PLAINTEXT + 1];
        assert_eq!(
            seal(&key(), &meta(KIND_REVISION), &blob)
                .unwrap_err()
                .to_string(),
            "frame too large"
        );
    }

    #[test]
    fn cascade_round_trip_and_tombstone_size() {
        let pt = b"hello cascade";
        let sealed = seal(&key(), &cascade(KIND_REVISION), pt).unwrap();
        assert_eq!(
            sealed.len(),
            crate::HEADER_LEN + pt.len() + CASCADE_OVERHEAD + crate::TAG_LEN
        );
        assert_eq!(open(&key(), &sealed).unwrap().expose().as_slice(), pt);
        let tomb = seal(&key(), &cascade(KIND_TOMBSTONE), &[]).unwrap();
        assert!(open(&key(), &tomb).unwrap().expose().is_empty());
        let index = crate::parse_index(&[sealed, tomb].concat()).unwrap();
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn cascade_every_flipped_byte_rejected() {
        let sealed = seal(&key(), &cascade(KIND_REVISION), b"secret").unwrap();
        for idx in 0..sealed.len() {
            if idx == crate::header::OFF_ALG || idx == crate::header::OFF_ALG + 1 {
                continue;
            }
            let mut bytes = sealed.clone();
            *bytes.get_mut(idx).unwrap() ^= 0x01;
            assert!(open(&key(), &bytes).is_err(), "flipped byte {idx} accepted");
        }
    }

    #[test]
    fn cascade_wrong_key_and_downgrade_rejected() {
        let sealed = seal(&key(), &cascade(KIND_REVISION), b"secret").unwrap();
        let other = frame_key(&[9u8; 32], &[7u8; 16], 4).unwrap();
        assert_eq!(
            open(&other, &sealed).unwrap_err().to_string(),
            "frame authentication failed"
        );
        let mut downgraded = sealed;
        downgraded[crate::header::OFF_ALG..crate::header::OFF_ALG + 2]
            .copy_from_slice(&ALG_AEGIS256.to_le_bytes());
        assert!(open(&key(), &downgraded).is_err());
    }

    #[test]
    fn unknown_seal_algorithm_rejected() {
        let meta = FrameMeta {
            alg: 0xA0FF,
            ..meta(KIND_REVISION)
        };
        assert_eq!(
            seal(&key(), &meta, b"x").unwrap_err().to_string(),
            "unsupported frame algorithm 0xa0ff"
        );
    }
}
