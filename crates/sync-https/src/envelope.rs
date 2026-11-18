//! Outer Cascade `0xA005` envelopes for zero-knowledge sync payloads and backups.
//!
//! Inner vault frames, snapshot containers, member logs, and `.zpbackup` bundles
//! are wrapped in an additional outer `ALG_CASCADE` (`0xA005`) authenticated
//! layer keyed from the mailbox or cloud backup secret so the sync server only
//! stores opaque ciphertext.

use frame::{ALG_CASCADE, FrameMeta, KIND_REVISION, open, parse, seal};
use secret::Secret;
use syncwire::reader::Reader;
use zeroize::Zeroizing;

use crate::limits::MAX_ENVELOPE_BYTES;

const ENV_MAGIC: [u8; 4] = *b"ZPSV";
const ENV_VERSION: u16 = 1;
const CHUNK_PLAIN_LEN: usize = 512 * 1024;
const MAX_ENV_FRAMES: usize = (MAX_ENVELOPE_BYTES / CHUNK_PLAIN_LEN) + 4;

/// Domain-separated purpose tag bound inside each outer `ZPSV` envelope.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopePurpose {
    /// Personal vault snapshot bytes (`ZPSN`).
    PersonalSnapshot = 1,
    /// Personal vault snapshot head metadata.
    PersonalHead = 2,
    /// Single personal record frame (`ZPPF` / sealed frame).
    PersonalFrame = 3,
    /// Encrypted personal `VK` rotation grant.
    PersonalRekey = 4,
    /// Shared vault snapshot bytes (`ZPSN`).
    SharedSnapshot = 5,
    /// Shared vault snapshot head metadata.
    SharedHead = 6,
    /// Single signed shared record bundle (`Attestation` + `frame`).
    SharedFrame = 7,
    /// Whole `.zpbackup` remote cloud backup bundle.
    CloudBackup = 8,
}

const fn box_tail(box_id: &[u8; 32]) -> [u8; 16] {
    let mut tail = [0u8; 16];
    if let Some((_, rhs)) = box_id.split_at_checked(16) {
        tail.copy_from_slice(rhs);
    }
    tail
}

/// Seal `plain` under an outer Cascade `0xA005` envelope bound to `box_id`,
/// `purpose`, and `seq`.
///
/// # Errors
///
/// Input exceeding `MAX_ENVELOPE_BYTES`, key/seal failure, or entropy failure.
pub fn seal_envelope(
    key: &Secret<[u8; 32]>,
    box_id: &[u8; 32],
    purpose: EnvelopePurpose,
    seq: u64,
    plain: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if plain.len() > MAX_ENVELOPE_BYTES {
        anyhow::bail!("envelope plaintext exceeds limit");
    }
    let tail = box_tail(box_id);
    let slices: Vec<&[u8]> = if plain.is_empty() {
        vec![&[][..]]
    } else {
        plain.chunks(CHUNK_PLAIN_LEN).collect()
    };
    let count_u32 =
        u32::try_from(slices.len()).map_err(|_| anyhow::anyhow!("envelope too large"))?;
    let mut out = Vec::with_capacity(4 + 2 + 4 + 8 + 4 + plain.len() + slices.len() * 192);
    out.extend_from_slice(&ENV_MAGIC);
    out.extend_from_slice(&ENV_VERSION.to_be_bytes());
    out.extend_from_slice(&(purpose as u32).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&count_u32.to_be_bytes());

    for (idx, chunk) in slices.into_iter().enumerate() {
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: purpose as u32,
            revision: u64::try_from(idx).map_err(|_| anyhow::anyhow!("chunk index overflow"))?,
            origin_device: tail,
            timestamp_ms: seq,
            alg: ALG_CASCADE,
        };
        let frame_bytes = seal(key, &meta, chunk)?;
        let len_u32 = u32::try_from(frame_bytes.len())
            .map_err(|_| anyhow::anyhow!("sealed frame exceeds u32"))?;
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&frame_bytes);
    }
    Ok(out)
}

/// Open and authenticate an outer Cascade `0xA005` envelope produced by
/// [`seal_envelope`], verifying purpose, mailbox binding, algorithm `0xA005`,
/// and frame ordering.
///
/// # Errors
///
/// Wrong magic/version, purpose or mailbox mismatch, downgraded algorithm, or
/// outer MAC/AEAD authentication failure.
pub fn open_envelope(
    key: &Secret<[u8; 32]>,
    box_id: &[u8; 32],
    expected_purpose: EnvelopePurpose,
    bytes: &[u8],
) -> anyhow::Result<(u64, Zeroizing<Vec<u8>>)> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != ENV_MAGIC || reader.u16()? != ENV_VERSION {
        anyhow::bail!("unsupported envelope format");
    }
    let purpose_u32 = reader.u32()?;
    if purpose_u32 != expected_purpose as u32 {
        anyhow::bail!("envelope purpose mismatch");
    }
    let seq = reader.u64()?;
    let count = usize::try_from(reader.u32()?).map_err(|_| anyhow::anyhow!("envelope count"))?;
    if count == 0 || count > MAX_ENV_FRAMES {
        anyhow::bail!("envelope frame count out of bounds");
    }
    let tail = box_tail(box_id);
    let mut plain = Zeroizing::new(Vec::new());
    for idx in 0..count {
        let frame_bytes = reader.bytes_u32(MAX_ENVELOPE_BYTES + 4_096)?;
        let header = parse(frame_bytes)?;
        let expected_rev =
            u64::try_from(idx).map_err(|_| anyhow::anyhow!("frame index overflow"))?;
        if header.alg != ALG_CASCADE
            || header.kind != KIND_REVISION
            || header.record_id != purpose_u32
            || header.revision != expected_rev
            || header.origin_device != tail
            || header.timestamp_ms != seq
        {
            anyhow::bail!("envelope header binding mismatch");
        }
        let dec = open(key, frame_bytes)?;
        if plain.len().saturating_add(dec.expose().len()) > MAX_ENVELOPE_BYTES {
            anyhow::bail!("opened envelope exceeds limit");
        }
        plain.extend_from_slice(dec.expose());
    }
    reader.finish()?;
    Ok((seq, plain))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests may unwrap")]
mod tests {
    use super::{EnvelopePurpose, open_envelope, seal_envelope};
    use secret::Secret;

    #[test]
    fn outer_cascade_envelope_round_trip_and_binds_context() {
        let key = Secret::new([0x42u8; 32]);
        let box_id = [0x11u8; 32];
        let sealed = seal_envelope(
            &key,
            &box_id,
            EnvelopePurpose::PersonalFrame,
            7,
            b"secret-inner-frame",
        )
        .unwrap();
        let (seq, plain) =
            open_envelope(&key, &box_id, EnvelopePurpose::PersonalFrame, &sealed).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(&*plain, b"secret-inner-frame");
        assert!(open_envelope(&key, &box_id, EnvelopePurpose::SharedFrame, &sealed).is_err());
        assert!(
            open_envelope(&key, &[0x22u8; 32], EnvelopePurpose::PersonalFrame, &sealed).is_err()
        );
        let mut tampered = sealed;
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xFF;
        }
        assert!(open_envelope(&key, &box_id, EnvelopePurpose::PersonalFrame, &tampered).is_err());
    }
}
