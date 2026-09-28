//! Secure-element (chip) wrap records: encode + parse.

use pq::{KEM_CT_LEN, PQ_PK_LEN};

use crate::limits::{read_array, shift, ENTRY_HEADER_LEN, KIND_CHIP};
use crate::wrap_entry::{ChipWrap, WrapEntry};

const CHIP_CHIP_PUB: usize = 16;
const CHIP_EPH_PUB: usize = 81;
const CHIP_PQ_PK: usize = 146;
const CHIP_PREFIX_LEN: usize = 16 + 65 + 65 + PQ_PK_LEN;
const CHIP_SUFFIX_LEN: usize = 96;
const CHIP_PAYLOAD_MIN: usize = CHIP_PREFIX_LEN + KEM_CT_LEN + CHIP_SUFFIX_LEN;

/// Encode one chip record. `kem_ct` is the ML-KEM-768 ciphertext.
///
/// # Errors
///
/// Returns `corrupted length` when `kem_ct` is not [`KEM_CT_LEN`] bytes or the payload
/// does not fit in `entry_len`.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one chip-wrap wire field"
)]
#[must_use = "the encoded record is only useful when stored"]
pub fn encode_chip_entry(
    id: [u8; 16],
    chip_pub: [u8; 65],
    eph_pub: [u8; 65],
    pq_pk: [u8; PQ_PK_LEN],
    kem_ct: &[u8],
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if kem_ct.len() != KEM_CT_LEN {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let payload = CHIP_PREFIX_LEN
        .checked_add(kem_ct.len())
        .and_then(|len| len.checked_add(CHIP_SUFFIX_LEN))
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let entry_len = u32::try_from(payload).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    let mut out = Vec::with_capacity(
        ENTRY_HEADER_LEN
            .checked_add(payload)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?,
    );
    out.extend_from_slice(&KIND_CHIP.to_le_bytes());
    out.extend_from_slice(&entry_len.to_le_bytes());
    out.extend_from_slice(&id);
    out.extend_from_slice(&chip_pub);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&pq_pk);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub(super) fn parse_chip(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let payload_len =
        usize::try_from(entry_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    if payload_len != CHIP_PAYLOAD_MIN {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, payload_len)?;
    if bytes.get(payload..end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let ct_at = shift(payload, CHIP_PREFIX_LEN)?;
    let after_ct = shift(ct_at, KEM_CT_LEN)?;
    let kem_ct = bytes
        .get(ct_at..after_ct)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((
        WrapEntry::Chip(ChipWrap {
            id: read_array(bytes, payload)?,
            chip_pub: read_array(bytes, shift(payload, CHIP_CHIP_PUB)?)?,
            eph_pub: read_array(bytes, shift(payload, CHIP_EPH_PUB)?)?,
            pq_pk: read_array(bytes, shift(payload, CHIP_PQ_PK)?)?,
            kem_ct,
            nonce: read_array(bytes, after_ct)?,
            ct: read_array(bytes, shift(after_ct, 32)?)?,
            tag: read_array(bytes, shift(after_ct, 64)?)?,
        }),
        end,
    ))
}
