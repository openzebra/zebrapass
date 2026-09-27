//! PRF wrap records: encode + parse.

use crate::limits::{read_array, shift, ENTRY_HEADER_LEN, KIND_PRF};
use crate::wrap_entry::{PrfWrap, WrapEntry};

const PRF_CRED_ID_MIN: usize = 16;
const PRF_CRED_ID_MAX: usize = 64;
const PRF_FIXED_LEN: usize = 16 + 32 + 32 + 32 + 32;
const PRF_PAYLOAD_MIN: usize = PRF_FIXED_LEN + PRF_CRED_ID_MIN;
const PRF_PAYLOAD_MAX: usize = PRF_FIXED_LEN + PRF_CRED_ID_MAX;

/// Encode one PRF record.
///
/// # Errors
///
/// Returns `corrupted length` when the credential id does not fit the
/// payload bounds.
#[must_use = "the encoded record is only useful when stored"]
pub fn encode_prf_entry(
    id: [u8; 16],
    cred_id: &[u8],
    salt: [u8; 32],
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if !matches!(cred_id.len(), PRF_CRED_ID_MIN..=PRF_CRED_ID_MAX) {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let payload = PRF_FIXED_LEN
        .checked_add(cred_id.len())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let entry_len = u32::try_from(payload).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    let mut out = Vec::with_capacity(
        ENTRY_HEADER_LEN
            .checked_add(payload)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?,
    );
    out.extend_from_slice(&KIND_PRF.to_le_bytes());
    out.extend_from_slice(&entry_len.to_le_bytes());
    out.extend_from_slice(&id);
    out.extend_from_slice(cred_id);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub(super) fn parse_prf(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let payload_len = usize::try_from(entry_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    if !matches!(payload_len, PRF_PAYLOAD_MIN..=PRF_PAYLOAD_MAX) {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, payload_len)?;
    if bytes.get(payload..end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let cred_len = payload_len - PRF_FIXED_LEN;
    let cred_at = shift(payload, 16)?;
    let salt_at = shift(cred_at, cred_len)?;
    let cred_id = bytes
        .get(cred_at..salt_at)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((
        WrapEntry::Prf(PrfWrap {
            id: read_array(bytes, payload)?,
            cred_id,
            salt: read_array(bytes, salt_at)?,
            nonce: read_array(bytes, shift(salt_at, 32)?)?,
            ct: read_array(bytes, shift(salt_at, 64)?)?,
            tag: read_array(bytes, shift(salt_at, 96)?)?,
        }),
        end,
    ))
}
