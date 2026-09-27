//! Device wrap records: encode + parse.

use pq::KEM_CT_LEN;

use crate::limits::{
    read_array, read_u16, shift, DEVICE_PAYLOAD_MIN, DEVICE_PREFIX_LEN, DEVICE_SUFFIX_LEN,
    ENTRY_HEADER_LEN, KIND_DEVICE, KEM_MLKEM768,
};
use crate::wrap_entry::{DeviceWrap, WrapEntry};

const DEV_KEM: usize = 16;
const DEV_X_PK: usize = 18;
const DEV_EPH_X_PK: usize = 50;

/// Encode one device record.
///
/// # Errors
///
/// Returns `corrupted length` when `kem_ct` is not [`KEM_CT_LEN`] bytes or the payload
/// does not fit in `entry_len`.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one device-wrap wire field"
)]
#[must_use = "the encoded record is only useful when stored"]
pub fn encode_device_entry(
    device_id: [u8; 16],
    kem_alg: u16,
    dev_x_pk: [u8; 32],
    eph_x_pk: [u8; 32],
    kem_ct: &[u8],
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if kem_ct.len() != KEM_CT_LEN {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let payload = DEVICE_PREFIX_LEN
        .checked_add(kem_ct.len())
        .and_then(|len| len.checked_add(DEVICE_SUFFIX_LEN))
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let entry_len = u32::try_from(payload).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    let mut out = Vec::with_capacity(
        ENTRY_HEADER_LEN
            .checked_add(payload)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?,
    );
    out.extend_from_slice(&KIND_DEVICE.to_le_bytes());
    out.extend_from_slice(&entry_len.to_le_bytes());
    out.extend_from_slice(&device_id);
    out.extend_from_slice(&kem_alg.to_le_bytes());
    out.extend_from_slice(&dev_x_pk);
    out.extend_from_slice(&eph_x_pk);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub(super) fn parse_device(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let payload_len = usize::try_from(entry_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    if payload_len != DEVICE_PAYLOAD_MIN {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, payload_len)?;
    if bytes.get(payload..end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let kem_alg = read_u16(bytes, shift(payload, DEV_KEM)?)?;
    if kem_alg != KEM_MLKEM768 {
        return Err(anyhow::anyhow!("unsupported kem {kem_alg:#06x}"));
    }
    let ct_at = shift(payload, DEVICE_PREFIX_LEN)?;
    let after_ct = shift(ct_at, KEM_CT_LEN)?;
    let kem_ct = bytes
        .get(ct_at..after_ct)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((
        WrapEntry::Device(DeviceWrap {
            device_id: read_array(bytes, payload)?,
            kem_alg,
            dev_x_pk: read_array(bytes, shift(payload, DEV_X_PK)?)?,
            eph_x_pk: read_array(bytes, shift(payload, DEV_EPH_X_PK)?)?,
            kem_ct,
            nonce: read_array(bytes, after_ct)?,
            ct: read_array(bytes, shift(after_ct, 32)?)?,
            tag: read_array(bytes, shift(after_ct, 64)?)?,
        }),
        end,
    ))
}
