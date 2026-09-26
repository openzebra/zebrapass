//! Password wrap records: encode + parse.

use std::marker::PhantomData;

use crate::limits::{
    self, read_array, shift, KIND_PASSWORD, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN,
};
use crate::wrap_entry::{PasswordWrap, WrapEntry};

const PW_NONCE: usize = 8;
const PW_CT: usize = 40;
const PW_TAG: usize = 72;

/// Encode one password record.
///
/// # Errors
///
/// Returns `corrupted length` when the payload does not fit `entry_len`.
#[must_use = "the encoded record is only useful when stored"]
pub fn encode_password_entry(
    kid: [u8; 8],
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> [u8; PASSWORD_RECORD_LEN] {
    let record_kind = KIND_PASSWORD.to_le_bytes();
    let entry_len = limits::wire_len(PASSWORD_PAYLOAD_LEN);
    limits::concat_array(&[&record_kind, &entry_len, &kid, &nonce, &ct, &tag])
}

pub(super) fn parse_password(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    if u32::try_from(PASSWORD_PAYLOAD_LEN) != Ok(entry_len) {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, PASSWORD_PAYLOAD_LEN)?;
    if bytes.get(payload..end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    Ok((
        WrapEntry::Password(PasswordWrap {
            kid: read_array(bytes, payload)?,
            nonce: read_array(bytes, shift(payload, PW_NONCE)?)?,
            ct: read_array(bytes, shift(payload, PW_CT)?)?,
            tag: read_array(bytes, shift(payload, PW_TAG)?)?,
            _file: PhantomData,
        }),
        end,
    ))
}
