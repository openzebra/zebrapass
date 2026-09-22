//! Password and device wrap records.
//!
//! `entry_len` is taken from the file only to compare it with the size the kind
//! requires. It is never used as an allocation length.

use std::marker::PhantomData;

use crate::limits::{
    self, read_array, read_u16, read_u32, shift, DEVICE_PAYLOAD_MIN, DEVICE_PREFIX_LEN,
    DEVICE_SUFFIX_LEN, ENTRY_HEADER_LEN, KEM_NTRULP, KIND_DEVICE, KIND_PASSWORD,
    PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN,
};

const PW_NONCE: usize = 8;
const PW_CT: usize = 40;
const PW_TAG: usize = 72;

const DEV_KEM: usize = 16;
const DEV_X_PK: usize = 18;
const DEV_EPH_X_PK: usize = 50;

const _: () = {
    assert!(PW_TAG + 32 == PASSWORD_PAYLOAD_LEN);
    assert!(DEV_EPH_X_PK + 32 == DEVICE_PREFIX_LEN);
};

/// Password wrap. Fixed fields are copies; the lifetime ties the entry to the file
/// the way [`DeviceWrap`] does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordWrap<'a> {
    /// Key id for this password wrap.
    pub kid: [u8; 8],
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext (32 bytes, without the tag).
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
    _file: PhantomData<&'a [u8]>,
}

/// Device wrap. The `ntrulp` ciphertext borrows the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceWrap<'a> {
    /// Device id.
    pub device_id: [u8; 16],
    /// KEM id. Parsed entries hold [`KEM_NTRULP`].
    pub kem_alg: u16,
    /// Long-term X25519 public key of the device.
    pub dev_x_pk: [u8; 32],
    /// Ephemeral X25519 public key of the vault owner.
    pub eph_x_pk: [u8; 32],
    /// `ntrulp` ciphertext borrowed from the file, not a `Vec` copy.
    pub ntru_ct: &'a [u8],
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext.
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
}

/// One wrap-directory record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapEntry<'a> {
    /// Kind `0x0001`.
    Password(PasswordWrap<'a>),
    /// Kind `0x0002`.
    Device(DeviceWrap<'a>),
}

/// Encode one password record (`110` bytes).
#[must_use]
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

/// Encode one device record. `ntru_ct` is the `ntrulp` ciphertext, any non-empty length.
///
/// # Errors
///
/// Returns `corrupted length` when `ntru_ct` is empty or the payload
/// does not fit in `entry_len`.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one device-wrap wire field"
)]
pub fn encode_device_entry(
    device_id: [u8; 16],
    kem_alg: u16,
    dev_x_pk: [u8; 32],
    eph_x_pk: [u8; 32],
    ntru_ct: &[u8],
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if ntru_ct.is_empty() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let payload = DEVICE_PREFIX_LEN
        .checked_add(ntru_ct.len())
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
    out.extend_from_slice(ntru_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn parse_entry(bytes: &[u8], offset: usize) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let header_end = shift(offset, ENTRY_HEADER_LEN)?;
    // Kind and entry_len are read only when those 6 bytes sit inside the buffer
    // (the caller passes bytes that already stop before the commit).
    if bytes.get(offset..header_end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let kind = read_u16(bytes, offset)?;
    let entry_len = read_u32(bytes, shift(offset, 2)?)?;
    match kind {
        KIND_PASSWORD => parse_password(bytes, header_end, entry_len),
        KIND_DEVICE => parse_device(bytes, header_end, entry_len),
        // Unknown kinds are corruption. This version does not skip them.
        _ => Err(anyhow::anyhow!("corrupted length")),
    }
}

fn parse_password(
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

fn parse_device(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let payload_len = usize::try_from(entry_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    if payload_len < DEVICE_PAYLOAD_MIN {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, payload_len)?;
    if bytes.get(payload..end).is_none() {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let kem_alg = read_u16(bytes, shift(payload, DEV_KEM)?)?;
    if kem_alg != KEM_NTRULP {
        return Err(anyhow::anyhow!("unsupported kem {kem_alg:#06x}"));
    }
    let ct_len = payload_len - DEVICE_PREFIX_LEN - DEVICE_SUFFIX_LEN;
    let ct_at = shift(payload, DEVICE_PREFIX_LEN)?;
    let after_ct = shift(ct_at, ct_len)?;
    let ntru_ct = bytes
        .get(ct_at..after_ct)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((
        WrapEntry::Device(DeviceWrap {
            device_id: read_array(bytes, payload)?,
            kem_alg,
            dev_x_pk: read_array(bytes, shift(payload, DEV_X_PK)?)?,
            eph_x_pk: read_array(bytes, shift(payload, DEV_EPH_X_PK)?)?,
            ntru_ct,
            nonce: read_array(bytes, after_ct)?,
            ct: read_array(bytes, shift(after_ct, 32)?)?,
            tag: read_array(bytes, shift(after_ct, 64)?)?,
        }),
        end,
    ))
}

impl<'a> TryFrom<&'a [u8]> for WrapEntry<'a> {
    type Error = anyhow::Error;

    /// Accept one record and nothing after it.
    ///
    /// # Errors
    ///
    /// Returns `corrupted length` when the record is truncated,
    /// the kind is unknown, or `entry_len` disagrees with the kind, and
    /// `unsupported kem` when a device record names another KEM.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (entry, next) = parse_entry(bytes, 0)?;
        if next == bytes.len() {
            Ok(entry)
        } else {
            Err(anyhow::anyhow!("corrupted length"))
        }
    }
}
