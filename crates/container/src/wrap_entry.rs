//! Password, device, chip, and PRF wrap records.
//!
//! `entry_len` is taken from the file only to compare it with the size the kind
//! requires. It is never used as an allocation length.

use std::marker::PhantomData;

use pq::{KEM_CT_LEN, PQ_PK_LEN};

use crate::limits::{
    self, read_array, read_u16, read_u32, shift, DEVICE_PAYLOAD_MIN, DEVICE_PREFIX_LEN,
    DEVICE_SUFFIX_LEN, ENTRY_HEADER_LEN, KEM_MLKEM768, KIND_CHIP, KIND_DEVICE, KIND_PASSWORD,
    KIND_PRF, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN,
};

const PW_NONCE: usize = 8;
const PW_CT: usize = 40;
const PW_TAG: usize = 72;

const DEV_KEM: usize = 16;
const DEV_X_PK: usize = 18;
const DEV_EPH_X_PK: usize = 50;

const CHIP_CHIP_PUB: usize = 16;
const CHIP_EPH_PUB: usize = 81;
const CHIP_PQ_PK: usize = 146;
const CHIP_PREFIX_LEN: usize = 16 + 65 + 65 + PQ_PK_LEN;
const CHIP_SUFFIX_LEN: usize = 96;
const CHIP_PAYLOAD_MIN: usize = CHIP_PREFIX_LEN + KEM_CT_LEN + CHIP_SUFFIX_LEN;

const PRF_CRED_ID_MIN: usize = 16;
const PRF_CRED_ID_MAX: usize = 64;
const PRF_FIXED_LEN: usize = 16 + 32 + 32 + 32 + 32;
const PRF_PAYLOAD_MIN: usize = PRF_FIXED_LEN + PRF_CRED_ID_MIN;
const PRF_PAYLOAD_MAX: usize = PRF_FIXED_LEN + PRF_CRED_ID_MAX;

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
    /// KEM id. Parsed entries hold [`KEM_MLKEM768`].
    pub kem_alg: u16,
    /// Long-term X25519 public key of the device.
    pub dev_x_pk: [u8; 32],
    /// Ephemeral X25519 public key of the vault owner.
    pub eph_x_pk: [u8; 32],
    /// `ntrulp` ciphertext borrowed from the file, not a `Vec` copy.
    pub kem_ct: &'a [u8],
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext.
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
}

/// Chip wrap (secure enclave, kind `0x0003`). The `ntrulp` ciphertext borrows the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipWrap<'a> {
    /// Grant id. A caller-chosen label, compared before any KEM.
    pub id: [u8; 16],
    /// Uncompressed P-256 public key of the chip (65 bytes).
    pub chip_pub: [u8; 65],
    /// Uncompressed P-256 public key of the sealing ephemeral key (65 bytes).
    pub eph_pub: [u8; 65],
    /// `ntrulp` public key the ephemeral PQ secret is encrypted to.
    pub pq_pk: [u8; PQ_PK_LEN],
    /// `ntrulp` ciphertext borrowed from the file, not a `Vec` copy.
    pub kem_ct: &'a [u8],
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext.
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
}

/// `YubiKey` PRF wrap (kind `0x0004`). The CTAP credential id borrows the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrfWrap<'a> {
    /// Grant id.
    pub id: [u8; 16],
    /// CTAP credential id borrowed from the file, `16..=64` bytes.
    pub cred_id: &'a [u8],
    /// PRF salt.
    pub salt: [u8; 32],
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext.
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
}

/// One wrap-directory record.
#[allow(
    clippy::large_enum_variant,
    reason = "the chip record carries the PQ public key inline; boxing it would defeat zero-copy parsing"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapEntry<'a> {
    /// Kind `0x0001`.
    Password(PasswordWrap<'a>),
    /// Kind `0x0002`.
    Device(DeviceWrap<'a>),
    /// Kind `0x0003`.
    Chip(ChipWrap<'a>),
    /// Kind `0x0004`.
    Prf(PrfWrap<'a>),
}

impl WrapEntry<'_> {
    /// Whether this record is a password wrap.
    #[must_use]
    pub const fn is_password(&self) -> bool {
        matches!(self, Self::Password(_))
    }

    /// Wire kind code of this record.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        match self {
            Self::Password(_) => KIND_PASSWORD,
            Self::Device(_) => KIND_DEVICE,
            Self::Chip(_) => KIND_CHIP,
            Self::Prf(_) => KIND_PRF,
        }
    }

    /// The id field of this record, when the kind carries one.
    #[must_use]
    pub const fn wrap_id(&self) -> Option<[u8; 16]> {
        match self {
            Self::Password(_) => None,
            Self::Device(wrap) => Some(wrap.device_id),
            Self::Chip(wrap) => Some(wrap.id),
            Self::Prf(wrap) => Some(wrap.id),
        }
    }
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

/// Encode one device record. `kem_ct` is the ML-KEM-768 ciphertext.
///
/// # Errors
///
/// Returns `corrupted length` when `kem_ct` is not [`KEM_CT_LEN`] bytes or the payload
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

/// Encode one PRF record. `cred_id` is the CTAP credential id, `16..=64` bytes.
///
/// # Errors
///
/// Returns `corrupted length` when `cred_id` is outside `16..=64` bytes
/// or the payload does not fit in `entry_len`.
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
        KIND_CHIP => parse_chip(bytes, header_end, entry_len),
        KIND_PRF => parse_prf(bytes, header_end, entry_len),
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

fn parse_chip(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(WrapEntry<'_>, usize)> {
    let payload_len = usize::try_from(entry_len).map_err(|_| anyhow::anyhow!("corrupted length"))?;
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

fn parse_prf(
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
