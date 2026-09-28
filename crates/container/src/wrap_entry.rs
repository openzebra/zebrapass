//! Password, device, chip, and PRF wrap records.
//!
//! `entry_len` is taken from the file only to compare it with the size the kind
//! requires. It is never used as an allocation length.

use pq::PQ_PK_LEN;
use std::marker::PhantomData;

use crate::limits::{
    read_u16, read_u32, shift, ENTRY_HEADER_LEN, KIND_CHIP, KIND_DEVICE, KIND_PASSWORD,
    KIND_PASSWORD_HUMAN, KIND_PRF,
};

mod chip;
mod device;
mod password;
mod prf;

use chip::parse_chip;
use device::parse_device;
use password::parse_password;
use prf::parse_prf;

pub use chip::encode_chip_entry;
pub use device::encode_device_entry;
pub use password::encode_password_entry;
pub use prf::encode_prf_entry;

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
    /// Kind `0x0005`: a human-chosen password, Argon2id + HKDF + AEGIS.
    HumanPassword(crate::wrap_human::HumanPasswordWrap<'a>),
}

impl WrapEntry<'_> {
    /// Whether this record is a password wrap.
    #[must_use]
    pub const fn is_password(&self) -> bool {
        matches!(self, Self::Password(_))
    }

    /// True for the human password wrap.
    #[must_use]
    pub const fn is_human_password(&self) -> bool {
        matches!(self, Self::HumanPassword(_))
    }

    /// True for any wrap a human can present: the seed recovery wrap or the
    /// human password wrap. A vault must keep at least one.
    #[must_use]
    pub const fn is_human_class(&self) -> bool {
        matches!(self, Self::Password(_) | Self::HumanPassword(_))
    }

    /// Wire kind code of this record.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        match self {
            Self::Password(_) => KIND_PASSWORD,
            Self::Device(_) => KIND_DEVICE,
            Self::Chip(_) => KIND_CHIP,
            Self::Prf(_) => KIND_PRF,
            Self::HumanPassword(_) => KIND_PASSWORD_HUMAN,
        }
    }

    /// The id field of this record, when the kind carries one.
    #[must_use]
    pub const fn wrap_id(&self) -> Option<[u8; 16]> {
        match self {
            Self::Password(_) | Self::HumanPassword(_) => None,
            Self::Device(wrap) => Some(wrap.device_id),
            Self::Chip(wrap) => Some(wrap.id),
            Self::Prf(wrap) => Some(wrap.id),
        }
    }
}

/// Encode one device record. `kem_ct` is the ML-KEM-768 ciphertext.
///
/// # Errors
///
/// Returns `corrupted length` when `kem_ct` is not [`KEM_CT_LEN`] bytes or the payload
/// does not fit in `entry_len`.
/// Encode one chip record. `kem_ct` is the ML-KEM-768 ciphertext.
///
/// # Errors
///
/// Returns `corrupted length` when `kem_ct` is not [`KEM_CT_LEN`] bytes or the payload
/// does not fit in `entry_len`.
/// Parse one wrap record starting at `offset`.
///
/// # Errors
///
/// `corrupted length` when the header or payload does not fit the buffer or
/// the entry length names a different payload size; `kdf parameters
/// rejected` for a human password wrap below the wire floor; `corrupted
/// length` for an unknown kind.
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
        KIND_PASSWORD_HUMAN => {
            crate::wrap_human::parse_human_password(bytes, header_end, entry_len)
        }
        // Unknown kinds are corruption. This version does not skip them.
        _ => Err(anyhow::anyhow!("corrupted length")),
    }
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
