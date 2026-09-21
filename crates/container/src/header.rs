//! Static header. Magic and version are checked, not stored: a parsed header is version 2.

use crate::error::FormatError;
use crate::limits::{
    self, read_array, read_u16, read_u32, HEADER_LEN, KDF_ARGON2ID, MAGIC, VERSION, WRAP_AEGIS256,
};

const OFF_VERSION: usize = 4;
const OFF_KDF_ALG: usize = 6;
const OFF_KDF_M: usize = 8;
const OFF_KDF_T: usize = 12;
const OFF_KDF_P: usize = 16;
const OFF_SALT: usize = 20;
const OFF_VAULT_ID: usize = 52;
const OFF_BODY_ALG: usize = 68;
const OFF_WRAP_ALG: usize = 70;

const _: () = {
    assert!(OFF_VERSION == 4);
    assert!(OFF_KDF_ALG == OFF_VERSION + 2);
    assert!(OFF_KDF_M == OFF_KDF_ALG + 2);
    assert!(OFF_KDF_T == OFF_KDF_M + 4);
    assert!(OFF_KDF_P == OFF_KDF_T + 4);
    assert!(OFF_SALT == OFF_KDF_P + 4);
    assert!(OFF_VAULT_ID == OFF_SALT + 32);
    assert!(OFF_BODY_ALG == OFF_VAULT_ID + 16);
    assert!(OFF_WRAP_ALG == OFF_BODY_ALG + 2);
    assert!(HEADER_LEN == OFF_WRAP_ALG + 2);
};

/// Fields of the 72-byte static header.
///
/// `magic` and `version` are not fields. [`Self::to_bytes`] writes [`MAGIC`] and
/// [`VERSION`], and [`TryFrom`] accepts only those values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticHeader {
    /// KDF id. Parsed headers hold [`KDF_ARGON2ID`].
    pub kdf_alg: u16,
    /// Argon2id memory cost in KiB.
    pub kdf_m_kib: u32,
    /// Argon2id time cost.
    pub kdf_t: u32,
    /// Argon2id parallelism.
    pub kdf_p: u32,
    /// Per-vault Argon2 salt. Not a secret.
    pub kdf_salt: [u8; 32],
    /// Public vault id. Also the HKDF salt.
    pub vault_id: [u8; 16],
    /// Body algorithm id.
    pub body_alg: u16,
    /// Wrap algorithm id.
    pub wrap_alg: u16,
}

impl StaticHeader {
    /// Encode the header, including magic and version.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let version = VERSION.to_le_bytes();
        let kdf_alg = self.kdf_alg.to_le_bytes();
        let kdf_m_kib = self.kdf_m_kib.to_le_bytes();
        let kdf_t = self.kdf_t.to_le_bytes();
        let kdf_p = self.kdf_p.to_le_bytes();
        let body_alg = self.body_alg.to_le_bytes();
        let wrap_alg = self.wrap_alg.to_le_bytes();
        limits::concat_array(&[
            &MAGIC,
            &version,
            &kdf_alg,
            &kdf_m_kib,
            &kdf_t,
            &kdf_p,
            &self.kdf_salt,
            &self.vault_id,
            &body_alg,
            &wrap_alg,
        ])
    }
}

impl TryFrom<&[u8]> for StaticHeader {
    type Error = FormatError;

    /// Accept exactly [`HEADER_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::BadMagic`] when the first bytes are not `BRBY`,
    /// [`FormatError::CorruptedLength`] when the slice is not 72 bytes,
    /// [`FormatError::UnsupportedVersion`], [`FormatError::UnsupportedKdf`],
    /// [`FormatError::UnsupportedWrapAlg`], or [`FormatError::UnsupportedBodyAlg`]
    /// for an unknown id, and [`FormatError::KdfParamsRejected`] when Argon2
    /// parameters fall outside the floor or ceiling.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        check_magic(bytes)?;
        if bytes.len() != HEADER_LEN {
            return Err(FormatError::CorruptedLength);
        }
        let version = read_u16(bytes, OFF_VERSION)?;
        if version != VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let kdf_alg = read_u16(bytes, OFF_KDF_ALG)?;
        if kdf_alg != KDF_ARGON2ID {
            return Err(FormatError::UnsupportedKdf(kdf_alg));
        }
        let wrap_alg = read_u16(bytes, OFF_WRAP_ALG)?;
        if wrap_alg != WRAP_AEGIS256 {
            return Err(FormatError::UnsupportedWrapAlg(wrap_alg));
        }
        let body_alg = read_u16(bytes, OFF_BODY_ALG)?;
        if !limits::known_body_alg(body_alg) {
            return Err(FormatError::UnsupportedBodyAlg(body_alg));
        }
        let kdf_m_kib = read_u32(bytes, OFF_KDF_M)?;
        let kdf_t = read_u32(bytes, OFF_KDF_T)?;
        let kdf_p = read_u32(bytes, OFF_KDF_P)?;
        // Floor and ceiling run inside header acceptance so callers never start
        // Argon2, and the file parser does not read the wrap directory yet.
        if !limits::kdf_params_ok(kdf_m_kib, kdf_t, kdf_p) {
            return Err(FormatError::KdfParamsRejected);
        }
        Ok(Self {
            kdf_alg,
            kdf_m_kib,
            kdf_t,
            kdf_p,
            kdf_salt: read_array(bytes, OFF_SALT)?,
            vault_id: read_array(bytes, OFF_VAULT_ID)?,
            body_alg,
            wrap_alg,
        })
    }
}

pub fn check_magic(bytes: &[u8]) -> Result<(), FormatError> {
    match bytes.get(..MAGIC.len()) {
        Some(magic) if magic == MAGIC.as_slice() => Ok(()),
        _ => Err(FormatError::BadMagic),
    }
}
