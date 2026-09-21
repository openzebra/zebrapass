//! Failures of create, unlock, and vault mutation.

use std::fmt;

use aead::AeadError;
use container::FormatError;
use kdf::KdfError;
use wraps::WrapError;

/// Caller-stored generation and commit tag from an earlier open.
///
/// Passed back to [`crate::unlock`]. Not a secret: both values are in the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Seen {
    /// `generation` the caller last accepted.
    pub generation: u64,
    /// Commit tag the caller last accepted.
    pub commit_tag: [u8; 32],
}

/// Failure of a vault operation.
///
/// Variants match the container, KDF, wrap, and body errors a caller can hit,
/// plus commit, rollback, and password checks that live in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultV2Error {
    /// File does not start with `BRBY`.
    BadMagic,
    /// `version` is not 2.
    UnsupportedVersion(u16),
    /// `body_alg` is unknown, or Kuznyechik-MGM which this build does not seal.
    UnsupportedBodyAlg(u16),
    /// `wrap_alg` is not AEGIS-256 (`0xB001`).
    UnsupportedWrapAlg(u16),
    /// `kdf_alg` is not Argon2id (`0x0001`).
    UnsupportedKdf(u16),
    /// Device `kem_alg` is not sntrup1277 (`0xC001`).
    UnsupportedKem(u16),
    /// Argon2id memory, time, or parallelism is outside the floor or ceiling.
    KdfParamsRejected,
    /// A length, count, or entry size does not match the file.
    CorruptedLength,
    /// The password wrap or the requested device id is not in the directory.
    WrapNotFound,
    /// The wrap tag did not match. A wrong password is this same error.
    WrapAuthFailed,
    /// HMAC over the file prefix did not match the trailing commit tag.
    CommitMismatch,
    /// The body authentication tag did not match.
    BodyAuthFailed,
    /// X25519 produced 32 zero bytes. HKDF was not run.
    ZeroSharedSecret,
    /// `file.generation` is older than [`Seen::generation`].
    Rollback,
    /// Same generation as [`Seen`], but a different commit tag.
    Conflict,
    /// The password is empty. Argon2 was not run.
    EmptyPassword,
}

impl fmt::Display for VaultV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("bad magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported version {version}")
            }
            Self::UnsupportedBodyAlg(alg) => {
                write!(formatter, "unsupported body algorithm {alg:#06x}")
            }
            Self::UnsupportedWrapAlg(alg) => {
                write!(formatter, "unsupported wrap algorithm {alg:#06x}")
            }
            Self::UnsupportedKdf(alg) => {
                write!(formatter, "unsupported kdf {alg:#06x}")
            }
            Self::UnsupportedKem(alg) => {
                write!(formatter, "unsupported kem {alg:#06x}")
            }
            Self::KdfParamsRejected => formatter.write_str("kdf parameters rejected"),
            Self::CorruptedLength => formatter.write_str("corrupted length"),
            Self::WrapNotFound => formatter.write_str("wrap not found"),
            Self::WrapAuthFailed => formatter.write_str("wrap authentication failed"),
            Self::CommitMismatch => formatter.write_str("commit mismatch"),
            Self::BodyAuthFailed => formatter.write_str("body authentication failed"),
            Self::ZeroSharedSecret => formatter.write_str("zero shared secret"),
            Self::Rollback => formatter.write_str("rollback"),
            Self::Conflict => formatter.write_str("conflict"),
            Self::EmptyPassword => formatter.write_str("empty password"),
        }
    }
}

impl std::error::Error for VaultV2Error {}

impl From<FormatError> for VaultV2Error {
    fn from(err: FormatError) -> Self {
        match err {
            FormatError::BadMagic => Self::BadMagic,
            FormatError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            FormatError::UnsupportedBodyAlg(alg) => Self::UnsupportedBodyAlg(alg),
            FormatError::UnsupportedWrapAlg(alg) => Self::UnsupportedWrapAlg(alg),
            FormatError::UnsupportedKdf(alg) => Self::UnsupportedKdf(alg),
            FormatError::UnsupportedKem(alg) => Self::UnsupportedKem(alg),
            FormatError::KdfParamsRejected => Self::KdfParamsRejected,
            FormatError::CorruptedLength => Self::CorruptedLength,
        }
    }
}

impl From<KdfError> for VaultV2Error {
    fn from(err: KdfError) -> Self {
        match err {
            KdfError::KdfParamsRejected => Self::KdfParamsRejected,
            KdfError::EmptyPassword => Self::EmptyPassword,
        }
    }
}

impl From<AeadError> for VaultV2Error {
    fn from(err: AeadError) -> Self {
        match err {
            AeadError::UnsupportedBodyAlg(alg) => Self::UnsupportedBodyAlg(alg),
            AeadError::BodyAuthFailed => Self::BodyAuthFailed,
            AeadError::CorruptedLength => Self::CorruptedLength,
        }
    }
}

impl From<WrapError> for VaultV2Error {
    fn from(err: WrapError) -> Self {
        match err {
            WrapError::EmptyPassword => Self::EmptyPassword,
            WrapError::KdfParamsRejected => Self::KdfParamsRejected,
            WrapError::ZeroSharedSecret => Self::ZeroSharedSecret,
            WrapError::WrapNotFound => Self::WrapNotFound,
            WrapError::UnsupportedKem(alg) => Self::UnsupportedKem(alg),
            WrapError::WrapAuthFailed => Self::WrapAuthFailed,
            // No session variant for an OS entropy failure or a KEM blob of the
            // wrong length. Both make the operation unusable, same as a length
            // that does not match the file.
            WrapError::Entropy | WrapError::KemLength => Self::CorruptedLength,
        }
    }
}
