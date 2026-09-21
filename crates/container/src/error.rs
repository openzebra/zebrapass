//! Structural failures of the vault container.

use std::fmt;

/// Parse and encode failures for the vault container.
///
/// Commit authentication is not represented. This crate returns the tag
/// bytes and leaves HMAC verification to the session layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    /// File does not start with [`crate::MAGIC`].
    BadMagic,
    /// `version` is not [`crate::VERSION`].
    UnsupportedVersion(u16),
    /// `body_alg` is not `0xA001`, `0xA002`, or `0xA003`.
    UnsupportedBodyAlg(u16),
    /// `wrap_alg` is not [`crate::WRAP_AEGIS256`].
    UnsupportedWrapAlg(u16),
    /// `kdf_alg` is not [`crate::KDF_ARGON2ID`].
    UnsupportedKdf(u16),
    /// Device `kem_alg` is not [`crate::KEM_SNTRUP1277`].
    UnsupportedKem(u16),
    /// Argon2id memory, time, or parallelism is outside the floor or ceiling.
    KdfParamsRejected,
    /// A length, count, kind, or entry size does not match the file.
    CorruptedLength,
}

impl fmt::Display for FormatError {
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
        }
    }
}

impl std::error::Error for FormatError {}
