//! Failures of password and device wraps.

use std::fmt;

use kdf::KdfError;
use pq::PqError;

/// Password-wrap or device-wrap failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapError {
    /// The password is empty. Argon2 was not run.
    EmptyPassword,
    /// Argon2 parameters are outside the floor or ceiling, or HKDF rejected them.
    KdfParamsRejected,
    /// The OS random source failed.
    Entropy,
    /// The X25519 shared secret was 32 zero bytes. HKDF was not run.
    ZeroSharedSecret,
    /// The device id does not match this wrap.
    WrapNotFound,
    /// `kem_alg` is not sntrup1277 (`0xC001`).
    UnsupportedKem(u16),
    /// The AEGIS-256 tag did not match.
    ///
    /// A wrong password is this same error. It is not reported separately.
    WrapAuthFailed,
    /// An sntrup1277 key or ciphertext had the wrong length.
    KemLength,
}

impl fmt::Display for WrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassword => formatter.write_str("empty password"),
            Self::KdfParamsRejected => formatter.write_str("kdf parameters rejected"),
            Self::Entropy => formatter.write_str("os entropy failed"),
            Self::ZeroSharedSecret => formatter.write_str("zero shared secret"),
            Self::WrapNotFound => formatter.write_str("wrap not found"),
            Self::UnsupportedKem(alg) => {
                write!(formatter, "unsupported kem {alg:#06x}")
            }
            Self::WrapAuthFailed => formatter.write_str("wrap authentication failed"),
            Self::KemLength => formatter.write_str("kem length"),
        }
    }
}

impl std::error::Error for WrapError {}

impl From<KdfError> for WrapError {
    fn from(err: KdfError) -> Self {
        match err {
            KdfError::EmptyPassword => Self::EmptyPassword,
            KdfError::KdfParamsRejected => Self::KdfParamsRejected,
        }
    }
}

impl From<PqError> for WrapError {
    fn from(err: PqError) -> Self {
        match err {
            PqError::PublicKeyLength
            | PqError::SecretKeyLength
            | PqError::CiphertextLength
            | PqError::SharedSecretLength => Self::KemLength,
        }
    }
}
