//! Rollback-detection state carried by [`crate::unlock`].

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

/// Errors at the session boundary.
///
/// `Display` text is stable: callers match on it while migrating off strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// On-disk generation is older than the last accepted one.
    Rollback,
    /// Same generation, different commit tag.
    Conflict,
    /// Commit HMAC does not match the file.
    CommitMismatch,
    /// A PRF wrap needs the platform HMAC response.
    PrfFactorRequired,
    /// No wrap matched the supplied factors.
    NoUsableWrap,
    /// A record payload longer than `u32::MAX` cannot be signed.
    CiphertextTooLarge,
    /// ML-DSA signing failed.
    SignFailed,
    /// The record is not strictly newer than the stored revision.
    StaleRevision,
    /// The frame header does not match the signed outer fields.
    HeaderMismatch,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rollback => "rollback",
            Self::Conflict => "conflict",
            Self::CommitMismatch => "commit mismatch",
            Self::PrfFactorRequired => "prf factor required",
            Self::NoUsableWrap => "no usable wrap",
            Self::CiphertextTooLarge => "ciphertext too large",
            Self::SignFailed => "sign failed",
            Self::StaleRevision => "stale revision",
            Self::HeaderMismatch => "header mismatch",
        })
    }
}

impl std::error::Error for SessionError {}
