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
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rollback => "rollback",
            Self::Conflict => "conflict",
            Self::CommitMismatch => "commit mismatch",
            Self::PrfFactorRequired => "prf factor required",
            Self::NoUsableWrap => "no usable wrap",
        })
    }
}

impl std::error::Error for SessionError {}
