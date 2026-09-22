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
