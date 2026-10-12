//! What the UI may say about a failure.
//!
//! Unlock failures collapse into one uniform [`UnlockError::Denied`]: a
//! wrong password, a wrong phrase, a flipped byte, and a forged tag all read
//! the same. The only distinct outcomes are flow signals (which factor to
//! present) and the rollback alarm, which is an attack signal rather than a
//! statement about the key.

use p2p_net::FetchError;
use session::SessionError;

/// Unlock outcome shown to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockError {
    /// Uniform authentication failure.
    Denied,
    /// The vault wants its password.
    NeedsPassword,
    /// The vault wants a hardware key, which this build cannot drive.
    NeedsHwKey,
    /// The file is older than the last one this device accepted.
    Rollback {
        /// Generation recorded on this device.
        seen: u64,
        /// Generation of the file on disk.
        disk: u64,
    },
    /// Same generation as the last accepted file, different contents.
    Conflict {
        /// The shared generation.
        generation: u64,
    },
    /// The device's rollback cursor is missing or unreadable.
    MetaMissing,
    /// Not a vault file this build can read.
    NotAVault,
    /// The other device could not be reached, turned this one away, or did
    /// not answer properly.
    Peer(FetchError),
    /// The other device sent a file that is not the vault it announced, or
    /// that does not open with this phrase.
    WrongVault,
    /// Storage or OS failure unrelated to any key.
    Io,
}

impl UnlockError {
    /// The one line shown for this outcome.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Denied => "Couldn't unlock this vault.",
            Self::NeedsPassword => "This vault opens with its password.",
            Self::NeedsHwKey => "This vault needs a hardware key. Not available yet.",
            Self::Rollback { .. } => "This vault file is older than the one this device last saw.",
            Self::Conflict { .. } => "This vault file conflicts with the one this device last saw.",
            Self::MetaMissing => "This device's rollback record for the vault is missing.",
            Self::NotAVault => "This is not a ZebraPass vault file.",
            Self::Peer(FetchError::Unreachable) => "That device could not be reached.",
            Self::Peer(FetchError::Refused) => "That device turned this one away.",
            Self::Peer(FetchError::Failed) => "That device did not answer properly.",
            Self::WrongVault => "That device did not send your vault.",
            Self::Io => "Couldn't read the vault file.",
        }
    }
}

impl From<&anyhow::Error> for UnlockError {
    fn from(error: &anyhow::Error) -> Self {
        let Some(kind) = error.downcast_ref::<SessionError>() else {
            // Wrap, commit, and body authentication failures are plain
            // messages in the core; all of them are the uniform denial.
            return Self::Denied;
        };
        match kind {
            SessionError::Rollback => Self::Rollback { seen: 0, disk: 0 },
            SessionError::Conflict => Self::Conflict { generation: 0 },
            SessionError::PrfFactorRequired => Self::NeedsHwKey,
            SessionError::HumanFactorRequired => Self::NeedsPassword,
            SessionError::Entropy => Self::Io,
            SessionError::CommitMismatch
            | SessionError::NoUsableWrap
            | SessionError::CiphertextTooLarge
            | SessionError::SignFailed
            | SessionError::StaleRevision
            | SessionError::HeaderMismatch
            | SessionError::ContentHashMismatch
            | SessionError::VaultMismatch
            | SessionError::WrapNotFound
            | SessionError::ZeroOrigin
            | SessionError::DeviceNotTrusted
            | SessionError::CertRejected
            | SessionError::CertExpired
            | SessionError::UnsupportedMsgVersion
            | SessionError::NotAWriter
            | SessionError::NotYours
            | SessionError::AttestationMismatch => Self::Denied,
        }
    }
}

/// Human text for a failed operation on an unlocked vault. The vault is
/// already open, so this is not an oracle; core messages carry no secrets.
#[must_use]
pub fn describe(error: &anyhow::Error) -> String {
    let Some(kind) = error.downcast_ref::<SessionError>() else {
        return format!("Failed: {error}");
    };
    String::from(match kind {
        SessionError::Rollback => "The vault file on disk is older than this session.",
        SessionError::Conflict => "The vault changed on disk. Lock and unlock to reload it.",
        SessionError::CommitMismatch => "The vault file failed its integrity check.",
        SessionError::PrfFactorRequired => "A hardware key must be present for this change.",
        SessionError::HumanFactorRequired => "The vault password is needed for this change.",
        SessionError::NoUsableWrap => "That would leave the vault without any unlock factor.",
        SessionError::CiphertextTooLarge => "The record is too large to sign.",
        SessionError::SignFailed => "Signing failed.",
        SessionError::StaleRevision => "Rejected: not newer than the stored revision.",
        SessionError::HeaderMismatch => "Rejected: frame header does not match its signature.",
        SessionError::ContentHashMismatch => "Rejected: content hash does not match.",
        SessionError::VaultMismatch => "Rejected: frame belongs to another vault.",
        SessionError::WrapNotFound => "A factor needed for this change is not on file.",
        SessionError::ZeroOrigin => "Rejected: frame has no signing device.",
        SessionError::DeviceNotTrusted => "Rejected: signing device is not trusted.",
        SessionError::CertRejected => "Rejected: device certificate is not valid.",
        SessionError::CertExpired => "Rejected: device certificate expired.",
        SessionError::UnsupportedMsgVersion => "Rejected: unsupported sync message version.",
        SessionError::Entropy => "The system random source failed.",
        SessionError::NotAWriter => "You can read this vault, not change it.",
        SessionError::NotYours => "Rejected: written by another device.",
        SessionError::AttestationMismatch => "Rejected: signature does not match the record.",
    })
}
