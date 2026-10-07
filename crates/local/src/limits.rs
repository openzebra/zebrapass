//! Bounds on untrusted or user-supplied local inputs.

use std::ops::RangeInclusive;

/// Accepted device PIN length in bytes.
pub const DEVICE_PIN_LEN: RangeInclusive<usize> = 6..=128;

/// Accepted auto-lock delay in seconds.
pub const LOCK_AFTER_S: RangeInclusive<u16> = 30..=3600;

/// Accepted clipboard clear delay in seconds.
pub const CLIP_CLEAR_S: RangeInclusive<u8> = 5..=90;

/// Accepted reveal auto-hide delay in seconds.
pub const REVEAL_HIDE_S: RangeInclusive<u8> = 3..=30;

/// Longest accepted sync server origin in bytes (`https://` + a DNS name +
/// a port).
pub const ORIGIN_MAX: usize = 8 + 253 + 6;

/// Longest name of a shared vault in bytes.
pub const SHARED_NAME_MAX: usize = 64;

/// Most address hints kept for a shared vault.
pub const SHARED_HINTS_MAX: usize = 4;

/// Longest address hint in bytes.
pub const SHARED_HINT_MAX: usize = 64;

/// Most records of a shared vault with a stored attestation.
pub const ATTESTATIONS_MAX: usize = 4096;

/// Most peer devices kept in the sync identity file.
pub const PEERS_MAX: usize = record::SYNC_PEER_TAGS;

/// Most signed peer address records kept per shared vault.
pub const SHARED_PEERS_MAX: usize = syncwire::MAX_PEERS;

/// Most signed revocations kept per vault.
pub const REVOKED_MAX: usize = record::SYNC_REVOKED_TAGS;

/// Most records with a saved last-seen revision (12 bytes each).
pub const LAST_SEEN_MAX: usize = record::SYNC_LAST_SEEN_TAGS * record::SYNC_LAST_SEEN_PER_TAG;

/// Most records with saved copy usage (16 bytes each).
pub const USAGE_MAX: usize = 512;

const _: () = assert!(
    LAST_SEEN_MAX * 12
        + PEERS_MAX * syncwire::CERT_WIRE_LEN
        + REVOKED_MAX * syncwire::REVOCATION_WIRE_LEN
        + 8192
        < record::MAX_DOC_LEN
);
