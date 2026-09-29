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

/// Most records with saved copy usage (16 bytes each).
pub const USAGE_MAX: usize = 512;
