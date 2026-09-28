//! Bounds on untrusted or user-supplied local inputs.

use std::ops::RangeInclusive;

/// Accepted device PIN length in bytes.
pub const DEVICE_PIN_LEN: RangeInclusive<usize> = 6..=128;
