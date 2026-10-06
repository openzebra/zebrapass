//! Bounds applied to every length parsed from the network.

use frame::{CASCADE_OVERHEAD, HEADER_LEN, MAX_FRAME_PLAINTEXT, TAG_LEN};

/// Largest sealed frame a record may carry.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_FRAME_PLAINTEXT + CASCADE_OVERHEAD + TAG_LEN;

/// Largest server origin a record may be addressed to.
pub const MAX_ORIGIN: usize = 267;

const _: () = assert!(MAX_FRAME <= u32::MAX as usize);
const _: () = assert!(MAX_ORIGIN <= u16::MAX as usize);
