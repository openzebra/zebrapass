//! Bounds applied to every length parsed from the network.

use frame::{CASCADE_OVERHEAD, HEADER_LEN, MAX_FRAME_PLAINTEXT, TAG_LEN};

/// Largest sealed frame a record may carry.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_FRAME_PLAINTEXT + CASCADE_OVERHEAD + TAG_LEN;

/// Largest server origin a record may be addressed to.
pub const MAX_ORIGIN: usize = 267;

const _: () = assert!(MAX_FRAME <= u32::MAX as usize);
const _: () = assert!(MAX_ORIGIN <= u16::MAX as usize);

/// Length of a mux message header: type, request number, payload length.
pub const MUX_HEADER_LEN: usize = 1 + 4 + 4;

/// Requests a peer may have unanswered on one connection.
pub const PIPELINE_DEPTH: usize = 4;

/// Bytes of a snapshot or member log carried by one chunk.
pub const CHUNK_LEN: usize = 64 * 1024;

/// Largest vault file a snapshot may name.
pub const MAX_SNAPSHOT_LEN: u64 = 512 << 20;

/// Largest member log a peer may name.
pub const MAX_LOG_LEN: u64 = 16 << 20;

/// Exact length of a rekey reply: a 64-byte seed and a 4-byte epoch.
pub const REKEY_LEN: usize = 64 + 4;

/// Largest revision a peer may carry: an attestation and a sealed frame.
pub const MAX_BUNDLE: usize = crate::ATTESTATION_WIRE_LEN + MAX_FRAME;

/// Largest frontier a peer may send.
pub const MAX_FRONTIER_PAYLOAD: usize = crate::MAX_FRONTIER * 32 + 8;

/// Largest list of peer records a peer may send.
pub const MAX_PEERS_PAYLOAD: usize =
    8 + crate::MAX_PEERS * (16 + 8 + 1 + 4 * 65 + crate::CERT_WIRE_LEN + session::SYNC_SIG_LEN);

const _: () = assert!(MUX_HEADER_LEN == 9);
const _: () = assert!(MAX_SNAPSHOT_LEN <= u64::MAX / 2);
