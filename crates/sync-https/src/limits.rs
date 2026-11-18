//! Protocol, chunking, replay, and memory bounds for `sync-https`.

/// Hard maximum byte length of a single uploaded/stored transfer chunk (`12 KiB`).
pub const SPLIT_CHUNK_MAX: usize = 12_288;

/// Client `SplitHTTP` chunk payload ceiling (`6 KiB`).
///
/// With a `3_309`-byte `ML-DSA-65` signature, compact HTTP headers, and a
/// fresh PQ TLS 1.3 (`X25519MLKEM768`) handshake on `Connection: close`, each
/// `SplitHTTP` TCP connection stays below typical `15.5–20 KB` DPI byte caps.
pub const SPLIT_TRANSFER_CHUNK: usize = 6_144;

/// Maximum inbound/outbound HTTP header section length in bytes.
pub const MAX_HTTP_HEADER: usize = 8_192;

/// Maximum single HTTP request or response body length in bytes.
pub const MAX_HTTP_BODY: usize = 32_768;

/// Maximum single WebSocket binary frame payload length in bytes.
pub const MAX_WS_FRAME: usize = 16_384;

/// Maximum snapshot head metadata envelope length in bytes.
pub const MAX_HEAD_META: usize = 4_096;

/// Maximum assembled opaque envelope payload stored per object (`16 MiB`).
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum chunks per vault snapshot upload.
pub const MAX_SNAPSHOT_CHUNKS: u32 = 8_192;

/// Maximum retained frames per mailbox append log.
pub const MAX_FRAMES_LOG: usize = 16_384;

/// Maximum frames returned in one `StateQuery` page.
pub const MAX_STATE_FRAMES_PAGE: usize = 32;

/// Maximum rekey grant blobs retained per mailbox.
pub const MAX_REKEYS: usize = 128;

/// Maximum revocations retained per mailbox.
pub const MAX_REVOCATIONS: usize = 256;

/// Maximum signed member log entries retained per shared mailbox.
pub const MAX_MEMBER_ENTRIES: usize = 1_024;

/// Maximum certified devices cached per mailbox.
pub const MAX_MAILBOX_DEVICES: usize = 128;

/// Maximum pending unanchored device certs cached in memory per server.
pub const MAX_PENDING_CERTS: usize = 256;

/// Maximum staging chunk uploads open concurrently in a mailbox.
pub const MAX_STAGED_UPLOADS: usize = 32;

/// Maximum chunks per cloud backup upload (`6_144 * 16_384` = 96 MiB).
pub const MAX_BACKUP_CHUNKS: u32 = 16_384;

/// Maximum subscribed mailbox ids on one WebSocket connection.
pub const MAX_SUB_BOXES: usize = 64;

/// Maximum distinct endpoint hosts / URLs allowed in one client.
pub const MAX_ENDPOINTS: usize = 8;

/// Maximum recent nonces tracked per server for replay protection.
pub const MAX_NONCE_CACHE: usize = 4_096;

/// Allowed clock skew around server wall time in seconds.
pub const MAX_TIME_SKEW_SECS: u64 = 300;

/// Maximum concurrent active connections handled by the server.
pub const MAX_CONNECTIONS: usize = 256;

/// Network read/write/connect timeout in seconds.
pub const IO_TIMEOUT_SECS: u64 = 15;

/// Minimum length of the `WebTunnel` camouflage URL secret path slug.
pub const MIN_SECRET_SLUG_LEN: usize = 16;

/// Maximum length of the `WebTunnel` camouflage URL secret path slug.
pub const MAX_SECRET_SLUG_LEN: usize = 128;

/// Maximum encoded HTTP request origin string stored in signed operations.
pub const MAX_ORIGIN_LEN: usize = 256;
