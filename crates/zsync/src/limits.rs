//! Bounds and protocol limits for `zsync`. Every wire length and count is
//! checked against these constants before allocating memory.

use std::time::Duration;

/// Magic header for every binary `zsync` frame (`ZBS3`).
pub const WIRE_MAGIC: [u8; 4] = *b"ZBS3";

/// Current binary protocol version.
pub const WIRE_VERSION: u8 = 2;

/// Largest single binary protocol frame (16 MiB).
pub const MAX_WIRE_FRAME: usize = 16 << 20;

/// Largest small control/frontier frame (512 KiB).
pub const MAX_SMALL_FRAME: usize = 512 << 10;

/// Largest outer-sealed envelope (12 MiB).
pub const MAX_ENVELOPE_BYTES: usize = 12 << 20;

/// Maximum records reconciled per frontier/delta exchange.
pub const MAX_RECORDS_PER_MSG: usize = 4096;

/// Maximum total records stored in one repository.
pub const MAX_REPO_RECORDS: usize = 65_536;

/// Maximum device certificates per repository.
pub const MAX_CERTS_PER_REPO: usize = 32;

/// Maximum revocations per repository.
pub const MAX_REVS_PER_REPO: usize = 64;

/// Maximum member log entries per shared repository.
pub const MAX_MEMBERS_PER_REPO: usize = 256;

/// Maximum rekey grants per repository.
pub const MAX_REKEYS_PER_REPO: usize = 64;

/// Maximum watched repositories per live watch stream.
pub const MAX_WATCH_REPOS: usize = 64;

/// Maximum repositories exchanged in a single mesh digest page.
pub const MAX_MESH_PAGE: usize = 1024;

/// Maximum repository identifiers sent in one mesh need batch.
pub const MAX_MESH_REPOS: usize = 16_384;

/// Maximum concurrent TLS connections accepted by a server.
pub const MAX_CONNS: usize = 512;

/// Maximum concurrent TLS connections accepted from one IP address.
pub const MAX_CONNS_PER_IP: usize = 64;

/// Maximum active relay slot reservations from one IP address.
pub const MAX_RESERVES_PER_IP: usize = 16;

/// Maximum relay connect attempts per IP address per 60-second window.
pub const MAX_CONNECTS_PER_MIN: u32 = 32;

/// Maximum entries tracked in the server-side anti-replay nonce cache.
pub const REPLAY_CAPACITY: usize = 8192;

/// Maximum initial revision number accepted when creating a new record on a server.
pub const MAX_INITIAL_REVISION: u64 = 1_000_000;

/// Maximum revision increment accepted in a single record update on a server.
pub const MAX_REVISION_STEP: u64 = 1024;

/// Hard ceiling keeping accepted revisions far away from `u64::MAX` overflow.
pub const MAX_SAFE_REVISION: u64 = 1u64 << 52;

/// Network connect / frame read-write timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum active relay slot reservations on a server.
pub const MAX_RELAY_SLOTS: usize = 1024;

/// Default relay reservation TTL in seconds.
pub const RELAY_TTL_SECS: u16 = 300;

/// Wait window for a relay slot holder to accept an incoming connection.
pub const RELAY_PENDING_SECS: u64 = 10;

/// Maximum bytes transferred in one relayed P2P session (64 MiB).
pub const RELAY_MAX_BYTES: u64 = 64 << 20;

/// Maximum clock skew accepted on signed watch requests (5 minutes).
pub const WATCH_MAX_SKEW_SECS: u64 = 300;

/// Maximum certificates loaded from `--extra-ca` PEM input.
pub const MAX_EXTRA_CERTS: usize = 32;
