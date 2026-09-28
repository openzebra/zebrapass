//! Bounds on untrusted import input, checked before memory is allocated.

/// Most items one import may produce.
pub const MAX_ITEMS: usize = 20_000;

/// Longest single field value, in bytes. Longer values skip the item.
pub const MAX_FIELD: usize = 60 * 1024;

/// Most custom fields per item. More skip the item.
pub const MAX_CUSTOM: usize = 64;

const _: () = assert!(MAX_FIELD <= u16::MAX as usize);
const _: () = assert!(MAX_ITEMS == session::MAX_BATCH);

/// Largest export file read, in bytes.
pub const MAX_IMPORT_FILE: u64 = 64 * 1024 * 1024;

/// Deepest XML nesting read.
pub const MAX_XML_DEPTH: usize = 64;

/// Most CSV columns.
pub const MAX_CSV_COLUMNS: usize = 64;

/// Largest Argon2 memory a `KeePass` database may ask for, in bytes
/// (the vault's own Strong profile).
pub const MAX_KDBX_ARGON2_MEMORY: u64 = 1 << 30;

/// Most Argon2 passes a `KeePass` database may ask for.
pub const MAX_KDBX_ARGON2_ITERATIONS: u64 = 256;

/// Most Argon2 lanes a `KeePass` database may ask for.
pub const MAX_KDBX_ARGON2_LANES: u32 = 16;

/// Largest Argon2 memory × passes, in MiB: 1 GiB × 16 or 64 MiB × 256.
pub const MAX_KDBX_ARGON2_WORK_MIB: u64 = 16 * 1024;

/// Most AES-KDF rounds a `KeePass` database may ask for.
pub const MAX_KDBX_AES_ROUNDS: u64 = 300_000_000;
