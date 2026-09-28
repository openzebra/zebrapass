//! Bounds on untrusted input the TUI reads itself. Every length and count
//! from a file is checked against these before memory is allocated.

/// Largest vault file the TUI will read (the container has no own cap; a
/// full record log at the per-record limits stays far below this).
pub const MAX_VAULT_FILE: u64 = 512 * 1024 * 1024;

/// Most vault directories listed under the data directory.
pub const MAX_VAULTS: usize = 256;

/// Longest vault display name, in bytes.
pub const MAX_VAULT_NAME: usize = 64;

/// Longest path typed into a file field, in bytes.
pub const MAX_PATH_INPUT: usize = 4096;
