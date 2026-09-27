//! Document size and count limits.

/// Document schema version written by this build.
pub const SCHEMA_VERSION: u16 = 1;

/// Maximum number of fields in one document.
pub const MAX_FIELDS: usize = 4096;

/// Maximum encoded document size in bytes (1 MiB).
pub const MAX_DOC_LEN: usize = 1024 * 1024;

/// Maximum UTF-8 length of a custom field name.
pub const MAX_CUSTOM_NAME: usize = 64;
