//! Revision frames: the unit of record history inside the vault body.
//!
//! A frame seals one document revision with AEGIS-256 under a per-record
//! key derived from the vault key. Unknown frame kinds and algorithms are
//! preserved byte for byte on a body rewrite: the index records their wire
//! shape without interpreting it.

mod header;
mod index;
mod limits;
mod seal;

pub use header::{aad, encode_header, parse, FrameMeta, Header, DOMAIN_FRAME, HEADER_LEN};
pub use index::{frame_at, latest, parse_index, FrameRef};
pub use limits::MAX_FRAME_PLAINTEXT;
pub use seal::{open, seal};

/// Frame kind: a record revision. Plaintext is an encoded document.
pub const KIND_REVISION: u8 = 1;

/// Frame kind: a deletion marker. Plaintext is empty.
pub const KIND_TOMBSTONE: u8 = 2;

/// Frame algorithm: AEGIS-256 with a 32-byte tag (`0xA001`).
pub const ALG_AEGIS256: u16 = 0xA001;

/// AEGIS-256 tag length in bytes.
pub const TAG_LEN: usize = 32;
