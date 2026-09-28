//! Adapter over `session`, `local`, and `seed`. No cryptography lives here:
//! every key operation is a core call.

pub mod chip;
pub mod create;
pub mod discover;
pub mod error;
pub mod factors;
pub mod limits;
pub mod open;
pub mod ops;
pub mod records;
pub mod sync;
pub mod sync_file;

pub use open::Vault;
