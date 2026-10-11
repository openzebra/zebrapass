//! Adapter over `session`, `local`, and `seed`. No cryptography lives here:
//! every key operation is a core call.

pub mod adopt;
pub mod create;
pub mod device;
pub mod discover;
pub mod error;
pub mod factors;
pub mod limits;
pub mod open;
pub mod ops;
pub mod records;
pub mod shared;

pub use open::Vault;
