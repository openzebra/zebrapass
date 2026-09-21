//! Argon2id profiles and HKDF domain separation.

mod argon2;
mod error;
mod hkdf;
mod profile;

pub use argon2::argon2id;
pub use error::KdfError;
pub use hkdf::{derive_vault_keys, hkdf_sha512, INFO_DEVICE_WRAP};
pub use profile::KdfProfile;
