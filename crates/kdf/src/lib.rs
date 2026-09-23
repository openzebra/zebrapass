//! Argon2id profiles and HKDF domain separation.

mod argon2;
mod derive;
mod hkdf;
mod profile;

pub use argon2::argon2id;
pub use derive::{frame_key, identity_seed, local_meta_key, INFO_FRAME_KEY, INFO_IDENTITY, INFO_LOCAL_META};
pub use hkdf::{derive_vault_keys, hkdf_sha512, INFO_CHIP_WRAP, INFO_DEVICE_WRAP, INFO_PRF_WRAP};
pub use profile::KdfProfile;
