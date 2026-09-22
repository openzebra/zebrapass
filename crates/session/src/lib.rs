//! Vault create, unlock, and mutation session.
//!
//! This crate is the public API of the zebrapass workspace: depend only on
//! `session`. All other workspace crates are internal (`publish = false`);
//! types that appear in the API signatures (`VaultFile`, `KdfProfile`,
//! `BodyAlg`, device wrap types) are re-exported here so no internal crate
//! is required.

mod create;
mod devices;
mod error;
mod rotate;
mod unlock;

pub use aead::BodyAlg;
pub use container::VaultFile;
pub use create::{create, Session};
pub use devices::{add_device, remove_device};
pub use error::Seen;
pub use kdf::KdfProfile;
pub use rotate::{change_password, reencrypt_body, write_records};
pub use unlock::unlock;
pub use wraps::{DeviceGrant, DeviceKeys, DevicePublics};
