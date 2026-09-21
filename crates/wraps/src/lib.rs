//! Password and device wraps of the vault key.

// pqcrypto-internals 0.2.11 requires getrandom 0.3. OsRng here is getrandom 0.4.
#![allow(clippy::multiple_crate_versions)]

mod device;
mod error;
mod grant;
mod password;
mod wad;

pub use device::{open_device, seal_device, DeviceKeys, DevicePublics};
pub use error::WrapError;
pub use grant::DeviceGrant;
pub use password::{open_password, seal_password};
