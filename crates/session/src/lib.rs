//! Vault create, unlock, and mutation session.

// pqcrypto-internals 0.2.11 (via wraps) requires getrandom 0.3. OsRng here is getrandom 0.4.
#![allow(clippy::multiple_crate_versions)]

mod create;
mod devices;
mod error;
mod rotate;
mod unlock;

pub use create::{create, Session};
pub use devices::{add_device, remove_device};
pub use error::{Seen, VaultV2Error};
pub use rotate::{change_password, reencrypt_body, write_records};
pub use unlock::unlock;
