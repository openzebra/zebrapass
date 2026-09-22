//! Vault create, unlock, and mutation session.

mod create;
mod devices;
mod error;
mod rotate;
mod unlock;

pub use create::{create, Session};
pub use devices::{add_device, remove_device};
pub use error::Seen;
pub use rotate::{change_password, reencrypt_body, write_records};
pub use unlock::unlock;
