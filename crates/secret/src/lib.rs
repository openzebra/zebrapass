//! Zeroizing secrets and constant-time equality.

mod ct_eq;
mod secret;

pub use ct_eq::{ct_eq, ct_eq_32};
pub use secret::Secret;
