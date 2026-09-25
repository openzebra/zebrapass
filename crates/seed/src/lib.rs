//! BIP39 seed phrases and the identity derived from them.
//!
//! The seed phrase is the master factor of a vault: the phrase validates
//! and normalizes into its 64-byte BIP39 seed, and the same seed yields
//! the same identity point on every device.

mod en_words;
mod identity;
mod phrase;
mod rng;

pub use identity::user_id;

/// Opaque 64-byte sync client id. Not [`user_id`]: that value is a P-256 point, not an authenticator.
pub use kdf::client_id;
pub use phrase::SeedPhrase;
pub use rng::OsFill;
