//! BIP39 seed phrases and the local identity derived from them.
//!
//! The seed phrase is the master factor of a vault: the phrase validates
//! and normalizes into its 64-byte BIP39 seed, and the same seed yields
//! the same identity point on every device. The server-visible client id
//! lives in [`kdf`], not here.

mod en_words;
mod identity;
mod phrase;
mod rng;

pub use identity::ec_identity_pk;

/// Opaque 64-byte sync client id. Not [`ec_identity_pk`]: that value is a P-256 point, not an authenticator.
pub use kdf::client_id;
pub use phrase::SeedPhrase;
pub use rng::OsFill;
