//! Body AEAD: AEGIS-256 and Kuznyechik-CTR-HMAC.

mod aegis;
mod error;
mod kuz_ctr;

pub use error::{decrypt_body, encrypt_body, AeadError, BodyAlg};
