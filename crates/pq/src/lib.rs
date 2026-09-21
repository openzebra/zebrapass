//! sntrup1277 key encapsulation.

mod sntrup;

#[cfg(test)]
mod kat;

pub use sntrup::{
    ciphertext_bytes, decapsulate, encapsulate, public_key_bytes, secret_key_bytes, PqError,
};
