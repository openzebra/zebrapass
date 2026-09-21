//! sntrup1277 key encapsulation.

mod sntrup;

#[cfg(test)]
mod kat;

pub use sntrup::{
    ciphertext_bytes, decapsulate, encapsulate, keypair, public_key_bytes, secret_key_bytes,
    PqError,
};
