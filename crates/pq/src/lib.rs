//! ntrulp encryption for a device wrap.

mod ntrup;

pub use ntrup::{
    decrypt_shared, encrypt_shared, keypair, public_key_bytes, secret_key_bytes, PQ_PK_LEN,
    PQ_SK_LEN,
};
