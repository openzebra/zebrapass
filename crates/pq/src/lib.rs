//! ML-KEM-768 encapsulation for device and chip wraps.

mod kem;
mod sign;

pub use kem::{
    kem_decapsulate as decrypt_shared, kem_encapsulate as encrypt_shared, kem_keypair as keypair,
    KEM_CT_LEN, KEM_DK_LEN as PQ_SK_LEN, KEM_EK_LEN as PQ_PK_LEN,
};

/// Encapsulation-key length. Kept so existing call sites do not hard-code a number.
#[must_use]
pub const fn public_key_bytes() -> usize {
    PQ_PK_LEN
}

/// Decapsulation-key length.
#[must_use]
pub const fn secret_key_bytes() -> usize {
    PQ_SK_LEN
}

pub use sign::{
    signing_key_from_seed, sync_sign, sync_verify, sync_verifying_key, verifying_key_of,
    SigningKeyMirror, DEVICE_CERT_CTX, SYNC_CTX, SYNC_SEED_LEN, SYNC_SIG_LEN, SYNC_VK_LEN,
};
