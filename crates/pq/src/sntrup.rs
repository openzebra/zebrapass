//! sntrup1277 encapsulation and decapsulation.

use std::fmt;

use pqcrypto_ntruprime::sntrup1277::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use secret::Secret;
use zeroize::Zeroize;

/// Byte length of an sntrup1277 public key.
#[must_use]
pub const fn public_key_bytes() -> usize {
    sntrup1277::public_key_bytes()
}

/// Byte length of an sntrup1277 secret key.
#[must_use]
pub const fn secret_key_bytes() -> usize {
    sntrup1277::secret_key_bytes()
}

/// Byte length of an sntrup1277 ciphertext.
#[must_use]
pub const fn ciphertext_bytes() -> usize {
    sntrup1277::ciphertext_bytes()
}

/// A public key, secret key, ciphertext, or shared secret had the wrong length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqError {
    /// `pk` is not [`public_key_bytes`] long.
    PublicKeyLength,
    /// `sk` is not [`secret_key_bytes`] long.
    SecretKeyLength,
    /// `ct` is not [`ciphertext_bytes`] long.
    CiphertextLength,
    /// The library shared secret was not 32 bytes.
    SharedSecretLength,
}

impl fmt::Display for PqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyLength => {
                write!(
                    f,
                    "sntrup1277 public key must be {} bytes",
                    public_key_bytes()
                )
            }
            Self::SecretKeyLength => {
                write!(
                    f,
                    "sntrup1277 secret key must be {} bytes",
                    secret_key_bytes()
                )
            }
            Self::CiphertextLength => {
                write!(
                    f,
                    "sntrup1277 ciphertext must be {} bytes",
                    ciphertext_bytes()
                )
            }
            Self::SharedSecretLength => f.write_str("sntrup1277 shared secret must be 32 bytes"),
        }
    }
}

impl std::error::Error for PqError {}

/// Encapsulates a fresh 32-byte shared secret to `pk`.
///
/// The ciphertext is the raw sntrup1277 encoding.
///
/// # Errors
///
/// Returns [`PqError::PublicKeyLength`] when `pk` is not [`public_key_bytes`] long,
/// or [`PqError::SharedSecretLength`] when the library shared secret is not 32 bytes.
#[must_use = "dropping the shared secret discards the encapsulated key"]
pub fn encapsulate(pk: &[u8]) -> Result<(Secret<[u8; 32]>, Vec<u8>), PqError> {
    // Length is checked before the library so a short or long key never reaches C.
    if pk.len() != public_key_bytes() {
        return Err(PqError::PublicKeyLength);
    }
    let public_key = PublicKey::from_bytes(pk).map_err(|_| PqError::PublicKeyLength)?;
    let (shared, ciphertext) = sntrup1277::encapsulate(&public_key);
    let secret = copy_shared_secret(&shared)?;
    Ok((secret, ciphertext.as_bytes().to_vec()))
}

/// Decapsulates `ct` with `sk`.
///
/// A ciphertext of [`ciphertext_bytes`] always yields 32 bytes. sntrup1277 uses
/// implicit rejection, so a well-sized ciphertext is not an error even when it
/// was not produced for this secret key.
///
/// # Errors
///
/// Returns [`PqError::SecretKeyLength`] or [`PqError::CiphertextLength`] when
/// `sk` or `ct` has the wrong length. Those checks run before the library.
/// Returns [`PqError::SharedSecretLength`] when the library shared secret is
/// not 32 bytes.
#[must_use = "dropping the shared secret discards the decapsulated key"]
pub fn decapsulate(sk: &[u8], ct: &[u8]) -> Result<Secret<[u8; 32]>, PqError> {
    if sk.len() != secret_key_bytes() {
        return Err(PqError::SecretKeyLength);
    }
    if ct.len() != ciphertext_bytes() {
        return Err(PqError::CiphertextLength);
    }
    let secret_key = SecretKey::from_bytes(sk).map_err(|_| PqError::SecretKeyLength)?;
    let ciphertext = Ciphertext::from_bytes(ct).map_err(|_| PqError::CiphertextLength)?;
    let shared = sntrup1277::decapsulate(&ciphertext, &secret_key);
    copy_shared_secret(&shared)
}

fn copy_shared_secret(shared: &SharedSecret) -> Result<Secret<[u8; 32]>, PqError> {
    let bytes = shared.as_bytes();
    let array: [u8; 32] = bytes.try_into().map_err(|_| PqError::SharedSecretLength)?;
    Ok(Secret::new(array))
}

const _: () = assert!(public_key_bytes() == 2067);
const _: () = assert!(secret_key_bytes() == 3059);

/// Generates an sntrup1277 keypair.
///
/// The public key is [`public_key_bytes`] long (2067). The secret key is wiped
/// on drop.
///
/// # Errors
///
/// [`PqError::PublicKeyLength`] or [`PqError::SecretKeyLength`] when the
/// library output is not the sntrup1277 size.
#[allow(
    clippy::large_stack_arrays,
    reason = "sntrup1277 secret keys are 3059 bytes"
)]
#[must_use = "dropping the secret key discards the device key"]
pub fn keypair() -> Result<(Vec<u8>, Secret<[u8; 3059]>), PqError> {
    let (public, secret) = sntrup1277::keypair();
    let public_bytes = public.as_bytes();
    if public_bytes.len() != public_key_bytes() {
        return Err(PqError::PublicKeyLength);
    }
    let mut secret_key =
        <[u8; 3059]>::try_from(secret.as_bytes()).map_err(|_| PqError::SecretKeyLength)?;
    // `Secret::new` copies. Wipe this stack copy; the returned secret wipes on drop.
    let wrapped = Secret::new(secret_key);
    secret_key.zeroize();
    Ok((public_bytes.to_vec(), wrapped))
}
