//! Device shared-secret encryption with `ntrulp` (`ntrup1277` + `std`).
//!
//! `ntrulp` encrypts bytes under a public key. It is not the fixed-size
//! sntrup1277 KEM. A 32-byte shared secret is encrypted, and the ciphertext
//! length is whatever `bytes_encrypt` returns.

use ntrulp::key::priv_key::PrivKey;
use ntrulp::key::pub_key::PubKey;
use ntrulp::ntru::std_cipher::{bytes_decrypt, bytes_encrypt};
use ntrulp::params::params::{PUBLICKEYS_BYTES, SECRETKEYS_BYTES};
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::rng::{random_small, short_random};
use secret::Secret;
use zeroize::Zeroize;

/// Public key length for this `ntrulp` build (`P * 2` = 2554 when `P` is 1277).
pub const PQ_PK_LEN: usize = PUBLICKEYS_BYTES;

/// Secret key length for this `ntrulp` build (`R3_BYTES * 2` = 640).
pub const PQ_SK_LEN: usize = SECRETKEYS_BYTES;

const KEYGEN_TRIES: usize = 64;

/// Byte length of an `ntrulp` public key.
#[must_use]
pub const fn public_key_bytes() -> usize {
    PQ_PK_LEN
}

/// Byte length of an `ntrulp` secret key.
#[must_use]
pub const fn secret_key_bytes() -> usize {
    PQ_SK_LEN
}

/// Encrypts a fresh 32-byte shared secret to `pk`.
///
/// # Errors
///
/// `ntrulp public key must be 2554 bytes` when `pk` has the wrong length.
/// `os entropy failed` when the OS RNG fails.
/// `ntrulp decrypt failed` when `ntrulp` rejects the encryption.
pub fn encrypt_shared(pk: &[u8]) -> anyhow::Result<(Secret<[u8; 32]>, Vec<u8>)> {
    let mut plain = random_shared()?;
    let ciphertext = encrypt(pk, &plain)?;
    let secret = Secret::new(plain);
    plain.zeroize();
    Ok((secret, ciphertext))
}

/// Decrypts a shared secret produced by [`encrypt_shared`].
///
/// # Errors
///
/// `ntrulp secret key must be 640 bytes` when `sk` has the wrong length.
/// `ntrulp decrypt failed` when `ntrulp` rejects the ciphertext.
/// `ntrulp shared secret must be 32 bytes` when the plaintext is not 32 bytes.
pub fn decrypt_shared(sk: &[u8], ciphertext: &[u8]) -> anyhow::Result<Secret<[u8; 32]>> {
    let opened = decrypt(sk, ciphertext)?;
    let bytes = <[u8; 32]>::try_from(opened.as_slice()).map_err(|_| anyhow::anyhow!("ntrulp shared secret must be 32 bytes"))?;
    Ok(Secret::new(bytes))
}

/// Generates an `ntrulp` keypair. The secret key is wiped on drop.
///
/// # Errors
///
/// `ntrulp key generation failed` when `short_random` fails or `PrivKey::compute` does not
/// succeed within [`KEYGEN_TRIES`].
#[allow(
    clippy::large_stack_arrays,
    reason = "sntrup1277 public and secret keys are fixed stack arrays"
)]
pub fn keypair() -> anyhow::Result<(Vec<u8>, Secret<[u8; PQ_SK_LEN]>)> {
    let mut rng = rand::rng();
    let f = Rq::from(short_random(&mut rng).map_err(|_| anyhow::anyhow!("ntrulp key generation failed"))?);
    let mut g = R3::from(random_small(&mut rng));
    let mut secret = None;
    for _ in 0..KEYGEN_TRIES {
        g = R3::from(random_small(&mut rng));
        if let Ok(priv_key) = PrivKey::compute(&f, &g) {
            secret = Some(priv_key);
            break;
        }
    }
    let Some(secret) = secret else {
        return Err(anyhow::anyhow!("ntrulp key generation failed"));
    };
    let public = PubKey::compute(&f, &g).map_err(|_| anyhow::anyhow!("ntrulp key generation failed"))?;
    Ok((public.to_bytes().to_vec(), Secret::new(secret.to_bytes())))
}

fn random_shared() -> anyhow::Result<[u8; 32]> {
    let mut plain = [0u8; 32];
    getrandom::fill(&mut plain).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok(plain)
}

fn encrypt(pk: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if pk.len() != PQ_PK_LEN {
        return Err(anyhow::anyhow!("ntrulp public key must be {PQ_PK_LEN} bytes"));
    }
    let bytes = <[u8; PQ_PK_LEN]>::try_from(pk).map_err(|_| anyhow::anyhow!("ntrulp public key must be {PQ_PK_LEN} bytes"))?;
    let mut rng = rand::rng();
    bytes_encrypt(&mut rng, plaintext, PubKey::import(&bytes))
        .map_err(|_| anyhow::anyhow!("ntrulp encrypt failed"))
}

fn decrypt(sk: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if sk.len() != PQ_SK_LEN {
        return Err(anyhow::anyhow!("ntrulp secret key must be {PQ_SK_LEN} bytes"));
    }
    let bytes = <[u8; PQ_SK_LEN]>::try_from(sk).map_err(|_| anyhow::anyhow!("ntrulp secret key must be {PQ_SK_LEN} bytes"))?;
    let secret = PrivKey::import(&bytes).map_err(|_| anyhow::anyhow!("ntrulp secret key must be {PQ_SK_LEN} bytes"))?;
    bytes_decrypt(ciphertext, secret).map_err(|_| anyhow::anyhow!("ntrulp decrypt failed"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::large_stack_arrays)]
mod tests {
    use super::{decrypt_shared, encrypt_shared, keypair, public_key_bytes, secret_key_bytes, PQ_PK_LEN, PQ_SK_LEN};

    #[test]
    fn lengths_match_sntrup1277() {
        assert_eq!(public_key_bytes(), 2554);
        assert_eq!(secret_key_bytes(), 640);
        assert_eq!(PQ_PK_LEN, 2554);
        assert_eq!(PQ_SK_LEN, 640);
    }

    #[test]
    fn rejects_wrong_key_lengths() {
        let err = encrypt_shared(&[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("ntrulp public key must be {PQ_PK_LEN} bytes")
        );
        let err = decrypt_shared(&[], &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("ntrulp secret key must be {PQ_SK_LEN} bytes")
        );
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let (pk, sk) = keypair().unwrap();
        let (shared, ciphertext) = encrypt_shared(&pk).unwrap();
        let opened = decrypt_shared(sk.expose(), &ciphertext).unwrap();
        assert_eq!(shared.expose(), opened.expose());
    }
}
