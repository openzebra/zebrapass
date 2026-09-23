//! P-256 helpers shared by the wraps and platform crates.
//!
//! Software-side elliptic-curve utilities: OS-RNG key generation, SEC1
//! encoding/decoding of uncompressed points, and the raw 32-byte ECDH
//! shared secret. Nothing here touches vault keys or wraps; callers keep
//! ownership of all key material.

use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use secret::Secret;
use zeroize::Zeroize;

/// Draw a software P-256 key pair from the OS RNG.
///
/// # Errors
///
/// `os entropy failed` when the OS RNG fails or no valid scalar is drawn
/// in eight attempts (virtually impossible for a 256-bit curve).
pub fn fresh_pair() -> anyhow::Result<(SecretKey, PublicKey)> {
    // Scalars are 32 random bytes; almost every draw is a valid secret key.
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
        let key = SecretKey::from_bytes(&bytes.into());
        bytes.zeroize();
        if let Ok(sk) = key {
            let pk = sk.public_key();
            return Ok((sk, pk));
        }
    }
    Err(anyhow::anyhow!("os entropy failed"))
}

/// Encode an uncompressed 65-byte public key (`0x04`-prefixed).
///
/// # Errors
///
/// `kem length` when the encoded point is not 65 bytes.
pub fn encode_pub(key: &PublicKey) -> anyhow::Result<[u8; 65]> {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!("kem length"));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Decode an uncompressed 65-byte public key.
///
/// # Errors
///
/// `kem length` when `bytes` is not a valid uncompressed P-256 point.
pub fn decode_pub(bytes: &[u8; 65]) -> anyhow::Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| anyhow::anyhow!("kem length"))
}

/// Derive a P-256 key pair from a 32-byte scalar.
///
/// The point is returned as 64 bytes: the SEC1 encoding without the
/// `0x04` prefix, that is `x ‖ y`. This is a derivation step for the
/// identity point, not key generation: the scalar comes from a KDF, not
/// from the RNG.
///
/// # Errors
///
/// `kem length` when the scalar is zero or not below the curve order.
pub fn pair_from_scalar(scalar: &Secret<[u8; 32]>) -> anyhow::Result<(SecretKey, [u8; 64])> {
    let sk = SecretKey::from_bytes(&(*scalar.expose()).into())
        .map_err(|_| anyhow::anyhow!("kem length"))?;
    let encoded = encode_pub(&sk.public_key())?;
    let mut point = [0u8; 64];
    let body = encoded.get(1..).ok_or_else(|| anyhow::anyhow!("kem length"))?;
    point.copy_from_slice(body);
    let mut encoded = encoded;
    encoded.zeroize();
    Ok((sk, point))
}

/// Raw 32-byte ECDH shared secret (the X coordinate).
#[must_use]
pub fn shared(sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let ss = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let raw = ss.raw_secret_bytes();
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(raw.iter()) {
        *dst = *src;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
mod tests {
    use super::{decode_pub, encode_pub, fresh_pair, pair_from_scalar, shared};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use secret::Secret;

    #[test]
    fn ecdh_is_symmetric_over_encoded_points() {
        let (sk_a, pk_a) = fresh_pair().unwrap();
        let (sk_b, pk_b) = fresh_pair().unwrap();
        let ab = shared(&sk_a, &pk_b);
        let ba = shared(&sk_b, &pk_a);
        assert_eq!(ab, ba);
        // Encoding round trip preserves the point.
        let decoded = decode_pub(&encode_pub(&pk_a).unwrap()).unwrap();
        assert_eq!(
            decoded.to_sec1_point(false).as_ref(),
            pk_a.to_sec1_point(false).as_ref()
        );
    }

    #[test]
    fn pair_from_scalar_is_deterministic_and_checked() {
        let scalar = Secret::new([7u8; 32]);
        let (sk, point) = pair_from_scalar(&scalar).unwrap();
        let expected = encode_pub(&sk.public_key()).unwrap();
        assert_eq!(point, <[u8; 64]>::try_from(&expected[1..]).unwrap());
        let again = pair_from_scalar(&scalar).unwrap();
        assert_eq!(point, again.1);
        // The zero scalar is not a valid secret key.
        let zero = Secret::new([0u8; 32]);
        assert_eq!(pair_from_scalar(&zero).unwrap_err().to_string(), "kem length");
        // A scalar at the curve order is rejected too.
        let n = Secret::new([
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ]);
        assert!(pair_from_scalar(&n).is_err());
    }
}
