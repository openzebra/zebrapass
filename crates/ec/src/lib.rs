//! P-256 helpers shared by the wraps and platform crates.
//!
//! Software-side elliptic-curve utilities: OS-RNG key generation, SEC1
//! encoding/decoding of uncompressed points, and the raw 32-byte ECDH
//! shared secret. Nothing here touches vault keys or wraps; callers keep
//! ownership of all key material.

use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
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
    use super::{decode_pub, encode_pub, fresh_pair, shared};
    use p256::elliptic_curve::sec1::ToSec1Point;

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
}
