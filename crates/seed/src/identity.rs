//! Identity point derived from the master seed.

use kdf::identity_seed;

/// The identity of `seed`: a P-256 point encoded as 64 bytes (`x ‖ y`,
/// no `0x04` prefix).
///
/// The scalar is `HKDF-SHA512(ikm = seed, salt = none, info =
/// zebrapass/identity/v1)`, so the same seed phrase yields the same
/// identity on every device. This is a derivation identifier, not an
/// authentication mechanism.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length;
/// `kem length` when the derived scalar is not a valid P-256 secret key
/// (practically impossible for a 256-bit HKDF output).
pub fn user_id(seed: &[u8; 64]) -> anyhow::Result<[u8; 64]> {
    let scalar = identity_seed(seed)?;
    let (_sk, point) = ec::pair_from_scalar(&scalar)?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::user_id;

    #[test]
    fn identity_is_deterministic_per_seed() {
        let a = user_id(&[1u8; 64]).unwrap();
        let b = user_id(&[1u8; 64]).unwrap();
        assert_eq!(a, b);
        let other = user_id(&[2u8; 64]).unwrap();
        assert_ne!(a, other);
        // Two distinct seeds must not collapse onto one point.
        assert_ne!(a, [0u8; 64]);
    }
}
