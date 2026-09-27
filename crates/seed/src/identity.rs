//! P-256 identity point derived from the master seed.
//!
//! The client id this point once served as is now [`kdf::client_id`], a
//! uniform HKDF output; see that function for why a curve point must not
//! be sent to servers.

use kdf::identity_seed;

/// The local identity of `seed`: a P-256 point encoded as 64 bytes
/// (`x ‖ y`, no `0x04` prefix).
///
/// The scalar is `HKDF-SHA512(ikm = seed, salt = none, info =
/// zebrapass/identity/v1)`, so the same seed phrase yields the same
/// point on every device. Keep this value on the device: P-256 falls to
/// Shor's algorithm, and a recorded point lets a quantum attacker
/// recover the seed-derived scalar. Never transmit it, and never use it
/// as a server-visible id — derive [`kdf::client_id`] for that.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length;
/// `kem length` when the derived scalar is not a valid P-256 secret key
/// (practically impossible for a 256-bit HKDF output).
pub fn ec_identity_pk(seed: &[u8; 64]) -> anyhow::Result<[u8; 64]> {
    let scalar = identity_seed(seed)?;
    let (_sk, point) = ec::pair_from_scalar(&scalar)?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::ec_identity_pk;

    #[test]
    fn identity_is_deterministic_per_seed() {
        let a = ec_identity_pk(&[1u8; 64]).unwrap();
        let b = ec_identity_pk(&[1u8; 64]).unwrap();
        assert_eq!(a, b);
        let other = ec_identity_pk(&[2u8; 64]).unwrap();
        assert_ne!(a, other);
        // Two distinct seeds must not collapse onto one point.
        assert_ne!(a, [0u8; 64]);
    }
}
