// Module name shadows the `argon2` crate.
extern crate argon2 as argon2_impl;

use argon2_impl::{Algorithm, Argon2, Params, Version};
use secret::Secret;

use crate::error::KdfError;

/// OWASP Argon2id minimum: 19 MiB, two iterations, one lane.
const M_KIB_FLOOR: u32 = 19_456;
const T_FLOOR: u32 = 2;
const P_FLOOR: u32 = 1;

/// Header fields are untrusted `u32`s. Past this, Argon2 would allocate.
const M_KIB_CEILING: u32 = 1_048_576;
const T_CEILING: u32 = 16;
const P_CEILING: u32 = 16;

const OUTPUT_LEN: usize = 32;

/// Derives a 32-byte Argon2id key.
///
/// Version is `0x13`. The secret and associated data are empty. `salt` is the
/// caller-supplied 32-byte salt, not an application constant.
///
/// # Errors
///
/// [`KdfError::KdfParamsRejected`] when `m_kib`, `t`, or `p` is outside the
/// floor (`m_kib >= 19456`, `t >= 2`, `p >= 1`) or the ceiling
/// (`m_kib <= 1048576`, `t <= 16`, `p <= 16`). Those inputs are rejected
/// before Argon2 runs. The same error is returned when Argon2 itself rejects
/// the inputs.
/// [`KdfError::EmptyPassword`] when `password` is empty. Argon2 is not called.
pub fn argon2id(
    password: &[u8],
    salt: &[u8; 32],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Secret<[u8; OUTPUT_LEN]>, KdfError> {
    // `Params::new` accepts `m_kib` up to `u32::MAX` and the hash then
    // allocates that many kibibytes. Reject before either step.
    let in_range = (M_KIB_FLOOR..=M_KIB_CEILING).contains(&m_kib)
        && (T_FLOOR..=T_CEILING).contains(&t)
        && (P_FLOOR..=P_CEILING).contains(&p);
    if !in_range {
        return Err(KdfError::KdfParamsRejected);
    }
    // Argon2 treats an empty password as valid. This format does not.
    if password.is_empty() {
        return Err(KdfError::EmptyPassword);
    }

    let params =
        Params::new(m_kib, t, p, Some(OUTPUT_LEN)).map_err(|_| KdfError::KdfParamsRejected)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; OUTPUT_LEN];
    hasher
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| KdfError::KdfParamsRejected)?;
    Ok(Secret::new(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{argon2id, derive_vault_keys, hkdf_sha512, KdfError, KdfProfile, INFO_DEVICE_WRAP};

    #[test]
    fn bounds_empty_password_floor_and_domains() {
        // One function so `cargo test` does not run these allocations in parallel.
        // Desktop is 256 MiB and is not hashed here.
        let salt = [0xA5u8; 32];
        let password = b"vault-password";
        let rejected = [
            (1_048_577, 2, 1),
            (19_456, 17, 1),
            (19_456, 2, 0),
            (19_455, 2, 1),
            (u32::MAX, 2, 1),
            (19_456, u32::MAX, 1),
            (19_456, 2, u32::MAX),
            (19_456, 1, 1),
            (19_456, 2, 17),
        ];
        for (m_kib, t, p) in rejected {
            assert!(matches!(
                argon2id(password, &salt, m_kib, t, p),
                Err(KdfError::KdfParamsRejected)
            ));
        }

        assert!(matches!(
            argon2id(b"", &salt, 19_456, 2, 1),
            Err(KdfError::EmptyPassword)
        ));

        assert_eq!(KdfProfile::Desktop.m_kib(), 262_144);
        assert_eq!(KdfProfile::Desktop.t(), 3);
        assert_eq!(KdfProfile::Desktop.p(), 4);
        assert_eq!(KdfProfile::Mobile.m_kib(), 65_536);
        assert_eq!(KdfProfile::Mobile.t(), 3);
        assert_eq!(KdfProfile::Mobile.p(), 2);
        assert_eq!(INFO_DEVICE_WRAP, b"brby/v2/device-wrap");

        let vk = [0x42u8; 32];
        let vault_id = [0x07u8; 16];
        let (body, bmac, commit) = derive_vault_keys(&vk, &vault_id).unwrap();
        let (body_again, bmac_again, commit_again) = derive_vault_keys(&vk, &vault_id).unwrap();
        assert_eq!(body.expose(), body_again.expose());
        assert_eq!(bmac.expose(), bmac_again.expose());
        assert_eq!(commit.expose(), commit_again.expose());
        assert_ne!(body.expose(), bmac.expose());
        assert_ne!(body.expose(), commit.expose());
        assert_ne!(bmac.expose(), commit.expose());
        assert_eq!(
            body.expose(),
            hkdf_sha512(&vk, &vault_id, b"brby/v2/body-enc")
                .unwrap()
                .expose()
        );
        assert_eq!(
            bmac.expose(),
            hkdf_sha512(&vk, &vault_id, b"brby/v2/body-mac")
                .unwrap()
                .expose()
        );
        assert_eq!(
            commit.expose(),
            hkdf_sha512(&vk, &vault_id, b"brby/v2/commit")
                .unwrap()
                .expose()
        );

        let first = argon2id(password, &salt, 19_456, 2, 1).unwrap();
        let second = argon2id(password, &salt, 19_456, 2, 1).unwrap();
        assert_eq!(first.expose(), second.expose());
        assert_ne!(first.expose(), &[0u8; 32]);
    }
}
