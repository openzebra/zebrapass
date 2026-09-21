//! Password wrap of the vault key.

use container::{encode_password_entry, PasswordWrap, StaticHeader};
use kdf::argon2id;
use secret::Secret;

use crate::error::WrapError;
use crate::wad::{self, password_wad};

/// Seal `vk` under `password`.
///
/// The returned bytes are one password record: kid, nonce, 32-byte ciphertext,
/// and a 32-byte AEGIS-256 tag. `k_pw` is Argon2id at the header salt and
/// parameters. Associated data is the static header, the password kind, the
/// kid, the nonce, and `brby/v2/wrap-password`.
///
/// # Errors
///
/// [`WrapError::EmptyPassword`] when `password` is empty. Argon2 is not run.
/// [`WrapError::KdfParamsRejected`] when the header parameters are rejected.
/// [`WrapError::Entropy`] when the OS RNG fails.
pub fn seal_password(
    header: &StaticHeader,
    password: &str,
    vk: &[u8; 32],
) -> Result<Vec<u8>, WrapError> {
    let kid = wad::random_array::<8>()?;
    let nonce = wad::random_array::<32>()?;
    let k_pw = argon2id(
        password.as_bytes(),
        &header.kdf_salt,
        header.kdf_m_kib,
        header.kdf_t,
        header.kdf_p,
    )?;
    let ad = password_wad(header, kid, &nonce);
    let (ct, tag) = wad::seal_vk(k_pw.expose(), &nonce, &ad, vk);
    Ok(encode_password_entry(kid, nonce, ct, tag).to_vec())
}

/// Open a password wrap.
///
/// A wrong password and a corrupt tag both finish Argon2 and then return
/// [`WrapError::WrapAuthFailed`]. They are not distinguished.
///
/// # Errors
///
/// [`WrapError::EmptyPassword`] when `password` is empty, before Argon2.
/// [`WrapError::KdfParamsRejected`] when the header parameters are rejected.
/// [`WrapError::WrapAuthFailed`] when the AEGIS-256 tag does not match.
pub fn open_password(
    header: &StaticHeader,
    wrap: &PasswordWrap<'_>,
    password: &str,
) -> Result<Secret<[u8; 32]>, WrapError> {
    let k_pw = argon2id(
        password.as_bytes(),
        &header.kdf_salt,
        header.kdf_m_kib,
        header.kdf_t,
        header.kdf_p,
    )?;
    let ad = password_wad(header, wrap.kid, &wrap.nonce);
    wad::open_vk(k_pw.expose(), &wrap.nonce, &ad, &wrap.ct, &wrap.tag)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]
mod tests {
    use container::{
        StaticHeader, WrapEntry, BODY_AEGIS256, KDF_ARGON2ID, KDF_M_KIB_MIN, KDF_P_MIN, KDF_T_MIN,
        PASSWORD_RECORD_LEN, WRAP_AEGIS256,
    };

    use super::{open_password, seal_password};
    use crate::error::WrapError;

    fn floor_header() -> StaticHeader {
        StaticHeader {
            kdf_alg: KDF_ARGON2ID,
            kdf_m_kib: KDF_M_KIB_MIN,
            kdf_t: KDF_T_MIN,
            kdf_p: KDF_P_MIN,
            kdf_salt: [0x5A; 32],
            vault_id: [0x11; 16],
            body_alg: BODY_AEGIS256,
            wrap_alg: WRAP_AEGIS256,
        }
    }

    #[test]
    fn password_wrap_floor_argon2() {
        // One function so `cargo test` does not run these Argon2 allocations in parallel.
        // Parameters are the floor (19 MiB, t = 2, p = 1), not the desktop profile.
        let header = floor_header();
        let vk = [0x42u8; 32];
        let password = "floor-password";

        assert_eq!(
            seal_password(&header, "", &vk).unwrap_err(),
            WrapError::EmptyPassword
        );

        let record = seal_password(&header, password, &vk).unwrap();
        assert_eq!(record.len(), 110);
        assert_eq!(record.len(), PASSWORD_RECORD_LEN);

        let WrapEntry::Password(parsed) = WrapEntry::try_from(record.as_slice()).unwrap() else {
            panic!("password record");
        };
        // AEGIS-256 of the 32-byte VK is 32 bytes of ciphertext and a 32-byte tag.
        assert_eq!(parsed.ct.len(), 32);
        assert_eq!(parsed.tag.len(), 32);
        assert_eq!(parsed.ct.len() + parsed.tag.len(), 64);

        let opened = open_password(&header, &parsed, password).unwrap();
        assert_eq!(opened.expose(), &vk);
        assert_eq!(
            open_password(&header, &parsed, "not-the-password").unwrap_err(),
            WrapError::WrapAuthFailed
        );
        assert_eq!(
            open_password(&header, &parsed, "").unwrap_err(),
            WrapError::EmptyPassword
        );
    }
}
