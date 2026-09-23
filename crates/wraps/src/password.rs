//! Password wrap of the vault key.
//!
//! Product-wise the "password" is the master factor: a validated BIP39
//! seed phrase is converted to its 64-byte BIP39 seed, and that seed —
//! not a user-chosen string — feeds Argon2id here. The wrap format is
//! unchanged.

use container::{encode_password_entry, PasswordWrap, StaticHeader};
use kdf::argon2id;
use secret::Secret;

use crate::wad::{self, password_wad};

/// Seal `vk` under `master`.
///
/// The returned bytes are one password record: kid, nonce, 32-byte ciphertext,
/// and a 32-byte AEGIS-256 tag. `k_pw` is Argon2id at the header salt and
/// parameters over the 64-byte master seed. Associated data is the static
/// header, the password kind, the kid, the nonce, and
/// `brby/v2/wrap-password`.
///
/// # Errors
///
/// `kdf parameters rejected` when the header parameters are rejected.
/// `os entropy failed` when the OS RNG fails.
pub fn seal_password(
    header: &StaticHeader,
    master: &[u8; 64],
    vk: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let kid = wad::random_array::<8>()?;
    let nonce = wad::random_array::<32>()?;
    let k_pw = argon2id(
        master,
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
/// A wrong master and a corrupt tag both finish Argon2 and then return
/// `wrap authentication failed`. They are not distinguished.
///
/// # Errors
///
/// `kdf parameters rejected` when the header parameters are rejected.
/// `wrap authentication failed` when the AEGIS-256 tag does not match.
pub fn open_password(
    header: &StaticHeader,
    wrap: &PasswordWrap<'_>,
    master: &[u8; 64],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let k_pw = argon2id(
        master,
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
        let master = [0x2Au8; 64];

        let record = seal_password(&header, &master, &vk).unwrap();
        assert_eq!(record.len(), 110);
        assert_eq!(record.len(), PASSWORD_RECORD_LEN);

        let WrapEntry::Password(parsed) = WrapEntry::try_from(record.as_slice()).unwrap() else {
            panic!("password record");
        };
        // AEGIS-256 of the 32-byte VK is 32 bytes of ciphertext and a 32-byte tag.
        assert_eq!(parsed.ct.len(), 32);
        assert_eq!(parsed.tag.len(), 32);
        assert_eq!(parsed.ct.len() + parsed.tag.len(), 64);

        let opened = open_password(&header, &parsed, &master).unwrap();
        assert_eq!(opened.expose(), &vk);
        let wrong = [0x2Bu8; 64];
        assert_eq!(
            open_password(&header, &parsed, &wrong).unwrap_err().to_string(),
            "wrap authentication failed"
        );
    }
}
