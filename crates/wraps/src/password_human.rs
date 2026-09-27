//! Human password wrap of the vault key (kind `0x0005`).
//!
//! Product-wise the recovery "password" is the BIP39 seed (kind `0x0001`);
//! this wrap seals the vault key under a *human-chosen* password for daily
//! unlock. Chain: Argon2id(password, salt, parameters ≥ wire floor) →
//! HKDF-SHA512 with the wrap domain → AEGIS-256 wrap of the vault key. The
//! parse floor in `container::limits` means a malicious file cannot
//! downgrade the KDF parameters; the seal path raises them to the floor, so
//! a locally created wrap always clears it.

use container::{
    encode_human_password_entry, HumanKdf, HumanPasswordWrap, StaticHeader, DOMAIN_WRAP_PASSWORD,
};
use kdf::{argon2id, hkdf_sha512};
use secret::Secret;

use crate::wad::{human_password_wad, open_vk, random_array, seal_vk};

/// Human password wrap input: the password bytes and the cost profile.
#[derive(Debug)]
pub struct HumanPasswordPublics {
    /// Key id (key-rotation label).
    pub kid: [u8; 8],
    /// The password as typed. Owned; nothing stores it.
    pub password: Vec<u8>,
    /// Argon2id memory in KiB (raised to the wire floor).
    pub m_kib: u32,
    /// Argon2id passes (raised to the wire floor).
    pub t: u32,
    /// Argon2id lanes (raised to the wire floor).
    pub p: u32,
}

/// Wrap-key derivation splits the salt: the first 16 bytes seed the Argon2
/// HKDF info-side binding, matching the parse layout.
const SALT_HALF: usize = 16;

/// Seal `vk` under a human password. Returns the encoded wire record.
///
/// # Errors
///
/// `kdf parameters rejected` when the (floored) parameters are out of
/// range; `os entropy failed` when the OS RNG fails.
pub fn seal_human_password(
    header: &StaticHeader,
    kid: [u8; 8],
    password: &[u8],
    vk: &[u8; 32],
    m_kib: u32,
    t: u32,
    p: u32,
) -> anyhow::Result<Vec<u8>> {
    let kdf = HumanKdf {
        m_kib: m_kib.max(container::KDF_M_KIB_MIN),
        t: t.max(container::KDF_T_MIN),
        p: p.max(container::KDF_P_MIN),
    };
    let salt = random_array::<32>()?;
    let nonce = random_array::<32>()?;
    let kek = argon2id(password, &salt, kdf.m_kib, kdf.t, kdf.p)?;
    // Separate the wrap key from the raw Argon2 output; the salt ties it to
    // this exact record.
    let (_, salt_hi) = salt.split_at(SALT_HALF);
    let info: [u8; 16] = salt_hi.try_into().map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    let wrap_key = hkdf_sha512(kek.expose(), &info, DOMAIN_WRAP_PASSWORD)?;
    let ad = human_password_wad(header, kid, &nonce);
    let (ct, tag) = seal_vk(wrap_key.expose(), &nonce, &ad, vk);
    Ok(encode_human_password_entry(kid, salt, kdf, nonce, ct, tag).to_vec())
}

/// Open a human password wrap.
///
/// A wrong password and a corrupt tag both finish Argon2 and then return
/// `wrap authentication failed`. They are not distinguished.
///
/// # Errors
///
/// `kdf parameters rejected` when the stored parameters are out of range;
/// `wrap authentication failed` on a wrong password or corrupt record.
pub fn open_human_password(
    header: &StaticHeader,
    wrap: &HumanPasswordWrap<'_>,
    password: &[u8],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let kek = argon2id(password, &wrap.salt, wrap.kdf.m_kib, wrap.kdf.t, wrap.kdf.p)?;
    let (_, salt_hi) = wrap.salt.split_at(SALT_HALF);
    let info: [u8; 16] = salt_hi.try_into().map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    let wrap_key = hkdf_sha512(kek.expose(), &info, DOMAIN_WRAP_PASSWORD)?;
    let ad = human_password_wad(header, wrap.kid, &wrap.nonce);
    open_vk(wrap_key.expose(), &wrap.nonce, &ad, &wrap.ct, &wrap.tag)
}
