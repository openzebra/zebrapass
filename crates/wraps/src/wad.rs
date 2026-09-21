//! Associated data for a password or device wrap, and AEGIS-256 over it.

use aegis::aegis256::Aegis256;
use container::{
    StaticHeader, DOMAIN_WRAP_DEVICE, DOMAIN_WRAP_PASSWORD, KIND_DEVICE, KIND_PASSWORD,
    SNTRUP_CT_LEN,
};
use secret::Secret;
use zeroize::Zeroize;

use crate::error::WrapError;

pub fn password_wad(header: &StaticHeader, kid: [u8; 8], nonce: &[u8; 32]) -> Vec<u8> {
    let header_bytes = header.to_bytes();
    let kind_le = KIND_PASSWORD.to_le_bytes();
    let mut wad = Vec::with_capacity(
        header_bytes.len() + kind_le.len() + kid.len() + nonce.len() + DOMAIN_WRAP_PASSWORD.len(),
    );
    wad.extend_from_slice(&header_bytes);
    wad.extend_from_slice(&kind_le);
    wad.extend_from_slice(&kid);
    wad.extend_from_slice(nonce);
    wad.extend_from_slice(DOMAIN_WRAP_PASSWORD);
    wad
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one device-wrap associated-data field"
)]
pub fn device_wad(
    header: &StaticHeader,
    device_id: &[u8; 16],
    kem_alg: u16,
    dev_x_pk: &[u8; 32],
    eph_x_pk: &[u8; 32],
    sntrup_ct: &[u8],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let header_bytes = header.to_bytes();
    let kind_le = KIND_DEVICE.to_le_bytes();
    let kem_le = kem_alg.to_le_bytes();
    let mut wad = Vec::with_capacity(
        header_bytes.len()
            + kind_le.len()
            + device_id.len()
            + kem_le.len()
            + dev_x_pk.len()
            + eph_x_pk.len()
            + sntrup_ct.len()
            + nonce.len()
            + DOMAIN_WRAP_DEVICE.len(),
    );
    wad.extend_from_slice(&header_bytes);
    wad.extend_from_slice(&kind_le);
    wad.extend_from_slice(device_id);
    wad.extend_from_slice(&kem_le);
    wad.extend_from_slice(dev_x_pk);
    wad.extend_from_slice(eph_x_pk);
    wad.extend_from_slice(sntrup_ct);
    wad.extend_from_slice(nonce);
    wad.extend_from_slice(DOMAIN_WRAP_DEVICE);
    wad
}

/// AEGIS-256, 32-byte tag. Plaintext is the 32-byte vault key.
pub fn seal_vk(key: &[u8; 32], nonce: &[u8; 32], ad: &[u8], vk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ct = *vk;
    let tag = Aegis256::<32>::new(key, nonce).encrypt_in_place(&mut ct, ad);
    (ct, tag)
}

pub fn open_vk(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    ct: &[u8; 32],
    tag: &[u8; 32],
) -> Result<Secret<[u8; 32]>, WrapError> {
    // Decrypt writes the plaintext over this copy. A bad tag erases it.
    let mut vk = *ct;
    match Aegis256::<32>::new(key, nonce).decrypt_in_place(&mut vk, tag, ad) {
        Ok(()) => {
            let secret = Secret::new(vk);
            vk.zeroize();
            Ok(secret)
        }
        Err(_err) => {
            vk.zeroize();
            Err(WrapError::WrapAuthFailed)
        }
    }
}

pub fn random_array<const N: usize>() -> Result<[u8; N], WrapError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| WrapError::Entropy)?;
    Ok(bytes)
}

pub fn device_ikm(
    ss_x: &[u8; 32],
    ss_pq: &[u8; 32],
    dev_x_pk: &[u8; 32],
    eph_pk: &[u8; 32],
    sntrup_ct: &[u8],
) -> Result<Vec<u8>, WrapError> {
    // Fixed layout: 32 + 32 + 32 + 32 + 1847. A short ciphertext must not reach HKDF.
    if sntrup_ct.len() != SNTRUP_CT_LEN {
        return Err(WrapError::KemLength);
    }
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + 32 + SNTRUP_CT_LEN);
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(dev_x_pk);
    ikm.extend_from_slice(eph_pk);
    ikm.extend_from_slice(sntrup_ct);
    Ok(ikm)
}
