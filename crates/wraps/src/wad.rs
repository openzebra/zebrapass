//! Associated data for password, device, chip, and PRF wraps, and AEGIS-256 over it.

use aegis::aegis256::Aegis256;
use container::{
    StaticHeader, DOMAIN_WRAP_CHIP, DOMAIN_WRAP_DEVICE, DOMAIN_WRAP_PASSWORD, DOMAIN_WRAP_PRF,
    KIND_CHIP, KIND_DEVICE, KIND_PASSWORD, KIND_PRF,
};
use pq::PQ_PK_LEN;
use secret::Secret;
use zeroize::Zeroize;


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
    kem_ct: &[u8],
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
            + kem_ct.len()
            + nonce.len()
            + DOMAIN_WRAP_DEVICE.len(),
    );
    wad.extend_from_slice(&header_bytes);
    wad.extend_from_slice(&kind_le);
    wad.extend_from_slice(device_id);
    wad.extend_from_slice(&kem_le);
    wad.extend_from_slice(dev_x_pk);
    wad.extend_from_slice(eph_x_pk);
    wad.extend_from_slice(kem_ct);
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
) -> anyhow::Result<Secret<[u8; 32]>> {
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
            Err(anyhow::anyhow!("wrap authentication failed"))
        }
    }
}

pub fn random_array<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok(bytes)
}

pub fn device_ikm(
    ss_x: &[u8; 32],
    ss_pq: &[u8; 32],
    dev_x_pk: &[u8; 32],
    eph_pk: &[u8; 32],
    kem_ct: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // An empty ciphertext is not an `ML-KEM-768` blob. Do not feed it to HKDF.
    if kem_ct.is_empty() {
        return Err(anyhow::anyhow!("kem length"));
    }
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + 32 + kem_ct.len());
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(dev_x_pk);
    ikm.extend_from_slice(eph_pk);
    ikm.extend_from_slice(kem_ct);
    Ok(ikm)
}

/// Concatenate IKM parts. Every part must be non-empty: an empty ciphertext is
/// not a KEM blob and must not reach HKDF.
fn ikm_concat(parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    if parts.iter().any(|part| part.is_empty()) {
        return Err(anyhow::anyhow!("kem length"));
    }
    let total = parts
        .iter()
        .fold(0usize, |acc, part| acc.saturating_add(part.len()));
    let mut ikm = Vec::with_capacity(total);
    for part in parts {
        ikm.extend_from_slice(part);
    }
    Ok(ikm)
}

/// IKM for the chip wrap key: private halves first, then the public fields
/// that pin the transcript, then the KEM blob.
pub fn chip_ikm(
    ss_p256: &[u8; 32],
    ss_pq: &[u8; 32],
    chip_pub: &[u8; 65],
    eph_pub: &[u8; 65],
    pq_pk: &[u8; PQ_PK_LEN],
    kem_ct: &[u8],
) -> anyhow::Result<Vec<u8>> {
    ikm_concat(&[ss_p256, ss_pq, chip_pub, eph_pub, pq_pk, kem_ct])
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one chip-wrap associated-data field"
)]
pub fn chip_wad(
    header: &StaticHeader,
    chip_id: &[u8; 16],
    chip_pub: &[u8; 65],
    eph_pub: &[u8; 65],
    pq_pk: &[u8; PQ_PK_LEN],
    kem_ct: &[u8],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let header_bytes = header.to_bytes();
    let kind_le = KIND_CHIP.to_le_bytes();
    let mut wad = Vec::with_capacity(
        header_bytes.len()
            + kind_le.len()
            + chip_id.len()
            + chip_pub.len()
            + eph_pub.len()
            + pq_pk.len()
            + kem_ct.len()
            + nonce.len()
            + DOMAIN_WRAP_CHIP.len(),
    );
    wad.extend_from_slice(&header_bytes);
    wad.extend_from_slice(&kind_le);
    wad.extend_from_slice(chip_id);
    wad.extend_from_slice(chip_pub);
    wad.extend_from_slice(eph_pub);
    wad.extend_from_slice(pq_pk);
    wad.extend_from_slice(kem_ct);
    wad.extend_from_slice(nonce);
    wad.extend_from_slice(DOMAIN_WRAP_CHIP);
    wad
}

pub fn prf_wad(
    header: &StaticHeader,
    prf_id: &[u8; 16],
    cred_id: &[u8],
    salt: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let header_bytes = header.to_bytes();
    let kind_le = KIND_PRF.to_le_bytes();
    let mut wad = Vec::with_capacity(
        header_bytes.len()
            + kind_le.len()
            + prf_id.len()
            + cred_id.len()
            + salt.len()
            + nonce.len()
            + DOMAIN_WRAP_PRF.len(),
    );
    wad.extend_from_slice(&header_bytes);
    wad.extend_from_slice(&kind_le);
    wad.extend_from_slice(prf_id);
    wad.extend_from_slice(cred_id);
    wad.extend_from_slice(salt);
    wad.extend_from_slice(nonce);
    wad.extend_from_slice(DOMAIN_WRAP_PRF);
    wad
}
