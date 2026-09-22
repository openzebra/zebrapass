//! Kuznyechik in GOST CTR, authenticated with HMAC-SHA256.

use hmac::{Hmac, KeyInit, Mac};
use kuznechik_rs::{Block128, Key, Kuznechik};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{copy_array, split_packed};

const IV_LEN: usize = 8;
const TAG_LEN: usize = 32;
const BLOCK_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

pub fn seal(
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    nonce: &[u8],
    ad: &[u8],
    pt: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let iv: [u8; IV_LEN] = copy_array(nonce)?;
    let mut ct = pt.to_vec();
    apply_ctr(k_body, iv, &mut ct);
    let tag = mac_tag(k_bmac, &iv, &ct, ad)?;
    Ok(pack(&iv, &ct, &tag))
}

pub fn open(
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    packed: &[u8],
    ad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (nonce, ct, tag) = split_packed(packed, IV_LEN, TAG_LEN)?;
    let iv: [u8; IV_LEN] = copy_array(nonce)?;
    let expected: [u8; TAG_LEN] = copy_array(tag)?;
    let computed = mac_tag(k_bmac, &iv, ct, ad)?;
    if !bool::from(expected.ct_eq(&computed)) {
        return Err(anyhow::anyhow!("body authentication failed"));
    }
    let mut pt = ct.to_vec();
    apply_ctr(k_body, iv, &mut pt);
    Ok(pt)
}

/// `kuznechik_rs::modes::ctr` increments only the low 32 bits (NIST SP 800-38A).
/// GOST R 34.13-2015 §5.2 adds one to the whole 128-bit big-endian block.
fn apply_ctr(key: &[u8; 32], iv: [u8; IV_LEN], data: &mut [u8]) {
    let cipher = Kuznechik::new(&Key::new(*key));
    let mut counter = [0u8; BLOCK_LEN];
    // `CTR_1 = IV ‖ 0^64`. The remaining eight bytes stay zero.
    for (dst, src) in counter.iter_mut().zip(iv.iter()) {
        *dst = *src;
    }
    for chunk in data.chunks_mut(BLOCK_LEN) {
        let mut block = Block128::from_bytes(counter);
        cipher.encrypt_block(&mut block);
        let keystream = block.to_bytes();
        for (out, ks) in chunk.iter_mut().zip(keystream.iter()) {
            *out ^= *ks;
        }
        increment_be(&mut counter);
    }
}

/// Adds one to a 16-byte big-endian integer. The last byte is the least significant.
fn increment_be(block: &mut [u8; BLOCK_LEN]) {
    for byte in block.iter_mut().rev() {
        let (sum, overflow) = byte.overflowing_add(1);
        *byte = sum;
        if !overflow {
            break;
        }
    }
}

/// Tag is HMAC-SHA256(`k_bmac`, `IV ‖ ct ‖ AD`). The nonce is not copied into `AD`.
fn mac_tag(k_bmac: &[u8; 32], iv: &[u8], ct: &[u8], ad: &[u8]) -> anyhow::Result<[u8; TAG_LEN]> {
    // A 32-byte key is a legal HMAC key. The constructor still returns `Result`.
    let Ok(mut mac) = HmacSha256::new_from_slice(k_bmac) else {
        return Err(anyhow::anyhow!("corrupted length"));
    };
    mac.update(iv);
    mac.update(ct);
    mac.update(ad);
    let digest = mac.finalize().into_bytes();
    copy_array(&digest)
}

fn pack(iv: &[u8], ct: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(iv.len() + ct.len() + tag.len());
    packed.extend_from_slice(iv);
    packed.extend_from_slice(ct);
    packed.extend_from_slice(tag);
    packed
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
    use super::{apply_ctr, increment_be};

    const KEY: &str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    const IV: &str = "1234567890abcef0";
    const PT: &str = concat!(
        "1122334455667700ffeeddccbbaa9988",
        "00112233445566778899aabbcceeff0a",
        "112233445566778899aabbcceeff0a00",
        "2233445566778899aabbcceeff0a0011",
    );
    const CT: &str = concat!(
        "f195d8bec10ed1dbd57b5fa240bda1b8",
        "85eee733f6a13e5df33ce4b33c45dee4",
        "a5eae88be6356ed3d5e877f13564a3a5",
        "cb91fab1f20cbab6d1c6d15820bdba73",
    );

    fn unhex(input: &str) -> Vec<u8> {
        hex::decode(input).expect("valid hex")
    }

    fn unhex_array<const N: usize>(input: &str) -> [u8; N] {
        hex::decode(input)
            .expect("valid hex")
            .try_into()
            .expect("hex width")
    }

    #[test]
    fn gost_r_34_13_2015_annex_a_1_2_ctr() {
        let key = unhex_array::<32>(KEY);
        let iv = unhex_array::<8>(IV);
        let pt = unhex(PT);
        let expected = unhex(CT);

        let mut ct = pt.clone();
        apply_ctr(&key, iv, &mut ct);
        assert_eq!(ct, expected);
        apply_ctr(&key, iv, &mut ct);
        assert_eq!(ct, pt);

        let mut longer = pt;
        longer.push(0x5a);
        let mut gamma = longer.clone();
        apply_ctr(&key, iv, &mut gamma);
        assert_eq!(&gamma[..expected.len()], &expected[..]);

        let mut tail_ff = longer.clone();
        tail_ff[64] = 0xff;
        let mut gamma_ff = tail_ff.clone();
        apply_ctr(&key, iv, &mut gamma_ff);
        assert_eq!(&gamma_ff[..64], &gamma[..64]);
        assert_eq!(gamma_ff[64] ^ 0xff, gamma[64] ^ 0x5a);

        apply_ctr(&key, iv, &mut gamma);
        assert_eq!(gamma, longer);
    }

    #[test]
    fn counter_add_is_big_endian() {
        let mut block = [0u8; 16];
        block[15] = 0xff;
        increment_be(&mut block);
        assert_eq!(block[15], 0x00);
        assert_eq!(block[14], 0x01);
        assert!(block[..14].iter().all(|byte| *byte == 0));
    }
}
