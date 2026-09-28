//! Cascade frame payload: Kuznyechik-CTR + HMAC over AEGIS-256.
//!
//! `payload = iv ‖ KuzCTR(k_kuz, AEGIS(k_aegis, pt) ‖ tag_aegis) ‖ HMAC(k_mac)`.
//! Both layers authenticate the full frame header, and each layer has its
//! own key derived from the frame key, so the frame stays confidential and
//! authentic while either cipher holds. The outer MAC is checked first.

use ::aegis::aegis256::Aegis256;
use aead::{decrypt_body, encrypt_body, BodyAlg};
use kdf::cascade_keys;
use secret::Secret;

use crate::TAG_LEN;

/// Kuznyechik-CTR IV length in bytes.
const KUZ_IV_LEN: usize = 16;

/// Bytes the cascade adds before the trailing outer MAC: the Kuznyechik IV
/// and the inner AEGIS-256 tag.
pub const CASCADE_OVERHEAD: usize = KUZ_IV_LEN + TAG_LEN;

/// Encrypts `pt`, returning `iv ‖ outer ct ‖ outer mac`.
pub fn seal(
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 32],
    ad: &[u8],
    pt: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (k_aegis, k_kuz, k_mac) = cascade_keys(key.expose())?;
    let (ct, tag) = Aegis256::<32>::new(k_aegis.expose(), nonce).encrypt(pt, ad);
    let mut inner = ct;
    inner.extend_from_slice(&tag);
    let mut iv = [0u8; KUZ_IV_LEN];
    getrandom::fill(&mut iv).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    encrypt_body(
        BodyAlg::KuzCtrHmac,
        k_kuz.expose(),
        k_mac.expose(),
        &iv,
        ad,
        &inner,
    )
}

/// Opens `iv ‖ outer ct ‖ outer mac`. Any authentication failure, in either
/// layer, is the same error.
pub fn open(
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 32],
    ad: &[u8],
    payload: &[u8],
) -> anyhow::Result<Secret<Vec<u8>>> {
    let (k_aegis, k_kuz, k_mac) = cascade_keys(key.expose())?;
    let inner = decrypt_body(
        BodyAlg::KuzCtrHmac,
        k_kuz.expose(),
        k_mac.expose(),
        payload,
        ad,
    )
    .map_err(|_| anyhow::anyhow!("frame authentication failed"))?;
    let ct_len = inner
        .len()
        .checked_sub(TAG_LEN)
        .ok_or_else(|| anyhow::anyhow!("frame authentication failed"))?;
    let (ct, tag) = inner.split_at(ct_len);
    let tag: [u8; TAG_LEN] = tag
        .try_into()
        .map_err(|_| anyhow::anyhow!("frame authentication failed"))?;
    Aegis256::<32>::new(k_aegis.expose(), nonce)
        .decrypt(ct, &tag, ad)
        .map(Secret::new)
        .map_err(|_| anyhow::anyhow!("frame authentication failed"))
}
