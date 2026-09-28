//! Body algorithm ids and the encrypt/decrypt entry points.

use crate::aegis;
use crate::kuz_ctr;

const AEGIS256_ID: u16 = 0xA001;
const KUZ_MGM_ID: u16 = 0xA002;
const KUZ_CTR_HMAC_ID: u16 = 0xA003;
const FRAMES_ID: u16 = 0xA004;

/// Body encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyAlg {
    /// AEGIS-256, 32-byte tag (`0xA001`).
    Aegis256,
    /// Kuznyechik-MGM (`0xA002`). Recognized, not implemented.
    KuzMgm,
    /// Kuznyechik-CTR with HMAC-SHA256 (`0xA003`).
    KuzCtrHmac,
    /// Length-delimited sealed frames. Not an AEAD (`0xA004`).
    Frames,
}

impl TryFrom<u16> for BodyAlg {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            AEGIS256_ID => Ok(Self::Aegis256),
            KUZ_MGM_ID => Ok(Self::KuzMgm),
            KUZ_CTR_HMAC_ID => Ok(Self::KuzCtrHmac),
            FRAMES_ID => Ok(Self::Frames),
            other => Err(anyhow::anyhow!("unsupported body algorithm {other:#06x}")),
        }
    }
}

/// Nonce, ciphertext, and tag borrowed from a packed body.
pub type NonceCtTag<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Copies `bytes` into an array.
///
/// # Errors
///
/// `corrupted length` when `bytes` is not `N` bytes long.
pub fn copy_array<const N: usize>(bytes: &[u8]) -> anyhow::Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_err| anyhow::anyhow!("corrupted length"))
}

/// Splits `nonce ‖ ct ‖ tag`.
///
/// # Errors
///
/// `corrupted length` when `packed` is shorter than `nonce_len + tag_len`.
pub fn split_packed(
    packed: &[u8],
    nonce_len: usize,
    tag_len: usize,
) -> anyhow::Result<NonceCtTag<'_>> {
    let nonce = packed
        .get(..nonce_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let rest = packed
        .get(nonce_len..)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let ct_len = rest
        .len()
        .checked_sub(tag_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let ct = rest
        .get(..ct_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let tag = rest
        .get(ct_len..)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((nonce, ct, tag))
}

/// Encrypts `pt` under `alg`.
///
/// Returned bytes are `nonce ‖ ct ‖ tag`. `nonce` is caller-supplied; nothing
/// here generates one.
///
/// # Errors
///
/// `unsupported body algorithm` for [`BodyAlg::KuzMgm`].
/// `corrupted length` when `nonce` is not the length `alg` requires.
pub fn encrypt_body(
    alg: BodyAlg,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    nonce: &[u8],
    ad: &[u8],
    pt: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match alg {
        BodyAlg::Aegis256 => aegis::seal(k_body, nonce, ad, pt),
        BodyAlg::KuzMgm => Err(anyhow::anyhow!(
            "unsupported body algorithm {KUZ_MGM_ID:#06x}"
        )),
        BodyAlg::Frames => Err(anyhow::anyhow!("frames body is not an aead")),
        BodyAlg::KuzCtrHmac => kuz_ctr::seal(k_body, k_bmac, nonce, ad, pt),
    }
}

/// Decrypts `packed` (`nonce ‖ ct ‖ tag`) under `alg`.
///
/// # Errors
///
/// `unsupported body algorithm` for [`BodyAlg::KuzMgm`].
/// `corrupted length` when `packed` is shorter than the nonce and tag.
/// `body authentication failed` when the tag does not match.
pub fn decrypt_body(
    alg: BodyAlg,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    packed: &[u8],
    ad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match alg {
        BodyAlg::Aegis256 => aegis::open(k_body, packed, ad),
        BodyAlg::KuzMgm => Err(anyhow::anyhow!(
            "unsupported body algorithm {KUZ_MGM_ID:#06x}"
        )),
        BodyAlg::Frames => Err(anyhow::anyhow!("frames body is not an aead")),
        BodyAlg::KuzCtrHmac => kuz_ctr::open(k_body, k_bmac, packed, ad),
    }
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
    use super::{decrypt_body, encrypt_body, BodyAlg};

    #[test]
    fn body_alg_ids() {
        assert_eq!(BodyAlg::try_from(0xA001).unwrap(), BodyAlg::Aegis256);
        assert_eq!(BodyAlg::try_from(0xA002).unwrap(), BodyAlg::KuzMgm);
        assert_eq!(BodyAlg::try_from(0xA003).unwrap(), BodyAlg::KuzCtrHmac);
        assert_eq!(BodyAlg::try_from(0xA004).unwrap(), BodyAlg::Frames);
        assert_eq!(
            BodyAlg::try_from(0xA005).unwrap_err().to_string(),
            "unsupported body algorithm 0xa005"
        );
    }
    #[test]
    fn kuz_mgm_is_unsupported() {
        let key = [0u8; 32];
        assert_eq!(
            encrypt_body(BodyAlg::KuzMgm, &key, &key, &[0u8; 16], b"", b"")
                .unwrap_err()
                .to_string(),
            "unsupported body algorithm 0xa002"
        );
        assert_eq!(
            decrypt_body(BodyAlg::KuzMgm, &key, &key, b"", b"")
                .unwrap_err()
                .to_string(),
            "unsupported body algorithm 0xa002"
        );
    }
    #[test]
    fn wrong_nonce_length_is_corrupted() {
        let k_body = [1u8; 32];
        let k_bmac = [2u8; 32];
        let ad = b"ad";
        let pt = b"pt";
        assert_eq!(
            encrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &[0u8; 16], ad, pt)
                .unwrap_err()
                .to_string(),
            "corrupted length"
        );
        assert_eq!(
            encrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &[0u8; 32], ad, pt)
                .unwrap_err()
                .to_string(),
            "corrupted length"
        );
        assert_eq!(
            decrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &[0u8; 63], ad)
                .unwrap_err()
                .to_string(),
            "corrupted length"
        );
        assert_eq!(
            decrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &[0u8; 39], ad)
                .unwrap_err()
                .to_string(),
            "corrupted length"
        );
    }

    #[test]
    fn aegis256_round_trip_and_rejects_flipped_ciphertext() {
        let k_body = [0x33u8; 32];
        let k_bmac = [0x44u8; 32];
        let nonce = [0x55u8; 32];
        let ad = b"brby/v2/body";
        let pt = b"0123456789abcdef0123456789abcdef";
        assert_eq!(pt.len(), 32);

        let packed = encrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &nonce, ad, pt).unwrap();
        assert_eq!(&packed[..32], &nonce);
        let ct_tag = &packed[32..];
        assert_eq!(ct_tag.len(), 64);
        assert_eq!(ct_tag[..32].len(), 32);
        assert_eq!(ct_tag[32..].len(), 32);
        assert_eq!(
            decrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &packed, ad).unwrap(),
            pt
        );
        let mut flipped = packed.clone();
        flipped[32] ^= 1;
        assert_eq!(
            decrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &flipped, ad)
                .unwrap_err()
                .to_string(),
            "body authentication failed"
        );
    }

    #[test]
    fn kuz_ctr_hmac_rejects_a_different_iv() {
        let k_body = [0x11u8; 32];
        let k_bmac = [0x22u8; 32];
        let iv = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let ad = b"brby/v2/body";
        let pt = b"same-ct-different-iv";

        let packed = encrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &iv, ad, pt).unwrap();
        assert_eq!(packed.len(), iv.len() + pt.len() + 32);
        assert_eq!(&packed[..iv.len()], &iv);
        assert_eq!(
            decrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &packed, ad).unwrap(),
            pt
        );
        let mut other_iv = packed.clone();
        other_iv[0] ^= 0x01;
        assert_eq!(&other_iv[iv.len()..], &packed[iv.len()..]);
        assert_eq!(
            decrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &other_iv, ad)
                .unwrap_err()
                .to_string(),
            "body authentication failed"
        );
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k_body = [7u8; 32];
        let k_bmac = [9u8; 32];
        let ad = b"ad";

        let aegis_nonce = [3u8; 32];
        let aegis =
            encrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &aegis_nonce, ad, b"").unwrap();
        assert_eq!(aegis.len(), 64);
        assert_eq!(
            decrypt_body(BodyAlg::Aegis256, &k_body, &k_bmac, &aegis, ad).unwrap(),
            b""
        );

        let iv = [4u8; 16];
        let kuz = encrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &iv, ad, b"").unwrap();
        assert_eq!(kuz.len(), 48);
        assert_eq!(
            decrypt_body(BodyAlg::KuzCtrHmac, &k_body, &k_bmac, &kuz, ad).unwrap(),
            b""
        );
    }
}
