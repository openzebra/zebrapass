//! Chip wrap: secure enclave P-256 hybrid with a software PQ half.

use container::{encode_chip_entry, ChipWrap, StaticHeader};
use kdf::{hkdf_sha512, INFO_CHIP_WRAP};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use pq::{decrypt_shared, encrypt_shared, PQ_PK_LEN, PQ_SK_LEN};
use secret::Secret;
use zeroize::Zeroize;

use crate::wad::{self, chip_wad};

/// Public identity accepted by [`seal_chip`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipPublics {
    /// Grant id. A caller-chosen label, compared before any KEM.
    pub id: [u8; 16],
    /// Uncompressed P-256 public key of the secure chip (65 bytes).
    pub chip_pub: [u8; 65],
    /// `ntrulp` public key of this phone for the PQ half.
    pub pq_pk: [u8; PQ_PK_LEN],
}

/// Secrets that open one chip wrap.
///
/// The chip private key never leaves the platform: it hands the P-256 shared
/// secret to [`open_chip`] instead.
#[derive(Debug)]
pub struct ChipKeys {
    /// Wrap id. Compared with the wrap record before any KEM.
    pub id: [u8; 16],
    /// `ntrulp` secret key of this phone.
    pub pq_sk: Secret<[u8; PQ_SK_LEN]>,
}

/// Owned grant. It is not a vault file and it does not include the commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChipGrant {
    bytes: Vec<u8>,
}

impl ChipGrant {
    /// Borrow the grant encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Seal `vk` to `chip`.
///
/// A fresh software P-256 key pair is drawn for every seal. The first shared
/// secret is `ECDH(ephemeral, chip.chip_pub)`; the ephemeral public half is
/// stored in the record. The PQ half encrypts a second shared secret to
/// `chip.pq_pk`, the same `ntrulp` key the device wrap uses. The wrap key is
/// `HKDF(ss_p256 ‖ ss_pq ‖ chip_pub ‖ eph_pub ‖ pq_pk ‖ sntrup_ct, vault_id)`.
///
/// Returns the chip record and the grant. The grant is the static header, the
/// id, both P-256 public keys, the `ntrulp` public key, the `ntrulp`
/// ciphertext, the nonce, and the AEGIS ciphertext and tag. It does not
/// include the record kind.
///
/// # Errors
///
/// `os entropy failed` when the OS RNG fails or no valid P-256 scalar is
/// drawn. `kem length` when the `ntrulp` key has the wrong length or a
/// public key does not decode. `kdf parameters rejected` when HKDF rejects
/// the output length.
pub fn seal_chip(
    header: &StaticHeader,
    chip: &ChipPublics,
    vk: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, ChipGrant)> {
    let (eph_secret, eph_key) = fresh_p256()?;
    let eph_pub = encode_pub(&eph_key)?;
    let chip_pk = decode_pub(&chip.chip_pub)?;
    let mut ss_p256 = shared(&eph_secret, &chip_pk);
    let sealed = seal_with_shared(header, chip, vk, &eph_pub, &ss_p256);
    ss_p256.zeroize();
    sealed
}

/// Open a chip wrap.
///
/// `ss_p256` is the P-256 shared secret the platform computes as
/// `ECDH(chip_sk, wrap.eph_pub)`; it never enters this process as a key.
///
/// # Errors
///
/// `wrap not found` when `keys.id` is not `wrap.id`.
/// `kem length` when decapsulation rejects a length.
/// `kdf parameters rejected` when HKDF rejects the output length.
/// `wrap authentication failed` when the AEGIS-256 tag does not match.
pub fn open_chip(
    header: &StaticHeader,
    wrap: &ChipWrap<'_>,
    keys: &ChipKeys,
    ss_p256: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    if keys.id != wrap.id {
        return Err(anyhow::anyhow!("wrap not found"));
    }
    let ss_pq = decrypt_shared(keys.pq_sk.expose(), wrap.sntrup_ct)?;
    let k_chip = derive_k_chip(
        ss_p256,
        ss_pq.expose(),
        &wrap.chip_pub,
        &wrap.eph_pub,
        &wrap.pq_pk,
        wrap.sntrup_ct,
        &header.vault_id,
    )?;
    drop(ss_pq);
    let ad = chip_wad(
        header,
        &wrap.id,
        &wrap.chip_pub,
        &wrap.eph_pub,
        &wrap.pq_pk,
        wrap.sntrup_ct,
        &wrap.nonce,
    );
    let vk = wad::open_vk(k_chip.expose(), &wrap.nonce, &ad, &wrap.ct, &wrap.tag);
    drop(k_chip);
    vk
}

fn seal_with_shared(
    header: &StaticHeader,
    chip: &ChipPublics,
    vk: &[u8; 32],
    eph_pub: &[u8; 65],
    ss_p256: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, ChipGrant)> {
    let (ss_pq, sntrup_ct) = encrypt_shared(chip.pq_pk.as_slice())?;
    let k_chip = derive_k_chip(
        ss_p256,
        ss_pq.expose(),
        &chip.chip_pub,
        eph_pub,
        &chip.pq_pk,
        &sntrup_ct,
        &header.vault_id,
    )?;
    // HKDF has copied this secret. Wipe it before the record is built.
    drop(ss_pq);
    let nonce = wad::random_array::<32>()?;
    let ad = chip_wad(
        header,
        &chip.id,
        &chip.chip_pub,
        eph_pub,
        &chip.pq_pk,
        &sntrup_ct,
        &nonce,
    );
    let (ct, tag) = wad::seal_vk(k_chip.expose(), &nonce, &ad, vk);
    drop(k_chip);
    let record = encode_chip_entry(
        chip.id,
        chip.chip_pub,
        *eph_pub,
        chip.pq_pk,
        &sntrup_ct,
        nonce,
        ct,
        tag,
    )
    .map_err(|_| anyhow::anyhow!("kem length"))?;
    let grant = assemble_chip(
        header,
        &chip.id,
        &chip.chip_pub,
        eph_pub,
        &chip.pq_pk,
        &sntrup_ct,
        &nonce,
        &ct,
        &tag,
    );
    Ok((record, grant))
}

fn derive_k_chip(
    ss_p256: &[u8; 32],
    ss_pq: &[u8; 32],
    chip_pub: &[u8; 65],
    eph_pub: &[u8; 65],
    pq_pk: &[u8; PQ_PK_LEN],
    sntrup_ct: &[u8],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let mut ikm = wad::chip_ikm(ss_p256, ss_pq, chip_pub, eph_pub, pq_pk, sntrup_ct)?;
    let derived = hkdf_sha512(&ikm, vault_id, INFO_CHIP_WRAP);
    ikm.zeroize();
    derived
}

/// Draw a software P-256 key pair from the OS RNG.
fn fresh_p256() -> anyhow::Result<(SecretKey, PublicKey)> {
    // Scalars are 32 random bytes; almost every draw is a valid secret key.
    for _ in 0..8 {
        let mut bytes = wad::random_array::<32>()?;
        let key = SecretKey::from_bytes(&bytes.into());
        bytes.zeroize();
        if let Ok(sk) = key {
            let pk = sk.public_key();
            return Ok((sk, pk));
        }
    }
    Err(anyhow::anyhow!("os entropy failed"))
}

/// Decode an uncompressed 65-byte P-256 public key.
fn decode_pub(bytes: &[u8; 65]) -> anyhow::Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| anyhow::anyhow!("kem length"))
}

fn shared(sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let ss = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let raw = ss.raw_secret_bytes();
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(raw.iter()) {
        *dst = *src;
    }
    out
}

fn encode_pub(key: &PublicKey) -> anyhow::Result<[u8; 65]> {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!("kem length"));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one grant field, in wire order"
)]
fn assemble_chip(
    header: &StaticHeader,
    chip_id: &[u8; 16],
    chip_pub: &[u8; 65],
    eph_pub: &[u8; 65],
    pq_pk: &[u8; PQ_PK_LEN],
    sntrup_ct: &[u8],
    nonce: &[u8; 32],
    ct: &[u8; 32],
    tag: &[u8; 32],
) -> ChipGrant {
    let header_bytes = header.to_bytes();
    let mut bytes = Vec::with_capacity(
        header_bytes.len()
            + chip_id.len()
            + chip_pub.len()
            + eph_pub.len()
            + pq_pk.len()
            + sntrup_ct.len()
            + nonce.len()
            + ct.len()
            + tag.len(),
    );
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(chip_id);
    bytes.extend_from_slice(chip_pub);
    bytes.extend_from_slice(eph_pub);
    bytes.extend_from_slice(pq_pk);
    bytes.extend_from_slice(sntrup_ct);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(ct);
    bytes.extend_from_slice(tag);
    ChipGrant { bytes }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::large_stack_arrays
)]
mod tests {
    use container::{
        StaticHeader, WrapEntry, BODY_AEGIS256, KDF_ARGON2ID, KDF_M_KIB_MIN, KDF_P_MIN, KDF_T_MIN,
        WRAP_AEGIS256,
    };
    use pq::{keypair, PQ_PK_LEN};

    use super::{decode_pub, encode_pub, fresh_p256, open_chip, seal_chip, shared, ChipKeys,
        ChipPublics};

    fn floor_header() -> StaticHeader {
        StaticHeader {
            kdf_alg: KDF_ARGON2ID,
            kdf_m_kib: KDF_M_KIB_MIN,
            kdf_t: KDF_T_MIN,
            kdf_p: KDF_P_MIN,
            kdf_salt: [0x5A; 32],
            vault_id: [0x22; 16],
            body_alg: BODY_AEGIS256,
            wrap_alg: WRAP_AEGIS256,
        }
    }

    #[test]
    fn chip_wrap_round_trip() {
        let header = floor_header();
        let vk = [0x24u8; 32];
        let (ntru_bytes, kem_secret) = keypair().unwrap();
        let ntru_pk: [u8; PQ_PK_LEN] = ntru_bytes.as_slice().try_into().unwrap();
        let (chip_secret, chip_pub_key) = fresh_p256().unwrap();
        let chip = ChipPublics {
            id: [0x11; 16],
            chip_pub: encode_pub(&chip_pub_key).unwrap(),
            pq_pk: ntru_pk,
        };
        let keys = ChipKeys {
            id: chip.id,
            pq_sk: kem_secret,
        };
        let (record, grant) = seal_chip(&header, &chip, &vk).unwrap();
        assert!(!grant.as_bytes().is_empty());
        let WrapEntry::Chip(wrap) = WrapEntry::try_from(record.as_slice()).unwrap() else {
            panic!("expected a chip entry");
        };
        let eph_pk = decode_pub(&wrap.eph_pub).unwrap();
        let ss = shared(&chip_secret, &eph_pk);
        let opened = open_chip(&header, &wrap, &keys, &ss).unwrap();
        assert_eq!(opened.expose(), &vk);
        // A shared secret from a foreign chip key fails authentication.
        let (other_sk, _) = fresh_p256().unwrap();
        let wrong_ss = shared(&other_sk, &eph_pk);
        assert_eq!(
            open_chip(&header, &wrap, &keys, &wrong_ss)
                .unwrap_err()
                .to_string(),
            "wrap authentication failed"
        );
        // A flipped ciphertext byte fails authentication.
        let mut tampered = record.clone();
        let len = tampered.len();
        tampered[len - 33] ^= 0x01;
        let WrapEntry::Chip(bad) = WrapEntry::try_from(tampered.as_slice()).unwrap() else {
            panic!("expected a chip entry");
        };
        assert_eq!(
            open_chip(&header, &bad, &keys, &ss).unwrap_err().to_string(),
            "wrap authentication failed"
        );
        // A foreign wrap id is rejected before any KEM.
        let (_, other_kem) = keypair().unwrap();
        let wrong_keys = ChipKeys {
            id: [0xFF; 16],
            pq_sk: other_kem,
        };
        assert_eq!(
            open_chip(&header, &wrap, &wrong_keys, &ss)
                .unwrap_err()
                .to_string(),
            "wrap not found"
        );
    }
}
