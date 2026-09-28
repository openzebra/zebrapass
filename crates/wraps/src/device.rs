//! Device wrap: X25519 and ML-KEM-768.

use container::{encode_device_entry, DeviceWrap, StaticHeader, KEM_MLKEM768};
use kdf::{hkdf_sha512, INFO_DEVICE_WRAP};
use pq::{decrypt_shared, encrypt_shared, PQ_PK_LEN, PQ_SK_LEN};
use secret::Secret;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

use crate::grant::{self, DeviceGrant};
use crate::wad::{self, device_wad};

/// Public identity accepted by [`seal_device`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePublics {
    /// Device id written into the wrap record.
    pub id: [u8; 16],
    /// Long-term X25519 public key.
    pub x_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub pq_pk: [u8; PQ_PK_LEN],
}

/// Long-term secrets that open one device wrap.
#[derive(Debug)]
pub struct DeviceKeys {
    /// Device id. Compared with the wrap record before any KEM.
    pub id: [u8; 16],
    /// Long-term X25519 secret.
    pub x_sk: Secret<[u8; 32]>,
    /// ML-KEM-768 seed.
    pub pq_sk: Secret<[u8; PQ_SK_LEN]>,
}

/// Seal `vk` to `dev`.
///
/// Returns the device record and the grant. The grant is the static header,
/// device id, KEM id, both X25519 public keys, the ML-KEM ciphertext, the
/// nonce, and the AEGIS ciphertext and tag. It does not include the record kind.
///
/// # Errors
///
/// `os entropy failed` when the OS RNG fails.
/// `zero shared secret` when the X25519 shared secret is 32 zero
/// bytes. HKDF is not called. The ephemeral scalar is wiped before that return.
/// `kem length` when the ML-KEM-768 key or ciphertext has the wrong length.
/// `kdf parameters rejected` when HKDF rejects the output length.
pub fn seal_device(
    header: &StaticHeader,
    dev: &DevicePublics,
    vk: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, DeviceGrant)> {
    let mut scalar = wad::random_array::<32>()?;
    let eph_pk = x25519(scalar, X25519_BASEPOINT_BYTES);
    let mut ss_x = x25519(scalar, dev.x_pk);
    // The scalar is done. Wipe it before the reject path and before HKDF.
    scalar.zeroize();
    if secret::ct_eq_32(&ss_x, &[0u8; 32]) {
        ss_x.zeroize();
        return Err(anyhow::anyhow!("zero shared secret"));
    }
    let sealed = seal_with_shared(header, dev, vk, &eph_pk, &ss_x);
    ss_x.zeroize();
    sealed
}

/// Open a device wrap.
///
/// # Errors
///
/// `wrap not found` when `keys.id` is not `wrap.device_id`.
/// `unsupported kem` when `wrap.kem_alg` is not `0xC002`.
/// `zero shared secret` when the X25519 shared secret is 32 zero bytes.
/// `kem length` when decapsulation rejects a length.
/// `kdf parameters rejected` when HKDF rejects the output length.
/// `wrap authentication failed` when the AEGIS-256 tag does not match.
pub fn open_device(
    header: &StaticHeader,
    wrap: &DeviceWrap<'_>,
    keys: &DeviceKeys,
) -> anyhow::Result<Secret<[u8; 32]>> {
    if keys.id != wrap.device_id {
        return Err(anyhow::anyhow!("wrap not found"));
    }
    if wrap.kem_alg != KEM_MLKEM768 {
        return Err(anyhow::anyhow!("unsupported kem {:#06x}", wrap.kem_alg));
    }
    let mut scalar = *keys.x_sk.expose();
    let mut ss_x = x25519(scalar, wrap.eph_x_pk);
    scalar.zeroize();
    if secret::ct_eq_32(&ss_x, &[0u8; 32]) {
        ss_x.zeroize();
        return Err(anyhow::anyhow!("zero shared secret"));
    }
    let opened = open_with_shared(header, wrap, keys, &ss_x);
    ss_x.zeroize();
    opened
}

fn seal_with_shared(
    header: &StaticHeader,
    dev: &DevicePublics,
    vk: &[u8; 32],
    eph_pk: &[u8; 32],
    ss_x: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, DeviceGrant)> {
    let (ss_pq, kem_ct) = encrypt_shared(dev.pq_pk.as_slice())?;
    let k_dev = derive_k_dev(
        ss_x,
        ss_pq.expose(),
        &dev.x_pk,
        eph_pk,
        &kem_ct,
        &header.vault_id,
    )?;
    // HKDF has copied this secret. Wipe it before the record is built.
    drop(ss_pq);
    let nonce = wad::random_array::<32>()?;
    let ad = device_wad(
        header,
        &dev.id,
        KEM_MLKEM768,
        &dev.x_pk,
        eph_pk,
        &kem_ct,
        &nonce,
    );
    let (ct, tag) = wad::seal_vk(k_dev.expose(), &nonce, &ad, vk);
    drop(k_dev);
    let record = encode_device_entry(
        dev.id,
        KEM_MLKEM768,
        dev.x_pk,
        *eph_pk,
        &kem_ct,
        nonce,
        ct,
        tag,
    )
    .map_err(|_| anyhow::anyhow!("kem length"))?;
    let grant = grant::assemble(
        header,
        &dev.id,
        KEM_MLKEM768,
        &dev.x_pk,
        eph_pk,
        &kem_ct,
        &nonce,
        &ct,
        &tag,
    );
    Ok((record, grant))
}

fn open_with_shared(
    header: &StaticHeader,
    wrap: &DeviceWrap<'_>,
    keys: &DeviceKeys,
    ss_x: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let ss_pq = decrypt_shared(keys.pq_sk.expose(), wrap.kem_ct)?;
    let k_dev = derive_k_dev(
        ss_x,
        ss_pq.expose(),
        &wrap.dev_x_pk,
        &wrap.eph_x_pk,
        wrap.kem_ct,
        &header.vault_id,
    )?;
    drop(ss_pq);
    let ad = device_wad(
        header,
        &wrap.device_id,
        wrap.kem_alg,
        &wrap.dev_x_pk,
        &wrap.eph_x_pk,
        wrap.kem_ct,
        &wrap.nonce,
    );
    let vk = wad::open_vk(k_dev.expose(), &wrap.nonce, &ad, &wrap.ct, &wrap.tag);
    drop(k_dev);
    vk
}

fn derive_k_dev(
    ss_x: &[u8; 32],
    ss_pq: &[u8; 32],
    dev_x_pk: &[u8; 32],
    eph_pk: &[u8; 32],
    kem_ct: &[u8],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let mut ikm = wad::device_ikm(ss_x, ss_pq, dev_x_pk, eph_pk, kem_ct)?;
    let derived = hkdf_sha512(&ikm, vault_id, INFO_DEVICE_WRAP);
    ikm.zeroize();
    derived
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
        StaticHeader, WrapEntry, BODY_AEGIS256, HEADER_LEN, KDF_ARGON2ID, KDF_M_KIB_MIN, KDF_P_MIN,
        KDF_T_MIN, KEM_MLKEM768, WRAP_AEGIS256,
    };
    use pq::PQ_PK_LEN;
    use secret::Secret;
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
    use zeroize::Zeroize;

    use super::{open_device, seal_device, DeviceKeys, DevicePublics};

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
    fn zero_x25519_public_key_is_rejected() {
        let header = floor_header();
        let dev = DevicePublics {
            id: [0x09; 16],
            x_pk: [0u8; 32],
            pq_pk: [0u8; PQ_PK_LEN],
        };
        let err = seal_device(&header, &dev, &[0x07; 32]).unwrap_err();
        assert_eq!(err.to_string(), "zero shared secret");
    }

    #[test]
    fn device_wrap_round_trip() {
        let header = floor_header();
        let vk = [0x24u8; 32];
        let (kem_bytes, kem_secret) = pq::keypair().unwrap();
        let kem_pk: [u8; PQ_PK_LEN] = kem_bytes.as_slice().try_into().unwrap();
        let mut raw_scalar = [0u8; 32];
        getrandom::fill(&mut raw_scalar).unwrap();
        let montgomery = x25519(raw_scalar, X25519_BASEPOINT_BYTES);
        let scalar_key = Secret::new(raw_scalar);
        raw_scalar.zeroize();
        let id = [0xA1u8; 16];
        let dev = DevicePublics {
            id,
            x_pk: montgomery,
            pq_pk: kem_pk,
        };
        let keys = DeviceKeys {
            id,
            x_sk: scalar_key,
            pq_sk: kem_secret,
        };

        let (record, grant) = seal_device(&header, &dev, &vk).unwrap();
        assert!(record.len() > 110);

        let WrapEntry::Device(parsed) = WrapEntry::try_from(record.as_slice()).unwrap() else {
            panic!("device record");
        };
        let grant_bytes = grant.as_bytes();
        let header_bytes = header.to_bytes();
        let kem_ct = parsed.kem_ct;
        let ct_at = header_bytes.len() + 16 + 2 + 32 + 32;
        let after_ct = ct_at + kem_ct.len();
        assert!(grant_bytes.len() > HEADER_LEN);
        assert_eq!(
            grant_bytes.get(..header_bytes.len()),
            Some(header_bytes.as_slice())
        );
        assert_eq!(grant_bytes.get(ct_at..after_ct), Some(kem_ct));
        assert_eq!(
            grant_bytes.get(after_ct..after_ct + 32),
            Some(parsed.nonce.as_slice())
        );
        assert_eq!(
            grant_bytes.get(after_ct + 32..after_ct + 64),
            Some(parsed.ct.as_slice())
        );
        assert_eq!(
            grant_bytes.get(after_ct + 64..after_ct + 96),
            Some(parsed.tag.as_slice())
        );
        assert_eq!(grant_bytes.len(), after_ct + 96);
        assert_eq!(parsed.kem_alg, KEM_MLKEM768);

        let opened = open_device(&header, &parsed, &keys).unwrap();
        assert_eq!(opened.expose(), &vk);

        let mut mismatched = parsed;
        mismatched.device_id = [0xFF; 16];
        assert_eq!(
            open_device(&header, &mismatched, &keys)
                .unwrap_err()
                .to_string(),
            "wrap not found"
        );
        let mut bad_kem = parsed;
        bad_kem.kem_alg = 0xC001;
        assert_eq!(
            open_device(&header, &bad_kem, &keys)
                .unwrap_err()
                .to_string(),
            "unsupported kem 0xc001"
        );
    }
}
