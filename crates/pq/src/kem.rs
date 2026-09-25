//! ML-KEM-768. A ciphertext that is not [`KEM_CT_LEN`] bytes never reaches the crate.

use anyhow::anyhow;
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{KeyExport, MlKem768, Seed, TryKeyInit};
use secret::Secret;

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 seed length. The decapsulation key is stored as this seed, not the expanded form.
pub const KEM_DK_LEN: usize = 64;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const KEM_CT_LEN: usize = 1088;

/// Fresh ML-KEM-768 key pair. The secret is the 64-byte seed (`d || z`).
///
/// # Errors
///
/// Returns an error when the OS random source fails.
pub fn kem_keypair() -> anyhow::Result<(Vec<u8>, Secret<[u8; KEM_DK_LEN]>)> {
    let mut seed = [0u8; KEM_DK_LEN];
    getrandom::fill(&mut seed).map_err(|_| anyhow!("os rng failed"))?;
    Ok(kem_keypair_from_seed(&seed))
}

/// Deterministic key pair from the 64-byte ML-KEM seed.
#[must_use]
pub fn kem_keypair_from_seed(seed: &[u8; KEM_DK_LEN]) -> (Vec<u8>, Secret<[u8; KEM_DK_LEN]>) {
    let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    let ek = dk.encapsulation_key();
    let mut pk = Vec::with_capacity(KEM_EK_LEN);
    pk.extend_from_slice(ek.to_bytes().as_slice());
    (pk, Secret::new(*seed))
}

fn encapsulation_key(ek: &[u8]) -> anyhow::Result<EncapsulationKey<MlKem768>> {
    EncapsulationKey::<MlKem768>::new_from_slice(ek)
        .map_err(|_| anyhow!("ml-kem encapsulation key must be {KEM_EK_LEN} bytes"))
}

/// Encapsulate a 32-byte shared secret. The ciphertext is always [`KEM_CT_LEN`] bytes.
///
/// # Errors
///
/// Returns an error when `ek` is the wrong length or the OS random source fails.
pub fn kem_encapsulate(ek: &[u8]) -> anyhow::Result<(Secret<[u8; 32]>, Vec<u8>)> {
    let key = encapsulation_key(ek)?;
    let mut coins = [0u8; 32];
    getrandom::fill(&mut coins).map_err(|_| anyhow!("os rng failed"))?;
    let (ct, ss) = key.encapsulate_deterministic(&coins.into());
    let mut out = Vec::with_capacity(KEM_CT_LEN);
    out.extend_from_slice(ct.as_slice());
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok((Secret::new(shared), out))
}

/// Decapsulate. Any length other than [`KEM_CT_LEN`] is an error, not a panic.
///
/// # Errors
///
/// Returns an error when the seed or ciphertext has the wrong length.
pub fn kem_decapsulate(dk: &[u8], ciphertext: &[u8]) -> anyhow::Result<Secret<[u8; 32]>> {
    let seed = <[u8; KEM_DK_LEN]>::try_from(dk)
        .map_err(|_| anyhow!("ml-kem seed must be {KEM_DK_LEN} bytes"))?;
    if ciphertext.len() != KEM_CT_LEN {
        return Err(anyhow!("ml-kem ciphertext must be {KEM_CT_LEN} bytes"));
    }
    let key = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
    let ss = key
        .decapsulate_slice(ciphertext)
        .map_err(|_| anyhow!("ml-kem ciphertext must be {KEM_CT_LEN} bytes"))?;
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok(Secret::new(shared))
}

#[cfg(test)]
mod tests {
    use super::{kem_decapsulate, kem_encapsulate, kem_keypair, KEM_CT_LEN, KEM_EK_LEN};

    #[test]
    fn roundtrip_and_rejects_short_ciphertext() -> anyhow::Result<()> {
        let (ek, dk) = kem_keypair()?;
        assert_eq!(ek.len(), KEM_EK_LEN);
        let (ss, ct) = kem_encapsulate(&ek)?;
        assert_eq!(ct.len(), KEM_CT_LEN);
        let opened = kem_decapsulate(dk.expose(), &ct)?;
        assert_eq!(opened.expose(), ss.expose());
        assert!(kem_decapsulate(dk.expose(), &[0u8; 8]).is_err());
        assert!(kem_decapsulate(dk.expose(), &[0u8; 1]).is_err());
        assert!(kem_decapsulate(dk.expose(), &[]).is_err());
        let mut flipped = ct;
        if let Some(byte) = flipped.first_mut() {
            *byte ^= 1;
        }
        let bad = kem_decapsulate(dk.expose(), &flipped)?;
        assert_ne!(bad.expose(), ss.expose());
        Ok(())
    }
}
