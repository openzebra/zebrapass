//! ML-DSA-65 signatures for sync requests. The seed is 32 bytes; the server only needs the verifying key.

use anyhow::anyhow;
use ml_dsa::{EncodedVerifyingKey, KeyInit, Keypair, MlDsa65, Signature, SigningKey};
use signature::{Signer, Verifier};

/// ML-DSA-65 seed length.
pub const SYNC_SEED_LEN: usize = 32;
/// ML-DSA-65 verifying key length.
pub const SYNC_VK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const SYNC_SIG_LEN: usize = 3309;

fn signing_key(seed: &[u8]) -> anyhow::Result<SigningKey<MlDsa65>> {
    let bytes = <[u8; SYNC_SEED_LEN]>::try_from(seed)
        .map_err(|_| anyhow!("ml-dsa seed must be {SYNC_SEED_LEN} bytes"))?;
    Ok(SigningKey::<MlDsa65>::from_seed(&bytes.into()))
}

/// Verifying key for `seed`. The server stores this, not the seed.
///
/// # Errors
///
/// Returns an error when `seed` is not [`SYNC_SEED_LEN`] bytes.
pub fn sync_verifying_key(seed: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = signing_key(seed)?;
    let vk = key.verifying_key();
    let mut out = Vec::with_capacity(SYNC_VK_LEN);
    out.extend_from_slice(vk.encode().as_slice());
    Ok(out)
}

/// Sign `message`. The signature is always [`SYNC_SIG_LEN`] bytes.
///
/// # Errors
///
/// Returns an error when `seed` is the wrong length or signing fails.
pub fn sync_sign(seed: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = signing_key(seed)?;
    let signature = key
        .try_sign(message)
        .map_err(|_| anyhow!("ml-dsa sign failed"))?;
    let mut out = Vec::with_capacity(SYNC_SIG_LEN);
    out.extend_from_slice(signature.encode().as_slice());
    Ok(out)
}

/// Verify a sync signature. A wrong length is an error, not a panic.
///
/// # Errors
///
/// Returns an error when the key or signature has the wrong length, or the signature does not verify.
pub fn sync_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    if verifying_key.len() != SYNC_VK_LEN {
        return Err(anyhow!(
            "ml-dsa verifying key must be {SYNC_VK_LEN} bytes"
        ));
    }
    if signature.len() != SYNC_SIG_LEN {
        return Err(anyhow!("ml-dsa signature must be {SYNC_SIG_LEN} bytes"));
    }
    let vk_bytes = EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key)
        .map_err(|_| anyhow!("ml-dsa verifying key must be {SYNC_VK_LEN} bytes"))?;
    let key = <ml_dsa::VerifyingKey<MlDsa65> as KeyInit>::new(&vk_bytes);
    let parsed = Signature::<MlDsa65>::try_from(signature)
        .map_err(|_| anyhow!("ml-dsa signature rejected"))?;
    key.verify(message, &parsed)
        .map_err(|_| anyhow!("ml-dsa verify failed"))
}

#[cfg(test)]
mod tests {
    use super::{sync_sign, sync_verify, sync_verifying_key, SYNC_SIG_LEN, SYNC_VK_LEN};

    #[test]
    fn sign_roundtrip_rejects_short_signature() -> anyhow::Result<()> {
        let seed = [7u8; 32];
        let vk = sync_verifying_key(&seed)?;
        assert_eq!(vk.len(), SYNC_VK_LEN);
        let message = b"vault-id|record-id|revision|hash";
        let signature = sync_sign(&seed, message)?;
        assert_eq!(signature.len(), SYNC_SIG_LEN);
        sync_verify(&vk, message, &signature)?;
        assert!(sync_verify(&vk, b"other", &signature).is_err());
        assert!(sync_verify(&vk, message, &[0u8; 8]).is_err());
        Ok(())
    }
}
