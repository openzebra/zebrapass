//! ML-DSA-65 signatures for sync writes and device certificates.
//!
//! The ml-dsa 0.1.1 API has no FIPS-204 context input, so the context string
//! is length-prefixed into the signed message. FIPS-204 §5.4 folds the same
//! bytes into the message hash, and the length prefix keeps
//! `ctx = "ab", msg = "c"` distinct from `ctx = "a", msg = "bc"`. Future
//! message types (delete, device list, auth challenge) get their own context
//! constant, so one signature cannot be replayed as another type.

use anyhow::anyhow;
use ml_dsa::{Keypair, MlDsa65, Signature, SigningKey};
use signature::{Signer, Verifier};

/// Sync record writes: `record_message` payloads sign under this context.
pub const SYNC_CTX: &[u8] = b"zebrapass/sync/record/v1";
/// Device certificates: [`crate::sign_device_cert`] signs under this context.
pub const DEVICE_CERT_CTX: &[u8] = b"zebrapass/device-cert/v1";
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

/// The bytes actually signed: `[u16 be ctx_len][ctx][message]`.
fn domain_message(ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + ctx.len() + message.len());
    let len = u16::try_from(ctx.len()).map_or([0x7F, 0xFF], u16::to_be_bytes);
    out.extend_from_slice(&len);
    out.extend_from_slice(ctx);
    out.extend_from_slice(message);
    out
}

/// Sign `message` under the FIPS-204-style context `ctx`. The signature is
/// always [`SYNC_SIG_LEN`] bytes.
///
/// # Errors
///
/// Returns an error when `seed` is the wrong length or signing fails.
pub fn sync_sign(seed: &[u8], ctx: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = signing_key(seed)?;
    let signature = key
        .try_sign(&domain_message(ctx, message))
        .map_err(|_| anyhow!("ml-dsa sign failed"))?;
    let mut out = Vec::with_capacity(SYNC_SIG_LEN);
    out.extend_from_slice(signature.encode().as_slice());
    Ok(out)
}

/// Verify a signature made by [`sync_sign`]. A wrong length is an error, not
/// a panic.
///
/// # Errors
///
/// Returns an error when the key or signature has the wrong length, or the
/// signature does not verify.
pub fn sync_verify(
    verifying_key: &[u8],
    ctx: &[u8],
    message: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    if verifying_key.len() != SYNC_VK_LEN {
        return Err(anyhow!("ml-dsa verifying key must be {SYNC_VK_LEN} bytes"));
    }
    if signature.len() != SYNC_SIG_LEN {
        return Err(anyhow!("ml-dsa signature must be {SYNC_SIG_LEN} bytes"));
    }
    let encoded = <[u8; SYNC_VK_LEN]>::try_from(verifying_key)
        .map_err(|_| anyhow!("ml-dsa verifying key must be {SYNC_VK_LEN} bytes"))?;
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded.into());
    let raw = <[u8; SYNC_SIG_LEN]>::try_from(signature)
        .map_err(|_| anyhow!("ml-dsa signature must be {SYNC_SIG_LEN} bytes"))?;
    let sig = Signature::<MlDsa65>::try_from(raw.as_slice())
        .map_err(|_| anyhow!("ml-dsa signature rejected"))?;
    vk.verify(&domain_message(ctx, message), &sig)
        .map_err(|_| anyhow!("ml-dsa signature does not verify"))
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

/// Opaque ML-DSA signing key for session-side device keys.
#[derive(Debug)]
pub struct SigningKeyMirror(SigningKey<MlDsa65>);

/// Build a device signing key from a fixed 32-byte seed. Infallible: the
/// length is fixed by the type.
#[must_use]
pub fn signing_key_from_seed(seed: &[u8; SYNC_SEED_LEN]) -> SigningKeyMirror {
    SigningKeyMirror(SigningKey::<MlDsa65>::from_seed(&(*seed).into()))
}

/// Encode the verifying key of a device signing key.
///
/// # Errors
///
/// Returns an error when the ML-DSA encoding fails.
pub fn verifying_key_of(key: &SigningKeyMirror) -> anyhow::Result<[u8; SYNC_VK_LEN]> {
    let vk = key.0.verifying_key();
    let encoded = vk.encode();
    <[u8; SYNC_VK_LEN]>::try_from(encoded.as_slice())
        .map_err(|_| anyhow!("ml-dsa verifying key must be {SYNC_VK_LEN} bytes"))
}

#[cfg(test)]
mod tests {
    use super::{
        sync_sign, sync_verify, sync_verifying_key, DEVICE_CERT_CTX, SYNC_CTX, SYNC_SIG_LEN,
        SYNC_VK_LEN,
    };

    #[test]
    fn sign_roundtrip_rejects_wrong_context() -> anyhow::Result<()> {
        let seed = [7u8; 32];
        let vk = sync_verifying_key(&seed)?;
        assert_eq!(vk.len(), SYNC_VK_LEN);
        let message = b"vault-id|record-id|revision|hash";
        let signature = sync_sign(&seed, SYNC_CTX, message)?;
        assert_eq!(signature.len(), SYNC_SIG_LEN);
        sync_verify(&vk, SYNC_CTX, message, &signature)?;
        // A certificate signature cannot verify as a record write.
        assert!(sync_verify(&vk, DEVICE_CERT_CTX, message, &signature).is_err());
        assert!(sync_verify(&vk, SYNC_CTX, b"other", &signature).is_err());
        assert!(sync_verify(&vk, SYNC_CTX, message, &[0u8; 8]).is_err());
        Ok(())
    }
}
