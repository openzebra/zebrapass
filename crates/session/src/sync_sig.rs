//! ML-DSA signing of one record payload for sync.
//!
//! The signed message is length-prefixed so a verifier cannot shift the
//! boundary between fields. The server verifies signatures but never sees
//! plaintext: the signed ciphertext is the sealed frame body.

pub use pq::{SYNC_SEED_LEN, SYNC_SIG_LEN, SYNC_VK_LEN};

/// L-prefix `vault_id`, 16 bytes.
const L_VAULT: u16 = 16;
/// L-prefix `record_id`, 4 bytes.
const L_RECORD: u16 = 4;
/// L-prefix `revision`, 8 bytes.
const L_REVISION: u16 = 8;
/// L-prefix `content_hash`, 32 bytes.
const L_HASH: u16 = 32;
/// L-prefix of the ciphertext length itself, 4 bytes.
const L_CT_LEN: u16 = 4;

/// Exact bytes signed over one record. Exposed so a verifier can rebuild it.
#[must_use]
pub fn record_message(
    vault_id: &[u8; 16],
    record_id: u32,
    revision: u64,
    content_hash: &[u8; 32],
    ciphertext: &[u8],
) -> Vec<u8> {
    let ct_len = u32::try_from(ciphertext.len()).unwrap_or(u32::MAX);
    let mut msg = Vec::with_capacity(
        usize::from(L_VAULT)
            + usize::from(L_RECORD)
            + usize::from(L_REVISION)
            + usize::from(L_HASH)
            + usize::from(L_CT_LEN)
            + ciphertext.len(),
    );
    msg.extend_from_slice(&L_VAULT.to_le_bytes());
    msg.extend_from_slice(vault_id);
    msg.extend_from_slice(&L_RECORD.to_le_bytes());
    msg.extend_from_slice(&record_id.to_le_bytes());
    msg.extend_from_slice(&L_REVISION.to_le_bytes());
    msg.extend_from_slice(&revision.to_le_bytes());
    msg.extend_from_slice(&L_HASH.to_le_bytes());
    msg.extend_from_slice(content_hash);
    msg.extend_from_slice(&L_CT_LEN.to_le_bytes());
    msg.extend_from_slice(&ct_len.to_le_bytes());
    msg.extend_from_slice(ciphertext);
    msg
}

/// ML-DSA-65 verifying key for `sync_seed` (1952 bytes).
///
/// # Errors
///
/// Propagates [`pq::sync_verifying_key`].
pub fn sync_verifying_key(sync_seed: &[u8; SYNC_SEED_LEN]) -> anyhow::Result<[u8; SYNC_VK_LEN]> {
    let vk = pq::sync_verifying_key(sync_seed)?;
    let key: [u8; SYNC_VK_LEN] = vk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key length"))?;
    Ok(key)
}

/// Sign one record payload.
///
/// # Errors
///
/// Propagates [`pq::sync_sign`].
pub fn sign_record(
    sync_seed: &[u8; SYNC_SEED_LEN],
    vault_id: &[u8; 16],
    record_id: u32,
    revision: u64,
    content_hash: &[u8; 32],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let msg = record_message(vault_id, record_id, revision, content_hash, ciphertext);
    pq::sync_sign(sync_seed, &msg)
}

/// Verify one record payload.
///
/// # Errors
///
/// `signature length` for a wrong-length signature; otherwise propagates
/// [`pq::sync_verify`] (verification failure included).
pub fn verify_record(
    verifying_key: &[u8; SYNC_VK_LEN],
    vault_id: &[u8; 16],
    record_id: u32,
    revision: u64,
    content_hash: &[u8; 32],
    ciphertext: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    if signature.len() != SYNC_SIG_LEN {
        anyhow::bail!("signature length");
    }
    let msg = record_message(vault_id, record_id, revision, content_hash, ciphertext);
    pq::sync_verify(verifying_key, &msg, signature)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "tests may unwrap, index, and panic"
    )]

    use super::{record_message, sign_record, sync_verifying_key, verify_record, SYNC_SEED_LEN};

    #[test]
    fn sign_verify_and_reject_tamper() {
        let seed = [7u8; SYNC_SEED_LEN];
        let other = [8u8; SYNC_SEED_LEN];
        let vault = [1u8; 16];
        let hash = [2u8; 32];
        let ct = vec![9u8; 100];
        let vk = sync_verifying_key(&seed).unwrap();
        let bad_vk = sync_verifying_key(&other).unwrap();
        let sig = sign_record(&seed, &vault, 3, 11, &hash, &ct).unwrap();
        verify_record(&vk, &vault, 3, 11, &hash, &ct, &sig).unwrap();
        assert_eq!(sig.len(), pq::SYNC_SIG_LEN);

        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        assert!(verify_record(&vk, &vault, 3, 11, &hash, &flipped, &sig).is_err());
        assert!(verify_record(&vk, &vault, 3, 12, &hash, &ct, &sig).is_err());
        assert!(verify_record(&bad_vk, &vault, 3, 11, &hash, &ct, &sig).is_err());
        assert!(verify_record(&vk, &vault, 3, 11, &hash, &ct, &sig[..100]).is_err());
    }

    #[test]
    fn message_is_length_prefixed() {
        let a = record_message(&[1u8; 16], 1, 1, &[2u8; 32], &[3u8; 10]);
        let b = record_message(&[1u8; 16], 1, 1, &[2u8; 32], &[3u8; 9]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 2 + 16 + 2 + 4 + 2 + 8 + 2 + 32 + 2 + 4 + 10);
    }
}
