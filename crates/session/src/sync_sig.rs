//! Sync signatures: one ML-DSA key per device, certified by the account root.
//!
//! The signed message is length-prefixed so a verifier cannot shift the
//! boundary between fields, and carries the message version and the vault-key
//! generation so a signature cannot be replayed across format changes or key
//! epochs. The server verifies signatures but never sees plaintext: the
//! signed ciphertext is the sealed frame.

use zeroize::Zeroizing;

pub use pq::{sync_verifying_key, DEVICE_CERT_CTX, SYNC_CTX, SYNC_SEED_LEN, SYNC_VK_LEN};

use crate::error::SessionError;

/// Wire format version of `record_message`.
pub const MSG_VERSION: u16 = 1;

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
/// L-prefix `msg_version`, 2 bytes.
const L_VERSION: u16 = 2;
/// L-prefix `key_generation`, 4 bytes.
const L_GENERATION: u16 = 4;

/// Length prefix for the ciphertext tail. The old code saturated at
/// `u32::MAX`; a length that cannot exist must be an error instead.
///
/// # Errors
///
/// `ciphertext too large` when `len` exceeds `u32::MAX`.
pub fn ct_len_prefix(len: usize) -> Result<[u8; 4], SessionError> {
    let Ok(value) = u32::try_from(len) else {
        return Err(SessionError::CiphertextTooLarge);
    };
    Ok(value.to_le_bytes())
}

/// Exact bytes signed over one record. Exposed so a verifier can rebuild it.
#[must_use]
pub fn record_message(
    vault_id: &[u8; 16],
    record_id: u32,
    revision: u64,
    content_hash: &[u8; 32],
    ciphertext: &[u8],
    msg_version: u16,
    key_generation: u32,
) -> Vec<u8> {
    // The caller got `ciphertext` from a frame, so the length fits; the
    // prefix is part of the signed bytes and must never saturate silently.
    let Ok(ct_len) = u32::try_from(ciphertext.len()) else {
        return Vec::new();
    };
    let mut msg = Vec::with_capacity(
        16 + 4 + 8 + 32 + 4 + 2 + 4 + ciphertext.len() + 7 * 2,
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
    msg.extend_from_slice(&L_VERSION.to_le_bytes());
    msg.extend_from_slice(&msg_version.to_le_bytes());
    msg.extend_from_slice(&L_GENERATION.to_le_bytes());
    msg.extend_from_slice(&key_generation.to_le_bytes());
    msg.extend_from_slice(ciphertext);
    msg
}

/// One signed sync record, ready for the server wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// Vault the record belongs to; must equal the session vault id.
    pub vault_id: [u8; 16],
    /// Record the frame carries.
    pub record_id: u32,
    /// Monotonic per-record counter; strictly newer than anything stored.
    pub revision: u64,
    /// SHA-256 of the frame ciphertext.
    pub content_hash: [u8; 32],
    /// Wire format version (`MSG_VERSION`).
    pub msg_version: u16,
    /// Vault-key generation the frame was written under.
    pub key_generation: u32,
    /// The sealed frame, as written to the vault body.
    pub frame: Vec<u8>,
    /// ML-DSA-65 signature over [`record_message`].
    pub signature: Vec<u8>,
}

impl SyncRecord {
    /// Rebuild the signed message for `self`.
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        record_message(
            &self.vault_id,
            self.record_id,
            self.revision,
            &self.content_hash,
            &self.frame,
            self.msg_version,
            self.key_generation,
        )
    }

    /// Verify this record against a device verifying key and the expected
    /// vault id.
    ///
    /// # Errors
    ///
    /// Propagates [`verify_record`].
    pub fn verify(&self, device_vk: &[u8; SYNC_VK_LEN], vault_id: &[u8; 16]) -> anyhow::Result<()> {
        verify_record(device_vk, self, vault_id)
    }
}

/// Sign a record payload with the device key. The signature covers every
/// field of `record`, so callers must fill `signature` last.
///
/// # Errors
///
/// `sign failed` when ML-DSA signing fails.
pub fn sign_record(
    device: &DeviceSignKey,
    record: &SyncRecord,
) -> Result<Vec<u8>, SessionError> {
    pq::sync_sign(&*device.seed, SYNC_CTX, &record.signed_message())
        .map_err(|_| SessionError::SignFailed)
}

/// Verify one record payload. Binds the record to `vault_id` before any
/// ciphertext is touched.
///
/// # Errors
///
/// `signature length` for a wrong-length signature; otherwise propagates
/// [`pq::sync_verify`] (verification failure included).
pub fn verify_record(
    device_vk: &[u8; SYNC_VK_LEN],
    record: &SyncRecord,
    vault_id: &[u8; 16],
) -> anyhow::Result<()> {
    if vault_id != &record.vault_id {
        return Err(anyhow::anyhow!("vault id mismatch"));
    }
    let msg = record.signed_message();
    pq::sync_verify(device_vk, SYNC_CTX, &msg, &record.signature)
}

/// Per-device ML-DSA signing key. `seed` zeroizes on drop.
#[derive(Debug)]
pub struct DeviceSignKey {
    seed: Zeroizing<[u8; SYNC_SEED_LEN]>,
    key: pq::SigningKeyMirror,
}

impl DeviceSignKey {
    /// Derive a device key from `seed`. In production the seed comes from the
    /// platform keychain; tests use fixed bytes.
    #[must_use]
    pub fn from_seed(seed: &[u8; SYNC_SEED_LEN]) -> Self {
        let key = pq::signing_key_from_seed(seed);
        Self { seed: Zeroizing::new(*seed), key }
    }

    /// The verifying key the account root certifies and servers pin.
    ///
    /// # Errors
    ///
    /// Propagates the ML-DSA encoding error, if any.
    pub fn verifying_key(&self) -> anyhow::Result<[u8; SYNC_VK_LEN]> {
        pq::verifying_key_of(&self.key)
    }

    /// Raw ML-DSA seed (already cloned; the source zeroizes independently).
    #[must_use]
    pub fn seed(&self) -> [u8; SYNC_SEED_LEN] {
        *self.seed
    }
}

/// A root-signed statement binding a device verifying key to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    /// Account id (`kdf::client_id`), binds the cert to one account.
    pub client_id: [u8; 64],
    /// ML-DSA-65 verifying key of the device.
    pub device_vk: [u8; SYNC_VK_LEN],
    /// Expiry in ms since the Unix epoch.
    pub not_after_ms: u64,
    /// Server-side certificate serial for revocation lists.
    pub serial: u64,
    /// ML-DSA-65 signature over [`DeviceCert::signed_message`].
    pub signature: Vec<u8>,
}

impl DeviceCert {
    /// Bytes the root signs: L-prefixed fields, like [`record_message`].
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(2 + 64 + 2 + SYNC_VK_LEN + 2 + 8 + 2 + 8);
        msg.extend_from_slice(&64u16.to_le_bytes());
        msg.extend_from_slice(&self.client_id);
        msg.extend_from_slice(
            &u16::try_from(SYNC_VK_LEN).unwrap_or(u16::MAX).to_le_bytes(),
        );
        msg.extend_from_slice(&self.device_vk);
        msg.extend_from_slice(&8u16.to_le_bytes());
        msg.extend_from_slice(&self.not_after_ms.to_le_bytes());
        msg.extend_from_slice(&8u16.to_le_bytes());
        msg.extend_from_slice(&self.serial.to_le_bytes());
        msg
    }

    /// Verify against the account root key at time `now_ms`.
    ///
    /// # Errors
    ///
    /// `device cert rejected` on a wrong-length signature or a failed
    /// verification; `device cert expired` when `now_ms > not_after_ms`.
    pub fn verify(&self, root_vk: &[u8; SYNC_VK_LEN], now_ms: u64) -> anyhow::Result<()> {
        if now_ms > self.not_after_ms {
            return Err(anyhow::anyhow!("device cert expired"));
        }
        pq::sync_verify(root_vk, DEVICE_CERT_CTX, &self.signed_message(), &self.signature)
            .map_err(|_| anyhow::anyhow!("device cert rejected"))
    }
}

/// Issue a device certificate: the root signs the device verifying key.
///
/// # Errors
///
/// `sign failed` when ML-DSA signing fails.
pub fn issue_device_cert(
    root_seed: &[u8; SYNC_SEED_LEN],
    client_id: &[u8; 64],
    device_vk: &[u8; SYNC_VK_LEN],
    not_after_ms: u64,
    serial: u64,
) -> Result<DeviceCert, SessionError> {
    let cert = DeviceCert {
        client_id: *client_id,
        device_vk: *device_vk,
        not_after_ms,
        serial,
        signature: Vec::new(),
    };
    let signature = pq::sync_sign(root_seed, DEVICE_CERT_CTX, &cert.signed_message())
        .map_err(|_| SessionError::SignFailed)?;
    Ok(DeviceCert { signature, ..cert })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "unit tests may unwrap and index"
    )]

    use super::{
        issue_device_cert, record_message, sign_record, verify_record, DeviceSignKey, SyncRecord,
        MSG_VERSION,
    };
    use crate::error::SessionError;

    #[test]
    fn signs_and_verifies_with_version_and_generation() {
        let device = DeviceSignKey::from_seed(&[7u8; 32]);
        let other = DeviceSignKey::from_seed(&[8u8; 32]);
        let vault = [1u8; 16];
        let hash = [2u8; 32];
        let ct = vec![9u8; 100];
        let vk = device.verifying_key().unwrap();
        let unsigned = SyncRecord {
            vault_id: vault,
            record_id: 3,
            revision: 11,
            content_hash: hash,
            msg_version: MSG_VERSION,
            key_generation: 4,
            frame: ct.clone(),
            signature: Vec::new(),
        };
        let signature = sign_record(&device, &unsigned).unwrap();
        let record = SyncRecord { signature, ..unsigned };
        verify_record(&vk, &record, &vault).unwrap();

        let mut flipped = ct;
        *flipped.get_mut(0).unwrap() ^= 1;
        let tampered = SyncRecord { frame: flipped, ..record.clone() };
        assert!(verify_record(&vk, &tampered, &vault).is_err());
        let rolled = SyncRecord { revision: 12, ..record.clone() };
        assert!(verify_record(&vk, &rolled, &vault).is_err());
        let foreign = SyncRecord { vault_id: [9u8; 16], ..record.clone() };
        assert!(verify_record(&vk, &foreign, &vault).is_err());
        let swapped = SyncRecord { record_id: 4, ..record.clone() };
        assert!(verify_record(&vk, &swapped, &vault).is_err());
        let wrong = SyncRecord { key_generation: 5, ..record.clone() };
        assert!(verify_record(&vk, &wrong, &vault).is_err());
        assert!(verify_record(&other.verifying_key().unwrap(), &record, &vault).is_err());
        let short = SyncRecord { signature: record.signature[..100].to_vec(), ..record };
        assert!(verify_record(&vk, &short, &vault).is_err());
    }

    #[test]
    fn message_is_length_prefixed_with_new_fields() {
        let a = record_message(&[1u8; 16], 1, 1, &[2u8; 32], &[3u8; 10], MSG_VERSION, 0);
        let b = record_message(&[1u8; 16], 1, 1, &[2u8; 32], &[3u8; 9], MSG_VERSION, 0);
        assert_ne!(a, b);
        assert_eq!(a.len(), 2 + 16 + 2 + 4 + 2 + 8 + 2 + 32 + 2 + 4 + 2 + 2 + 2 + 4 + 10);
    }

    #[test]
    fn oversize_ciphertext_is_rejected_not_saturated() {
        assert!(matches!(
            super::ct_len_prefix(u32::MAX as usize + 1),
            Err(SessionError::CiphertextTooLarge)
        ));
        assert_eq!(super::ct_len_prefix(u32::MAX as usize).unwrap(), [0xFF; 4]);
    }

    #[test]
    fn certificates_expire_and_reject_swap() {
        let root = DeviceSignKey::from_seed(&[7u8; 32]);
        let device = DeviceSignKey::from_seed(&[8u8; 32]);
        let client = [3u8; 64];
        let vk = device.verifying_key().unwrap();
        let cert = issue_device_cert(&root.seed(), &client, &vk, 1_000, 1).unwrap();
        cert.verify(&root.verifying_key().unwrap(), 999).unwrap();
        assert!(cert.verify(&root.verifying_key().unwrap(), 1_001).is_err());

        let mut forged = cert;
        forged.device_vk = other_vk(&[9u8; 32]);
        assert!(forged.verify(&root.verifying_key().unwrap(), 999).is_err());
    }

    fn other_vk(seed: &[u8; 32]) -> [u8; pq::SYNC_VK_LEN] {
        DeviceSignKey::from_seed(seed).verifying_key().unwrap()
    }
}
