//! Sync signatures: one ML-DSA key per device, certified by the account root.
//!
//! The signed message is length-prefixed so a verifier cannot shift the
//! boundary between fields, and carries the message version and the vault-key
//! generation so a signature cannot be replayed across format changes or key
//! epochs. The server verifies signatures but never sees plaintext: the
//! signed ciphertext is the sealed frame.

use zeroize::Zeroizing;

pub use pq::{sync_verifying_key, DEVICE_CERT_CTX, SYNC_CTX, SYNC_SEED_LEN, SYNC_VK_LEN};

#[allow(clippy::cast_possible_truncation)]
const SYNC_VK_LEN_U16: u16 = {
    assert!(SYNC_VK_LEN <= u16::MAX as usize);
    SYNC_VK_LEN as u16
};

use crate::error::SessionError;
use crate::sync_msg::{record_message, MSG_VERSION, MSG_VERSION_V1};

/// Length prefix for the ciphertext tail of a version-1 message.
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

/// One signed sync record, ready for the server wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// Account id (`kdf::client_id`) of the sender.
    pub client_id: [u8; 64],
    /// SHA-256 of the frame this revision supersedes on the sender; zero
    /// for the first revision. A server uses it for compare-and-swap.
    pub prev_hash: [u8; 32],
    /// SHA-256 of the frame ciphertext.
    pub content_hash: [u8; 32],
    /// Vault the record belongs to; must equal the session vault id.
    pub vault_id: [u8; 16],
    /// Device that sealed and signed the frame; equals the frame origin.
    pub device_id: [u8; 16],
    /// Record the frame carries.
    pub record_id: u32,
    /// Monotonic per-record counter; strictly newer than anything stored.
    pub revision: u64,
    /// Wire format version (`MSG_VERSION`).
    pub msg_version: u16,
    /// Vault-key generation the frame was written under.
    pub key_generation: u32,
    /// Server origin the record is addressed to; empty until a sync
    /// server exists.
    pub server_origin: Box<[u8]>,
    /// The sealed frame, as written to the vault body.
    pub frame: Vec<u8>,
    /// ML-DSA-65 signature over [`record_message`].
    pub signature: Vec<u8>,
}

impl SyncRecord {
    /// Rebuild the signed message for `self`.
    ///
    /// # Errors
    ///
    /// As in [`record_message`].
    pub fn signed_message(&self) -> anyhow::Result<Vec<u8>> {
        record_message(self)
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
/// field of `record`, so callers must fill `signature` last. Only the
/// current [`MSG_VERSION`] is ever signed.
///
/// # Errors
///
/// `sign failed` when ML-DSA signing fails; `unsupported sync message
/// version` for any other version.
pub fn sign_record(device: &DeviceSignKey, record: &SyncRecord) -> Result<Vec<u8>, SessionError> {
    if record.msg_version != MSG_VERSION {
        return Err(SessionError::UnsupportedMsgVersion);
    }
    let msg = record
        .signed_message()
        .map_err(|_| SessionError::UnsupportedMsgVersion)?;
    pq::sync_sign(&*device.seed, SYNC_CTX, &msg).map_err(|_| SessionError::SignFailed)
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
    if !matches!(record.msg_version, MSG_VERSION | MSG_VERSION_V1) {
        return Err(anyhow::anyhow!("unsupported sync message version"));
    }
    let msg = record.signed_message()?;
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
        Self {
            seed: Zeroizing::new(*seed),
            key,
        }
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
        msg.extend_from_slice(&SYNC_VK_LEN_U16.to_le_bytes());
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
        pq::sync_verify(
            root_vk,
            DEVICE_CERT_CTX,
            &self.signed_message(),
            &self.signature,
        )
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

    use sha2::{Digest, Sha256};

    use super::{issue_device_cert, sign_record, verify_record, DeviceSignKey, SyncRecord};
    use crate::error::SessionError;
    use crate::sync_msg::{record_message, MSG_VERSION, MSG_VERSION_V1};

    fn unsigned(frame: Vec<u8>) -> SyncRecord {
        SyncRecord {
            client_id: [5u8; 64],
            prev_hash: [6u8; 32],
            content_hash: Sha256::digest(&frame).into(),
            vault_id: [1u8; 16],
            device_id: [2u8; 16],
            record_id: 3,
            revision: 11,
            msg_version: MSG_VERSION,
            key_generation: 4,
            server_origin: Box::from(&b"https://sync.example"[..]),
            frame,
            signature: Vec::new(),
        }
    }

    #[test]
    fn every_bound_field_breaks_the_signature() {
        let device = DeviceSignKey::from_seed(&[7u8; 32]);
        let other = DeviceSignKey::from_seed(&[8u8; 32]);
        let vault = [1u8; 16];
        let vk = device.verifying_key().unwrap();
        let base = unsigned(vec![9u8; 100]);
        let record = SyncRecord {
            signature: sign_record(&device, &base).unwrap(),
            ..base
        };
        verify_record(&vk, &record, &vault).unwrap();

        let mut flipped = record.frame.clone();
        flipped[0] ^= 1;
        let variants = [
            SyncRecord {
                content_hash: Sha256::digest(&flipped).into(),
                frame: flipped,
                ..record.clone()
            },
            SyncRecord {
                revision: 12,
                ..record.clone()
            },
            SyncRecord {
                record_id: 4,
                ..record.clone()
            },
            SyncRecord {
                key_generation: 5,
                ..record.clone()
            },
            SyncRecord {
                client_id: [0u8; 64],
                ..record.clone()
            },
            SyncRecord {
                device_id: [0u8; 16],
                ..record.clone()
            },
            SyncRecord {
                prev_hash: [0u8; 32],
                ..record.clone()
            },
            SyncRecord {
                server_origin: Box::from(&b"https://evil.example"[..]),
                ..record.clone()
            },
            SyncRecord {
                msg_version: MSG_VERSION_V1,
                ..record.clone()
            },
        ];
        for variant in &variants {
            assert!(verify_record(&vk, variant, &vault).is_err());
        }
        let foreign = SyncRecord {
            vault_id: [9u8; 16],
            ..record.clone()
        };
        assert!(verify_record(&vk, &foreign, &[9u8; 16]).is_err());
        assert!(verify_record(&vk, &record, &[9u8; 16]).is_err());
        assert!(verify_record(&other.verifying_key().unwrap(), &record, &vault).is_err());
        let short = SyncRecord {
            signature: record.signature[..100].to_vec(),
            ..record
        };
        assert!(verify_record(&vk, &short, &vault).is_err());
    }

    #[test]
    fn content_hash_must_match_frame() {
        let record = SyncRecord {
            content_hash: [0u8; 32],
            ..unsigned(vec![1u8; 10])
        };
        assert_eq!(
            record_message(&record).unwrap_err().to_string(),
            "content hash mismatch"
        );
    }

    #[test]
    fn v1_messages_verify_but_are_never_signed() {
        let device = DeviceSignKey::from_seed(&[7u8; 32]);
        let legacy = SyncRecord {
            msg_version: MSG_VERSION_V1,
            ..unsigned(vec![3u8; 10])
        };
        assert!(matches!(
            sign_record(&device, &legacy),
            Err(SessionError::UnsupportedMsgVersion)
        ));
        let msg = record_message(&legacy).unwrap();
        assert_eq!(
            msg.len(),
            2 + 16 + 2 + 4 + 2 + 8 + 2 + 32 + 2 + 4 + 2 + 2 + 2 + 4 + 10
        );
        let signature = pq::sync_sign(&device.seed(), pq::SYNC_CTX, &msg).unwrap();
        let signed = SyncRecord {
            signature,
            ..legacy
        };
        verify_record(&device.verifying_key().unwrap(), &signed, &[1u8; 16]).unwrap();
    }

    #[test]
    fn v2_message_is_domain_separated_and_framed() {
        let msg = record_message(&unsigned(vec![3u8; 10])).unwrap();
        assert_eq!(&msg[..2], &19u16.to_be_bytes());
        assert_eq!(&msg[2..21], b"brby/v2/sync-record");
        let longer = record_message(&unsigned(vec![3u8; 11])).unwrap();
        assert_ne!(msg, longer);
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
