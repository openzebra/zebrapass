//! Where a device can be reached, signed by that device.
//!
//! A member that learns another member's address from a third party needs to
//! know the address really is that member's and was not planted. A peer record
//! names the vault and the addresses, is signed with the device key, and
//! carries the device certificate, so it only counts for an account the member
//! log lists.

use pq::{sync_sign, sync_verify, PEER_CTX, SYNC_VK_LEN};

use crate::error::SessionError;
use crate::sync_msg::frame_parts;
use crate::sync_sig::{DeviceCert, DeviceSignKey};

const DOMAIN_PEER: &[u8] = b"brby/v2/peer-record";

/// Most addresses one record lists.
pub const MAX_HINTS: usize = 4;
/// Longest address, in bytes.
pub const MAX_HINT_LEN: usize = 64;
/// How long a record stays believable.
pub const PEER_MAX_AGE_MS: u64 = 3 * 24 * 60 * 60 * 1000;
/// Clock difference tolerated for a record from the future.
const SKEW_MS: u64 = 5 * 60 * 1000;

/// A device's signed list of addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRecord {
    /// The vault the addresses are for.
    pub vault_id: [u8; 16],
    /// When the device signed it, in Unix milliseconds.
    pub issued_ms: u64,
    /// Socket addresses, as `ip:port`.
    pub hints: Vec<String>,
    /// Certificate of the signing device.
    pub signer: DeviceCert,
    /// ML-DSA-65 signature over [`PeerRecord::signed_message`].
    pub signature: Vec<u8>,
}

impl PeerRecord {
    /// Sign `hints` as this device.
    ///
    /// # Errors
    ///
    /// Too many or too long addresses, and signing failures.
    pub fn sign(
        key: &DeviceSignKey,
        cert: &DeviceCert,
        vault_id: [u8; 16],
        hints: Vec<String>,
        now_ms: u64,
    ) -> anyhow::Result<Self> {
        let unsigned = Self {
            vault_id,
            issued_ms: now_ms,
            hints,
            signer: cert.clone(),
            signature: Vec::new(),
        };
        unsigned.check_shape()?;
        let signature = sync_sign(key.seed(), PEER_CTX, &unsigned.signed_message()?)
            .map_err(|_| SessionError::SignFailed)?;
        Ok(Self {
            signature,
            ..unsigned
        })
    }

    fn check_shape(&self) -> anyhow::Result<()> {
        let fits = self.hints.len() <= MAX_HINTS
            && self
                .hints
                .iter()
                .all(|hint| !hint.is_empty() && hint.len() <= MAX_HINT_LEN);
        if fits {
            Ok(())
        } else {
            Err(anyhow::anyhow!("invalid peer record"))
        }
    }

    /// Bytes the device signs.
    ///
    /// # Errors
    ///
    /// `sync field too long` when a part does not fit a `u16` length.
    pub fn signed_message(&self) -> anyhow::Result<Vec<u8>> {
        let count = u16::try_from(self.hints.len())?.to_be_bytes();
        let serial = self.signer.serial.to_be_bytes();
        let issued = self.issued_ms.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![
            DOMAIN_PEER,
            &self.vault_id,
            &self.signer.device_id,
            &serial,
            &self.signer.client_id,
            &issued,
            &count,
        ];
        parts.extend(self.hints.iter().map(String::as_bytes));
        frame_parts(&parts)
    }

    /// Verify the shape, the freshness at `now_ms`, the signer's certificate
    /// against its account root, and the signature.
    ///
    /// # Errors
    ///
    /// `device cert rejected` for every failure.
    pub fn verify(&self, root_vk: &[u8; SYNC_VK_LEN], now_ms: u64) -> Result<(), SessionError> {
        let fresh = self.issued_ms <= now_ms.saturating_add(SKEW_MS)
            && now_ms.saturating_sub(self.issued_ms) <= PEER_MAX_AGE_MS;
        if !fresh || self.check_shape().is_err() {
            return Err(SessionError::CertRejected);
        }
        self.signer
            .verify(root_vk, now_ms)
            .map_err(|_| SessionError::CertRejected)?;
        let message = self
            .signed_message()
            .map_err(|_| SessionError::CertRejected)?;
        sync_verify(&self.signer.device_vk, PEER_CTX, &message, &self.signature)
            .map_err(|_| SessionError::CertRejected)
    }
}
