//! Device revocation: a signed statement that one device certificate of an
//! account is no longer trusted.
//!
//! Any enrolled device of the account may sign one, so a lost device can be
//! cut off at once; the account root seed is not needed. A revocation does
//! not undo itself and a compromised device can only revoke, never enroll.
//! Revoking a device is paired with a vault-key rotation: the revocation
//! stops the handshake and the sync metadata, the rotation stops the data.

use pq::{sync_sign, sync_verify, REVOKE_CTX, SYNC_VK_LEN};

use crate::error::SessionError;
use crate::sync_msg::frame_parts;
use crate::sync_sig::{DeviceCert, DeviceSignKey};

const DOMAIN_REVOCATION: &[u8] = b"brby/v2/revocation";

/// A signed revocation of one device certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// Account the revoked device belongs to.
    pub client_id: [u8; 64],
    /// The revoked device.
    pub device_id: [u8; 16],
    /// Serial of the revoked certificate; a freshly enrolled certificate for
    /// the same device id has another serial and is not affected.
    pub serial: u64,
    /// When the revocation was signed, in unix milliseconds.
    pub revoked_at_ms: u64,
    /// Certificate of the device that signed this revocation.
    pub signer: DeviceCert,
    /// ML-DSA-65 signature over [`Revocation::signed_message`].
    pub signature: Vec<u8>,
}

impl Revocation {
    /// Bytes the signer signs.
    ///
    /// # Errors
    ///
    /// `sync field too long` when a part does not fit a `u16` length.
    pub fn signed_message(&self) -> anyhow::Result<Vec<u8>> {
        frame_parts(&[
            DOMAIN_REVOCATION,
            &self.client_id,
            &self.device_id,
            &self.serial.to_be_bytes(),
            &self.revoked_at_ms.to_be_bytes(),
            &self.signer.device_id,
            &self.signer.serial.to_be_bytes(),
        ])
    }

    /// Verify against the account root key: the signer's certificate must
    /// chain to `root_vk`, belong to the same account and be unexpired at
    /// `now_ms`, and the signature must verify under its key.
    ///
    /// # Errors
    ///
    /// `revocation rejected` for every failure.
    pub fn verify(&self, root_vk: &[u8; SYNC_VK_LEN], now_ms: u64) -> anyhow::Result<()> {
        let rejected = || anyhow::anyhow!("revocation rejected");
        if self.signer.client_id != self.client_id {
            return Err(rejected());
        }
        self.signer
            .verify(root_vk, now_ms)
            .map_err(|_| rejected())?;
        let message = self.signed_message().map_err(|_| rejected())?;
        sync_verify(
            &self.signer.device_vk,
            REVOKE_CTX,
            &message,
            &self.signature,
        )
        .map_err(|_| rejected())
    }

    /// Whether this revokes `cert`.
    #[must_use]
    pub fn covers(&self, cert: &DeviceCert) -> bool {
        self.client_id == cert.client_id
            && self.device_id == cert.device_id
            && self.serial == cert.serial
    }
}

/// Sign a revocation of `target` with this device's key.
///
/// # Errors
///
/// `cert rejected` when `target` belongs to another account than `signer`;
/// `sign failed` when ML-DSA signing fails.
pub fn issue_revocation(
    signer_key: &DeviceSignKey,
    signer: &DeviceCert,
    target: &DeviceCert,
    revoked_at_ms: u64,
) -> Result<Revocation, SessionError> {
    if signer.client_id != target.client_id {
        return Err(SessionError::CertRejected);
    }
    let unsigned = Revocation {
        client_id: target.client_id,
        device_id: target.device_id,
        serial: target.serial,
        revoked_at_ms,
        signer: signer.clone(),
        signature: Vec::new(),
    };
    let message = unsigned
        .signed_message()
        .map_err(|_| SessionError::SignFailed)?;
    let signature =
        sync_sign(signer_key.seed(), REVOKE_CTX, &message).map_err(|_| SessionError::SignFailed)?;
    Ok(Revocation {
        signature,
        ..unsigned
    })
}
