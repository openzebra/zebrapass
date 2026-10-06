//! Signed device revocations a vault has accepted. Each entry is kept with
//! its signature so it can be passed on to a peer that missed it.

use record::{Document, ValueType, TAG_SYNC_REVOKED_MIN};
use session::{DeviceCert, Revocation, SYNC_VK_LEN};
use syncwire::{decode_revocation, encode_revocation};

use crate::limits::REVOKED_MAX;

/// The accepted revocations of one vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revocations {
    list: Vec<Revocation>,
}

impl Revocations {
    /// Every accepted revocation.
    #[must_use]
    pub fn all(&self) -> &[Revocation] {
        &self.list
    }

    /// Whether `cert` has been revoked.
    #[must_use]
    pub fn is_revoked(&self, cert: &DeviceCert) -> bool {
        self.list.iter().any(|revocation| revocation.covers(cert))
    }

    /// Accept `revocation` after verifying it against the account root key
    /// `root_vk`. A revocation that is already known is a no-op; one signed
    /// by a device that is itself revoked is refused.
    ///
    /// Returns `true` when the revocation was new.
    ///
    /// # Errors
    ///
    /// `revocation rejected` for a bad signature, certificate or expiry, or a
    /// revoked signer; `revocation list full` at the bound. The list never
    /// evicts, because forgetting a revocation would re-admit a device.
    pub fn add(
        &mut self,
        revocation: Revocation,
        root_vk: &[u8; SYNC_VK_LEN],
        now_ms: u64,
    ) -> anyhow::Result<bool> {
        revocation.verify(root_vk, now_ms)?;
        if self.is_revoked(&revocation.signer) {
            anyhow::bail!("revocation rejected");
        }
        if self.list.iter().any(|known| {
            known.client_id == revocation.client_id
                && known.device_id == revocation.device_id
                && known.serial == revocation.serial
        }) {
            return Ok(false);
        }
        if self.list.len() >= REVOKED_MAX {
            anyhow::bail!("revocation list full");
        }
        self.list.push(revocation);
        Ok(true)
    }

    pub(crate) fn write(&self, doc: &mut Document) -> anyhow::Result<()> {
        for (revocation, tag) in self.list.iter().zip(TAG_SYNC_REVOKED_MIN..) {
            doc.set_data(tag, ValueType::Bytes, &encode_revocation(revocation)?);
        }
        Ok(())
    }

    pub(crate) fn read(doc: &Document) -> anyhow::Result<Self> {
        let mut list = Vec::new();
        for tag in (TAG_SYNC_REVOKED_MIN..).take(REVOKED_MAX) {
            let Some(bytes) = doc.data(tag)? else {
                break;
            };
            list.push(decode_revocation(bytes)?);
        }
        let stray = (TAG_SYNC_REVOKED_MIN..)
            .take(REVOKED_MAX)
            .skip(list.len())
            .any(|tag| doc.get(tag).is_some());
        if stray {
            anyhow::bail!("corrupted length");
        }
        Ok(Self { list })
    }
}
