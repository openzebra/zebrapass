//! Public facts about the open vault.

use local::{device_key_info, DeviceKeyInfo, Prefs};
use session::WrapDirectory;

use crate::vault::Vault;

/// Public facts about the open vault, kept while a job holds the vault.
#[derive(Clone, Debug)]
pub struct VaultInfo {
    /// Display name.
    pub label: String,
    /// Vault id.
    pub vault_id: [u8; 16],
    /// Account client id.
    pub client_id: [u8; 64],
    /// Device id this session stamps into frames.
    pub origin: [u8; 16],
    /// Directory generation.
    pub generation: u64,
    /// Wrap directory.
    pub directory: WrapDirectory,
    /// Public header of this device's key file, when it has one.
    pub device: Option<DeviceKeyInfo>,
    /// Saved preferences; `None` until this device saves some.
    pub prefs: Option<Prefs>,
}

impl VaultInfo {
    /// The device wrap this machine holds a key file for.
    #[must_use]
    pub fn owned_device(&self) -> Option<[u8; 16]> {
        self.device.map(|device| device.id)
    }
}

impl From<&Vault> for VaultInfo {
    fn from(vault: &Vault) -> Self {
        Self {
            label: vault.label(),
            vault_id: *vault.session.vault_id(),
            client_id: vault.meta.client_id,
            origin: vault.session.origin_device(),
            generation: vault.session.generation(),
            directory: vault.directory.clone(),
            device: device_key_info(&vault.paths.device_key).ok(),
            prefs: vault.meta.prefs.clone(),
        }
    }
}
