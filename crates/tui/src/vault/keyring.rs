//! This device's unlock factor: a device wrap (X25519 + ML-KEM hybrid) whose
//! secrets live in the OS secret store, one item per vault.
//!
//! macOS uses the login keychain. Elsewhere, and whenever the keychain is
//! switched off, keys live in memory and die with the process.

use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use platform::MacKeychain;
use platform::{MemoryStore, SecretStore};
use session::{enroll_device, DeviceKeys, Session, VaultFile};

/// Where device keys are kept.
enum Store {
    /// The OS keychain.
    #[cfg(target_os = "macos")]
    Os(MacKeychain),
    /// Process memory only.
    Memory(MemoryStore),
}

impl Store {
    fn put(&self, account: &str, secret: &[u8]) -> anyhow::Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Os(store) => store.put(account, secret),
            Self::Memory(store) => store.put(account, secret),
        }
    }

    fn get(&self, account: &str) -> anyhow::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Os(store) => store.get(account),
            Self::Memory(store) => store.get(account),
        }
    }

    fn delete(&self, account: &str) -> anyhow::Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Os(store) => store.delete(account),
            Self::Memory(store) => store.delete(account),
        }
    }
}

/// Handle to the device-key store, shared with the worker thread.
#[derive(Clone)]
pub struct Keyring {
    store: Arc<Store>,
    /// Device wrap ids whose keys this store was seen to hold.
    owned: Arc<Mutex<Vec<[u8; 16]>>>,
}

impl Default for Keyring {
    fn default() -> Self {
        Self::memory()
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl Keyring {
    /// The OS keychain when this platform has one, memory otherwise.
    #[must_use]
    pub fn os() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::with(Store::Os(MacKeychain))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::memory()
        }
    }

    /// Keys in process memory only.
    #[must_use]
    pub fn memory() -> Self {
        Self::with(Store::Memory(MemoryStore::default()))
    }

    fn with(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            owned: Arc::default(),
        }
    }

    /// `"macOS keychain"` or `"memory only"`, for the UI.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match *self.store {
            #[cfg(target_os = "macos")]
            Store::Os(_) => "macOS keychain",
            Store::Memory(_) => "memory only",
        }
    }

    /// Whether keys survive the process.
    #[must_use]
    pub fn persistent(&self) -> bool {
        !matches!(*self.store, Store::Memory(_))
    }

    /// Whether this store holds the keys behind device wrap `id`. Only
    /// answers from what [`Self::keys`] and [`Self::enroll`] have seen, so it
    /// never touches the keychain.
    #[must_use]
    pub fn owns(&self, id: &[u8; 16]) -> bool {
        self.owned.lock().is_ok_and(|owned| owned.contains(id))
    }

    /// Generate device keys, store them, and add a device wrap (with its
    /// public keys in the device book) to the vault.
    ///
    /// The keys are stored first: a failed enrollment leaves no wrap that
    /// nothing can open, and the stored item is removed again.
    ///
    /// # Errors
    ///
    /// Entropy, secret-store, and `session::enroll_device` errors.
    pub fn enroll(&self, session: &mut Session, file: &mut VaultFile) -> anyhow::Result<()> {
        let keys = DeviceKeys::generate()?;
        let account = account(session.vault_id());
        self.store.put(&account, keys.to_bytes().as_slice())?;
        let enrolled = keys
            .publics()
            .and_then(|publics| enroll_device(session, file, &publics));
        if let Err(error) = enrolled {
            let _ = self.store.delete(&account);
            return Err(error);
        }
        self.remember(keys.id);
        Ok(())
    }

    /// This device's keys for `vault_id`, when the store has them.
    ///
    /// # Errors
    ///
    /// Secret-store read errors; `corrupted length` for a damaged item.
    pub fn keys(&self, vault_id: &[u8; 16]) -> anyhow::Result<Option<DeviceKeys>> {
        let Some(bytes) = self.store.get(&account(vault_id))? else {
            return Ok(None);
        };
        let keys = DeviceKeys::try_from(bytes.as_slice())?;
        self.remember(keys.id);
        Ok(Some(keys))
    }

    /// Delete the keys for `vault_id` if they belong to device wrap `id`.
    pub fn forget(&self, vault_id: &[u8; 16], id: &[u8; 16]) {
        let ours = self
            .keys(vault_id)
            .ok()
            .flatten()
            .is_some_and(|keys| keys.id == *id);
        if ours {
            let _ = self.store.delete(&account(vault_id));
        }
        if let Ok(mut owned) = self.owned.lock() {
            owned.retain(|known| known != id);
        }
    }

    fn remember(&self, id: [u8; 16]) {
        if let Ok(mut owned) = self.owned.lock() {
            if !owned.contains(&id) {
                owned.push(id);
            }
        }
    }
}

/// Keychain account for one vault: `device/<vault id hex>`.
fn account(vault_id: &[u8; 16]) -> String {
    format!(
        "device/{}",
        local::vault_dir_name(vault_id).trim_start_matches("vaults/")
    )
}
