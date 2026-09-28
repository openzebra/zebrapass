//! Secure-chip factor seam.
//!
//! Only `platform::SoftwareChip` exists today: an in-memory P-256 store for
//! development. It sits behind the `dev-chip` feature, its keys die with the
//! process, and every screen that offers it says so. Without the feature the
//! chip factor fails closed. A native keychain / secure-enclave backend plugs
//! in here.

#[cfg(feature = "dev-chip")]
use std::sync::{Arc, Mutex};

use crate::vault::keyring::Keyring;

#[cfg(feature = "dev-chip")]
use platform::{ChipBackend, SoftwareChip};
#[cfg(feature = "dev-chip")]
use session::{ChipKeys, ChipPublics, Factor, Session, UnlockCreds, VaultFile};
#[cfg(feature = "dev-chip")]
use zeroize::Zeroizing;

/// Handle to the platform key backends (the secure chip and the device-key
/// keyring), shared with the worker thread.
#[derive(Clone, Default)]
pub struct Chips {
    #[cfg(feature = "dev-chip")]
    store: Arc<ChipStore>,
    keyring: Keyring,
}

impl std::fmt::Debug for Chips {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Chips")
    }
}

#[cfg(feature = "dev-chip")]
#[derive(Default)]
struct ChipStore {
    chip: SoftwareChip,
    keys: Mutex<Vec<ChipKeys>>,
}

impl Chips {
    /// Backends with device keys in the OS keychain (`keychain`) or in memory.
    #[must_use]
    pub fn new(keychain: bool) -> Self {
        let mut chips = Self::default();
        if keychain {
            chips.keyring = Keyring::os();
        }
        chips
    }

    /// The device-key keyring.
    #[must_use]
    pub const fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Whether this build has any chip backend.
    #[must_use]
    pub const fn available() -> bool {
        cfg!(feature = "dev-chip")
    }

    /// Whether this process holds the chip key behind wrap `id`.
    #[cfg(feature = "dev-chip")]
    #[must_use]
    pub fn owns(&self, id: &[u8; 16]) -> bool {
        self.store
            .keys
            .lock()
            .is_ok_and(|keys| keys.iter().any(|key| key.id == *id))
    }

    /// Whether this process holds the chip key behind wrap `id`.
    #[cfg(not(feature = "dev-chip"))]
    #[must_use]
    pub const fn owns(&self, _id: &[u8; 16]) -> bool {
        false
    }

    /// No chip backend: nothing to forget.
    #[cfg(not(feature = "dev-chip"))]
    pub const fn forget(&self, _id: &[u8; 16]) {}
}

#[cfg(feature = "dev-chip")]
fn alias(id: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    id.iter().fold(String::from("zp/chip/"), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(feature = "dev-chip")]
impl Chips {
    /// Create a chip key and add a chip wrap for it.
    ///
    /// # Errors
    ///
    /// Backend, ML-KEM, entropy, and `session::add_chip_unlock` errors.
    pub fn enroll(&self, session: &mut Session, file: &mut VaultFile) -> anyhow::Result<()> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
        let name = alias(&id);
        let chip_pub = self.store.chip.generate_pair(&name)?;
        let (pq_public, kem_secret) = pq::keypair()?;
        let pq_pk = pq_public
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("kem length"))?;
        let publics = ChipPublics {
            id,
            chip_pub,
            pq_pk,
        };
        if let Err(error) = session::add_chip_unlock(session, file, &publics) {
            let _ = self.store.chip.delete(&name);
            return Err(error);
        }
        self.store
            .keys
            .lock()
            .map_err(|_| anyhow::anyhow!("chip store poisoned"))?
            .push(ChipKeys {
                id,
                pq_sk: kem_secret,
            });
        Ok(())
    }

    /// Unlock `file` with the first chip wrap this process owns.
    ///
    /// # Errors
    ///
    /// `no usable wrap` when no owned chip wrap is in the file; unlock errors.
    pub fn unlock(&self, file: &VaultFile) -> anyhow::Result<Session> {
        let directory = session::wrap_directory(file)?;
        let keys = self
            .store
            .keys
            .lock()
            .map_err(|_| anyhow::anyhow!("chip store poisoned"))?;
        let (key, eph_pub) = directory
            .factors
            .iter()
            .find_map(|factor| match factor {
                Factor::Chip(chip) => keys
                    .iter()
                    .find(|key| key.id == chip.publics.id)
                    .map(|key| (key, chip.eph_pub)),
                Factor::Recovery
                | Factor::Password { .. }
                | Factor::Device { .. }
                | Factor::Prf { .. } => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no usable wrap"))?;
        let shared = Zeroizing::new(self.store.chip.ecdh(&alias(&key.id), &eph_pub)?);
        let opened = session::unlock(file, &UnlockCreds::default().with_chip(key, *shared), None);
        drop(keys);
        opened
    }

    /// Delete the chip key behind wrap `id`.
    pub fn forget(&self, id: &[u8; 16]) {
        if let Ok(mut keys) = self.store.keys.lock() {
            keys.retain(|key| key.id != *id);
        }
        let _ = self.store.chip.delete(&alias(id));
    }
}
