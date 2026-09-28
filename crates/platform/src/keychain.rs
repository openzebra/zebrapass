//! Small per-account secrets: the macOS login keychain, or an in-memory store
//! for tests. Values leave as zeroizing buffers; nothing here formats them.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

/// A store that keeps one small secret per account name.
pub trait SecretStore {
    /// Whether the store can be used on this machine.
    fn capability(&self) -> crate::Capability;

    /// Store `secret` under `account`, replacing any previous value.
    ///
    /// # Errors
    ///
    /// `secret store unavailable` or a backend write failure.
    fn put(&self, account: &str, secret: &[u8]) -> anyhow::Result<()>;

    /// The secret under `account`, or `None` when there is none.
    ///
    /// # Errors
    ///
    /// `secret store unavailable` or a backend read failure (including a
    /// denied access prompt).
    fn get(&self, account: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;

    /// Remove the secret under `account`; a missing account is not an error.
    ///
    /// # Errors
    ///
    /// `secret store unavailable` or a backend delete failure.
    fn delete(&self, account: &str) -> anyhow::Result<()>;
}

/// In-memory store for tests. Not for production: values die with the process.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryStore")
    }
}

impl SecretStore for MemoryStore {
    fn capability(&self) -> crate::Capability {
        crate::Capability {
            present: true,
            gated: false,
            kind: "memory",
        }
    }

    fn put(&self, account: &str, secret: &[u8]) -> anyhow::Result<()> {
        self.items
            .lock()
            .map_err(|_| anyhow::anyhow!("secret store unavailable"))?
            .insert(account.to_owned(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn get(&self, account: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        let items = self
            .items
            .lock()
            .map_err(|_| anyhow::anyhow!("secret store unavailable"))?;
        Ok(items
            .get(account)
            .map(|value| Zeroizing::new(value.to_vec())))
    }

    fn delete(&self, account: &str) -> anyhow::Result<()> {
        self.items
            .lock()
            .map_err(|_| anyhow::anyhow!("secret store unavailable"))?
            .remove(account);
        Ok(())
    }
}

/// The macOS login keychain: generic passwords under service `zebrapass`.
///
/// Items are readable by this binary without a prompt; any other program
/// (or a rebuilt binary) triggers the system access dialog.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub struct MacKeychain;

#[cfg(target_os = "macos")]
const SERVICE: &str = "zebrapass";

/// `errSecItemNotFound`.
#[cfg(target_os = "macos")]
const ITEM_NOT_FOUND: i32 = -25_300;

#[cfg(target_os = "macos")]
impl SecretStore for MacKeychain {
    fn capability(&self) -> crate::Capability {
        crate::Capability {
            present: true,
            gated: false,
            kind: "macos-keychain",
        }
    }

    fn put(&self, account: &str, secret: &[u8]) -> anyhow::Result<()> {
        security_framework::passwords::set_generic_password(SERVICE, account, secret)
            .map_err(|_| anyhow::anyhow!("keychain write failed"))
    }

    fn get(&self, account: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        match security_framework::passwords::get_generic_password(SERVICE, account) {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(anyhow::anyhow!("keychain read failed")),
        }
    }

    fn delete(&self, account: &str) -> anyhow::Result<()> {
        match security_framework::passwords::delete_generic_password(SERVICE, account) {
            Err(error) if error.code() != ITEM_NOT_FOUND => {
                Err(anyhow::anyhow!("keychain delete failed"))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{MemoryStore, SecretStore};

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let store = MemoryStore::default();
        assert!(store.get("a").unwrap().is_none());
        store.put("a", b"one").unwrap();
        store.put("a", b"two").unwrap();
        assert_eq!(store.get("a").unwrap().unwrap().as_slice(), b"two");
        store.delete("a").unwrap();
        store.delete("a").unwrap();
        assert!(store.get("a").unwrap().is_none());
        assert_eq!(format!("{store:?}"), "MemoryStore");
    }
}
