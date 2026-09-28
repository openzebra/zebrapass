//! On-device vault storage.
//!
//! One directory per vault under the platform data directory: `vault.brby`
//! is the container file, `local.meta` a standalone frame with this
//! device's metadata. The metadata never syncs; its key is derived from
//! the vault key with a dedicated info.

mod atomic;
mod meta;

use std::path::{Path, PathBuf};

use aead::BodyAlg;
use kdf::KdfProfile;
use session::{create, Session, VaultFile};

pub use atomic::write_atomic;
pub use meta::{load_local_meta, save_local_meta, LocalMeta, SeenCursor};

/// Locations of one vault on this device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Paths {
    /// Platform data directory passed to [`create_vault`].
    pub base: PathBuf,
    /// The container file: `vaults/<vault_id_hex>/vault.brby`.
    pub vault_file: PathBuf,
    /// This device's metadata: `vaults/<vault_id_hex>/local.meta`.
    pub local_meta: PathBuf,
}

impl Paths {
    /// The vault directory: `<base>/vaults/<vault_id_hex>`.
    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        self.vault_file.parent().unwrap_or(self.base.as_path())
    }
}

/// The platform data directory for zebrapass.
///
/// macOS: `$HOME/Library/Application Support/zebrapass`; other Unix:
/// `$XDG_DATA_HOME/zebrapass` or `$HOME/.local/share/zebrapass`; Windows:
/// `%APPDATA%\zebrapass`.
///
/// # Errors
///
/// `home directory not found` when neither the platform-specific variable
/// nor `$HOME` is set.
pub fn base_dir() -> anyhow::Result<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        let home = home_dir()?;
        home.join("Library/Application Support/zebrapass")
    } else if cfg!(windows) {
        let appdata = std::env::var_os("APPDATA")
            .ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
        PathBuf::from(appdata).join("zebrapass")
    } else {
        match std::env::var_os("XDG_DATA_HOME") {
            Some(xdg) => PathBuf::from(xdg).join("zebrapass"),
            None => home_dir()?.join(".local/share/zebrapass"),
        }
    };
    Ok(base)
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("home directory not found"))
}

/// The vault directory name for `vault_id`: `vaults/<lowercase hex>`.
#[must_use]
pub fn vault_dir_name(vault_id: &[u8; 16]) -> String {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    let mut name = String::with_capacity(7 + 32);
    name.push_str("vaults/");
    for byte in vault_id {
        // Both indexes are masked into 0..=15 before the lookup.
        name.push_str(HEX.get(usize::from(*byte >> 4)).copied().unwrap_or("0"));
        name.push_str(HEX.get(usize::from(*byte & 0x0F)).copied().unwrap_or("0"));
    }
    name
}

/// File locations for `vault_id` under `base`.
#[must_use]
pub fn paths_for(base: &Path, vault_id: &[u8; 16]) -> Paths {
    let vault_dir = base.join(vault_dir_name(vault_id));
    Paths {
        base: base.to_path_buf(),
        vault_file: vault_dir.join("vault.brby"),
        local_meta: vault_dir.join("local.meta"),
    }
}

/// Create a vault and both of its files under `base`.
///
/// Draws this device's id, derives the identity point from `seed`, seals
/// the vault through [`session::create`], then writes `vault.brby` and
/// `local.meta` atomically. The returned [`LocalMeta`] mirrors what the
/// metadata file contains.
///
/// # Errors
///
/// Errors from [`session::create`], [`kdf::client_id`], and the storage
/// layer (`os entropy failed`, `write failed`, `rename failed`,
/// `sync failed`).
pub fn create_vault(
    base: &Path,
    seed: &[u8; 64],
    profile: KdfProfile,
    body_alg: BodyAlg,
) -> anyhow::Result<(Paths, Session, VaultFile, LocalMeta)> {
    let client_id = kdf::client_id(seed)?;
    let (file, session) = create(seed, profile, body_alg)?;
    let device_id = session.origin_device();
    let vault_id = file.parse()?.header.vault_id;
    let paths = paths_for(base, &vault_id);
    write_atomic(&paths.vault_file, file.as_bytes())?;
    let meta = LocalMeta {
        device_id,
        client_id,
        created_at_ms: now_ms(),
        name: String::new(),
        seen: None,
    };
    save_local_meta(&paths.local_meta, &meta, &session.local_meta_key()?)?;
    Ok((paths, session, file, meta))
}

/// Record the file state a session holds as the last accepted one.
///
/// Call after every successful [`session::unlock`] or write: the cursor is
/// what makes replacing the vault file with an older copy fail on the next
/// unlock, without the caller tracking anything.
///
/// # Errors
///
/// Key-derivation and atomic-write errors as in [`save_local_meta`].
pub fn mark_seen(
    paths: &Paths,
    meta: &mut LocalMeta,
    session: &session::Session,
) -> anyhow::Result<()> {
    meta.seen = Some(meta::SeenCursor {
        generation: session.generation(),
        commit_tag: *session.commit_tag(),
    });
    save_local_meta(&paths.local_meta, meta, &session.local_meta_key()?)
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "tests may unwrap, index, and panic"
    )]

    use std::path::{Path, PathBuf};

    use super::{base_dir, paths_for, vault_dir_name};

    #[test]
    fn vault_dir_name_is_hex() {
        let mut two = [0u8; 16];
        two[0] = 0x00;
        two[1] = 0xAB;
        assert_eq!(
            vault_dir_name(&two),
            "vaults/00ab0000000000000000000000000000"
        );
        let all = [0xFF; 16];
        assert_eq!(vault_dir_name(&all), format!("vaults/{}", "ff".repeat(16)));
    }

    #[test]
    fn paths_live_under_base() {
        let paths = paths_for(Path::new("/data"), &[0x07; 16]);
        let dir = PathBuf::from("/data/vaults").join("07070707070707070707070707070707");
        assert_eq!(paths.vault_file, dir.join("vault.brby"));
        assert_eq!(paths.local_meta, dir.join("local.meta"));
        assert_eq!(paths.vault_dir(), dir);
    }

    #[test]
    fn base_dir_is_found() {
        // At least one platform source must exist in the test environment.
        let base = base_dir().unwrap();
        assert!(base.ends_with("zebrapass"));
    }
}
