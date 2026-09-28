//! Find vaults on this device: `<data dir>/vaults/<vault_id hex>/vault.brby`.

use std::path::{Path, PathBuf};

use local::Paths;

use crate::vault::limits::MAX_VAULTS;

/// A vault known by location. Nothing here is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRef {
    /// File locations.
    pub paths: Paths,
    /// Vault id from the directory name, when it follows the layout.
    pub vault_id: Option<[u8; 16]>,
}

/// The data directory: the override, or the platform default.
///
/// # Errors
///
/// `home directory not found` from [`local::base_dir`].
pub fn data_dir(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    explicit.map_or_else(local::base_dir, |dir| Ok(dir.to_path_buf()))
}

/// Every vault directory under `base` that holds a vault file, sorted.
#[must_use]
pub fn discover(base: &Path) -> Vec<VaultRef> {
    let Ok(entries) = std::fs::read_dir(base.join("vaults")) else {
        return Vec::new();
    };
    let mut found: Vec<VaultRef> = entries
        .filter_map(Result::ok)
        .take(MAX_VAULTS)
        .filter_map(|entry| parse_hex_id(&entry.file_name().to_string_lossy()))
        .map(|id| VaultRef {
            paths: local::paths_for(base, &id),
            vault_id: Some(id),
        })
        .filter(|vault| vault.paths.vault_file.is_file())
        .collect();
    found.sort_by_key(|vault| vault.vault_id);
    found
}

/// A vault given as an explicit file path. Its `local.meta` is the sibling.
#[must_use]
pub fn from_file(path: &Path) -> VaultRef {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let vault_id = dir
        .file_name()
        .and_then(|name| parse_hex_id(&name.to_string_lossy()));
    let base = dir
        .parent()
        .and_then(Path::parent)
        .filter(|_| vault_id.is_some())
        .unwrap_or(dir);
    VaultRef {
        paths: Paths {
            base: base.to_path_buf(),
            vault_file: path.to_path_buf(),
            local_meta: dir.join("local.meta"),
            device_key: dir.join("device.key"),
        },
        vault_id,
    }
}

fn parse_hex_id(name: &str) -> Option<[u8; 16]> {
    if name.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (slot, pair) in id.iter_mut().zip(name.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{from_file, parse_hex_id};

    #[test]
    fn hex_ids_round_trip_and_reject_garbage() {
        assert_eq!(
            parse_hex_id("00ff".repeat(8).as_str()),
            Some([0x00, 0xFF].repeat(8).try_into().unwrap_or([0; 16]))
        );
        assert_eq!(parse_hex_id("zz"), None);
        assert_eq!(parse_hex_id(&"g".repeat(32)), None);
    }

    #[test]
    fn explicit_file_uses_sibling_meta() {
        let vault = from_file(Path::new("/tmp/elsewhere/vault.brby"));
        assert_eq!(
            vault.paths.local_meta,
            Path::new("/tmp/elsewhere/local.meta")
        );
        assert!(vault.vault_id.is_none());
    }
}
