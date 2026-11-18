//! Find vaults on this device: `<data dir>/vaults/<vault_id hex>/vault.brby`,
//! ordered with the most recently unlocked vault first.

use std::path::{Path, PathBuf};

use local::Paths;

use crate::vault::limits::{MAX_RECENT_VAULTS_BYTES, MAX_VAULTS};

const RECENT_FILE: &str = "vaults.recent";

/// A vault known by location. Nothing here is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRef {
    /// File locations.
    pub paths: Paths,
    /// Vault id from the directory name, when it follows the layout.
    pub vault_id: Option<[u8; 16]>,
    /// Whether this was the last vault unlocked on this device.
    pub last_unlocked: bool,
}

/// The data directory: the override, or the platform default.
///
/// # Errors
///
/// `home directory not found` from [`local::base_dir`].
pub fn data_dir(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    explicit.map_or_else(local::base_dir, |dir| Ok(dir.to_path_buf()))
}

/// Every vault directory under `base` that holds a vault file, ordered with
/// recently unlocked vaults first (most recent at index `0`) and remaining
/// vaults sorted by `vault_id`.
#[must_use]
pub fn discover(base: &Path) -> Vec<VaultRef> {
    let Ok(entries) = std::fs::read_dir(base.join("vaults")) else {
        return Vec::new();
    };
    let recent = load_recent_vaults(base);
    let top = recent.first().copied();
    let mut found: Vec<VaultRef> = entries
        .filter_map(Result::ok)
        .take(MAX_VAULTS)
        .filter_map(|entry| parse_hex_id(&entry.file_name().to_string_lossy()))
        .map(|id| VaultRef {
            paths: local::paths_for(base, &id),
            vault_id: Some(id),
            last_unlocked: top == Some(id),
        })
        .filter(|vault| vault.paths.vault_file.is_file())
        .collect();
    found.sort_by_key(|vault| {
        let rank = vault
            .vault_id
            .and_then(|id| recent.iter().position(|known| *known == id))
            .unwrap_or(usize::MAX);
        (rank, vault.vault_id)
    });
    found
}

/// Record `vault_id` as the most recently unlocked vault under `base`.
///
/// Stores only public 16-byte `vault_id` entries, capped at [`MAX_VAULTS`],
/// written atomically. Best-effort: UI preference persistence never blocks
/// unlocking.
pub fn remember_unlocked(base: &Path, vault_id: &[u8; 16]) {
    let mut recent = load_recent_vaults(base);
    recent.retain(|existing| existing != vault_id);
    recent.insert(0, *vault_id);
    recent.truncate(MAX_VAULTS);
    let mut bytes = Vec::with_capacity(recent.len() * 16);
    for id in &recent {
        bytes.extend_from_slice(id);
    }
    let _ = local::write_atomic(&base.join(RECENT_FILE), &bytes);
}

/// Read the bounded MRU list of public `vault_id`s under `base`.
#[must_use]
pub fn load_recent_vaults(base: &Path) -> Vec<[u8; 16]> {
    let path = base.join(RECENT_FILE);
    let Ok(meta) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    let len = meta.len();
    if len == 0 || len > MAX_RECENT_VAULTS_BYTES || !len.is_multiple_of(16) {
        return Vec::new();
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    if bytes.len() as u64 != len {
        return Vec::new();
    }
    bytes.as_chunks::<16>().0.to_vec()
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
    let last_unlocked =
        vault_id.is_some_and(|id| load_recent_vaults(base).first().copied() == Some(id));
    VaultRef {
        paths: Paths {
            base: base.to_path_buf(),
            vault_file: path.to_path_buf(),
            local_meta: dir.join("local.meta"),
            device_key: dir.join("device.key"),
        },
        vault_id,
        last_unlocked,
    }
}

fn parse_hex_id(name: &str) -> Option<[u8; 16]> {
    if name.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (slot, pair) in id.iter_mut().zip(name.as_bytes().as_chunks::<2>().0) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "tests may index")]

    use std::path::Path;

    use super::{from_file, load_recent_vaults, parse_hex_id, remember_unlocked};

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
        assert!(!vault.last_unlocked);
    }

    #[test]
    fn recent_vaults_move_latest_to_front_and_reject_bad_lengths() {
        let mut suffix = [0u8; 6];
        let _ = getrandom::fill(&mut suffix);
        let dir = std::env::temp_dir().join(format!(
            "zp-recent-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            suffix[0], suffix[1], suffix[2], suffix[3], suffix[4], suffix[5]
        ));
        let _ = std::fs::create_dir_all(&dir);
        let a = [0x11; 16];
        let b = [0x22; 16];
        remember_unlocked(&dir, &a);
        remember_unlocked(&dir, &b);
        assert_eq!(load_recent_vaults(&dir), vec![b, a]);
        remember_unlocked(&dir, &a);
        assert_eq!(load_recent_vaults(&dir), vec![a, b]);

        let _ = std::fs::write(dir.join("vaults.recent"), [1u8, 2, 3]);
        assert_eq!(load_recent_vaults(&dir), [] as [[u8; 16]; 0]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
