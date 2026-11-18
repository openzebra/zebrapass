//! Automatic rolling `.zpbackup` snapshot writer and retention pruner.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use session::{Session, VaultFile};

use crate::backup::build_backup_bundle;
use crate::limits::BACKUP_KEEP_MAX;
use crate::{now_ms, write_atomic};

const ROLLING_EXT: &str = ".zpbackup";

fn vault_prefix(vault_id: &[u8; 16]) -> String {
    let mut prefix = String::with_capacity(22);
    prefix.push_str("zebrapass-");
    for byte in vault_id.iter().take(4) {
        let _ = write!(prefix, "{byte:02x}");
    }
    prefix.push_str("-gen");
    prefix
}

fn parse_rolling_key(file_name: &str, prefix: &str) -> Option<(u64, u64)> {
    let rest = file_name.strip_prefix(prefix)?.strip_suffix(ROLLING_EXT)?;
    let (gen_str, ms_str) = rest.split_once('-')?;
    let generation = gen_str.parse::<u64>().ok()?;
    let ms = ms_str.parse::<u64>().ok()?;
    Some((generation, ms))
}

/// Write an automatic rolling `.zpbackup` into `dir` and prune older rolling
/// snapshots for this vault beyond `keep` (`1..=BACKUP_KEEP_MAX`).
///
/// # Errors
///
/// Out-of-range `keep`, backup creation error, directory creation or atomic
/// write error.
pub fn write_rolling_backup(
    base: &Path,
    session: &Session,
    file: &VaultFile,
    name: &str,
    dir: &Path,
    keep: u8,
) -> anyhow::Result<PathBuf> {
    if keep == 0 || keep > BACKUP_KEEP_MAX {
        anyhow::bail!("rolling backup retention out of range");
    }
    std::fs::create_dir_all(dir)?;
    let bundle = build_backup_bundle(base, session, file, name)?;
    let prefix = vault_prefix(session.vault_id());
    let stamp = now_ms();
    let filename = format!("{prefix}{}-{stamp}{ROLLING_EXT}", session.generation());
    let dest = dir.join(filename);
    write_atomic(&dest, &bundle)?;

    let mut entries: Vec<((u64, u64), PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let fname = path.file_name()?.to_str()?;
            let key = parse_rolling_key(fname, &prefix)?;
            Some((key, path))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, old_path) in entries.into_iter().skip(usize::from(keep)) {
        let _ = std::fs::remove_file(old_path);
    }
    Ok(dest)
}
