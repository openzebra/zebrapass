//! Crash-safe file writes: temp file, fsync, rename, directory fsync.
//!
//! The rename is atomic within the filesystem, so a reader sees either
//! the old file or the new one — never a torn write. Temp files are
//! created in the target directory and removed on failure.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Replace `path` with `bytes` atomically.
///
/// The file mode is `0600` on Unix. A best-effort `fsync` on the
/// containing directory makes the rename durable.
///
/// # Errors
///
/// `write failed` when creating or filling the temp file fails;
/// `rename failed` when the atomic swap fails; `sync failed` when the
/// file or directory sync fails; `os entropy failed` when the temp file
/// suffix cannot be drawn.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("write failed"))?;
    fs::create_dir_all(dir).map_err(|_| anyhow::anyhow!("write failed"))?;
    let temp = dir.join(temp_name(path)?);
    let write = || -> anyhow::Result<()> {
        let mut file = fs::File::create(&temp).map_err(|_| anyhow::anyhow!("write failed"))?;
        set_private_mode(&file)?;
        file.write_all(bytes)
            .map_err(|_| anyhow::anyhow!("write failed"))?;
        file.sync_all()
            .map_err(|_| anyhow::anyhow!("sync failed"))?;
        drop(file);
        fs::rename(&temp, path).map_err(|_| anyhow::anyhow!("rename failed"))?;
        if let Ok(dir_handle) = fs::File::open(dir) {
            dir_handle
                .sync_all()
                .map_err(|_| anyhow::anyhow!("sync failed"))?;
        }
        Ok(())
    };
    match write() {
        Ok(()) => Ok(()),
        Err(error) => {
            drop(fs::remove_file(&temp));
            Err(error)
        }
    }
}

fn temp_name(path: &Path) -> anyhow::Result<String> {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let mut name = path.file_name().map_or_else(
        || String::from("file"),
        |name| name.to_string_lossy().into_owned(),
    );
    name.push_str(".tmp-");
    for byte in suffix {
        // Both indexes are masked into 0..=15 before the lookup.
        name.push_str(HEX.get(usize::from(byte >> 4)).copied().unwrap_or("0"));
        name.push_str(HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or("0"));
    }
    Ok(name)
}

#[cfg(unix)]
fn set_private_mode(file: &fs::File) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| anyhow::anyhow!("write failed"))
}

#[cfg(not(unix))]
fn set_private_mode(_file: &fs::File) -> anyhow::Result<()> {
    Ok(())
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

    use std::fmt::Write as _;
    use std::fs;
    use std::path::PathBuf;

    use super::write_atomic;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let mut name = format!("zp-local-{tag}-");
        for byte in suffix {
            write!(name, "{byte:02x}").unwrap();
        }
        let dir = std::env::temp_dir().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_is_atomic_and_leaves_no_temp() {
        let dir = temp_dir("atomic");
        let target = dir.join("file.bin");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        // Overwrite in place.
        write_atomic(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        let left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec![String::from("file.bin")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let target = dir.join("private.bin");
        write_atomic(&target, b"x").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_parent_is_created() {
        let dir = temp_dir("nested");
        let target = dir.join("a/b/c/file.bin");
        write_atomic(&target, b"deep").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"deep");
        fs::remove_dir_all(&dir).unwrap();
    }
}
