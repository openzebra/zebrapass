//! From a path on disk to parsed items: the entry point an application
//! calls (on a background thread: a `.kdbx` runs its KDF here).

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::source::{read_file, read_head, sniff, Source};
use crate::{parse, Mapping, Parsed, Request};

/// Bytes read for [`inspect`].
const HEAD_BYTES: u64 = 4096;

/// Credentials of a `.kdbx` database. Other sources need none.
#[derive(Default)]
pub struct Credentials {
    /// Master password.
    pub password: Option<Zeroizing<Vec<u8>>>,
    /// Key-file path.
    pub key_file: Option<PathBuf>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("key_file", &self.key_file.is_some())
            .finish()
    }
}

/// One export to read: the job an application hands to a background
/// thread (a `.kdbx` runs its KDF here).
#[derive(Debug)]
pub struct Load {
    /// Export file.
    pub path: PathBuf,
    /// Its format.
    pub source: Source,
    /// `.kdbx` credentials.
    pub credentials: Credentials,
    /// CSV only: column targets; `None` detects them from the header.
    pub mapping: Option<Mapping>,
}

impl Load {
    /// Read the export and parse it. Folder, group, and collection names
    /// become tags.
    ///
    /// # Errors
    ///
    /// A human message that never repeats file contents: IO and size
    /// errors, `key file: …`, and every parse error of [`parse`].
    pub fn run(self) -> anyhow::Result<Parsed> {
        let bytes = read_file(&self.path)?;
        let key_file = self
            .credentials
            .key_file
            .as_deref()
            .map(read_file)
            .transpose()
            .map_err(|error| anyhow::anyhow!("key file: {error}"))?;
        parse(&Request {
            bytes,
            source: self.source,
            mapping: self.mapping,
            folders_as_tags: true,
            password: self.credentials.password,
            key_file,
        })
    }
}

/// [`Load::run`] with the detected CSV mapping.
///
/// # Errors
///
/// As [`Load::run`].
pub fn load(path: &Path, source: Source, credentials: Credentials) -> anyhow::Result<Parsed> {
    Load {
        path: path.to_path_buf(),
        source,
        credentials,
        mapping: None,
    }
    .run()
}

/// What a path points at, for a live hint while it is typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileHint {
    /// Nothing readable there.
    Missing,
    /// A file whose format was guessed (`None`: unknown), and its size.
    Found(Option<Source>, u64),
}

/// Look at the first bytes of `path`. Cheap and unauthenticated.
#[must_use]
pub fn inspect(path: &Path) -> FileHint {
    if path.as_os_str().is_empty() {
        return FileHint::Missing;
    }
    read_head(path, HEAD_BYTES).map_or(FileHint::Missing, |(head, size)| {
        let extension = path.extension().and_then(|ext| ext.to_str());
        FileHint::Found(sniff(&head, extension), size)
    })
}

/// A typed path with `~` and `~/…` resolved against `HOME`.
#[must_use]
pub fn expand_home(typed: &str) -> PathBuf {
    let typed = typed.trim();
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    match typed.strip_prefix('~') {
        Some("") => home().unwrap_or_else(|| PathBuf::from(typed)),
        Some(rest) if rest.starts_with('/') => home().map_or_else(
            || PathBuf::from(typed),
            |home| home.join(rest.trim_start_matches('/')),
        ),
        Some(_) | None => PathBuf::from(typed),
    }
}
