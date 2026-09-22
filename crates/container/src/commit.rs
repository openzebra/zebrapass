//! File framing: static header, wrap directory, body, and an unverified commit tag.

use crate::header::{check_magic, StaticHeader};
use crate::limits::{self, read_array, COMMIT_LEN, HEADER_LEN, MIN_FILE_LEN};
use crate::wrap_dir::WrapDir;
use crate::wrap_entry::WrapEntry;

/// Owned vault file. Parsing borrows these bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultFile {
    bytes: Vec<u8>,
}

impl VaultFile {
    /// Wrap bytes read from disk. This does not parse them.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the encoded file.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Parse the container. The commit tag is returned and not checked.
    ///
    /// # Errors
    ///
    /// Magic is checked first. A file shorter than the
    /// header plus the commit is `corrupted length` before version
    /// or KDF parameters are interpreted. Argon2 floor and ceiling are rejected
    /// before the wrap directory is read.
    pub fn parse(&self) -> anyhow::Result<Parsed<'_>> {
        let bytes = self.as_bytes();
        check_magic(bytes)?;
        if bytes.len() < MIN_FILE_LEN {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let header_bytes = bytes
            .get(..HEADER_LEN)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let header = StaticHeader::try_from(header_bytes)?;
        let commit_at = bytes
            .len()
            .checked_sub(COMMIT_LEN)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let commit = read_array(bytes, commit_at)?;
        let prefix = bytes.get(..commit_at).ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let dir_and_body = prefix
            .get(HEADER_LEN..)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let (dir, body) = WrapDir::parse_prefix(dir_and_body)?;
        let min_body = limits::min_body_len(header.body_alg)
            .ok_or_else(|| anyhow::anyhow!("unsupported body algorithm {:#06x}", header.body_alg))?;
        if body.len() < min_body {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        Ok(Parsed {
            header,
            generation: dir.generation,
            entries: dir.entries,
            body,
            commit,
        })
    }
}

impl From<Vec<u8>> for VaultFile {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// A parsed file. `entries` and `body` borrow [`VaultFile`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parsed<'a> {
    /// Static header.
    pub header: StaticHeader,
    /// Generation from the wrap directory.
    pub generation: u64,
    /// Wrap records in file order.
    pub entries: Vec<WrapEntry<'a>>,
    /// Body bytes between the wrap directory and the commit.
    pub body: &'a [u8],
    /// Last 32 bytes. Not authenticated here.
    pub commit: [u8; COMMIT_LEN],
}

/// Concatenate header, wrap directory, body, and commit without validating them.
#[must_use]
pub fn assemble(
    header: &StaticHeader,
    wrap_dir: &[u8],
    body: &[u8],
    commit: &[u8; COMMIT_LEN],
) -> VaultFile {
    let header_bytes = header.to_bytes();
    let cap = header_bytes
        .len()
        .checked_add(wrap_dir.len())
        .and_then(|len| len.checked_add(body.len()))
        .and_then(|len| len.checked_add(commit.len()))
        .unwrap_or(0);
    let mut bytes = Vec::with_capacity(cap);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(wrap_dir);
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(commit);
    VaultFile::new(bytes)
}
