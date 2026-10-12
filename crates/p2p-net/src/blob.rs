//! A thing served in chunks: the member log, or a snapshot (its prefix, then
//! the vault file read from the handle that was opened when the transfer
//! began, so a file replaced meanwhile does not change what is being sent).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use syncwire::limits::CHUNK_LEN;

use crate::view::SnapshotSource;

/// Bytes of the file that go into the name of a transfer.
const NAME_SAMPLE: usize = 4096;

/// A transfer being served.
pub struct Blob {
    id: [u8; 32],
    prefix: Vec<u8>,
    file: Option<Mutex<File>>,
    total: u64,
}

impl Blob {
    /// A blob held in memory.
    #[must_use]
    pub fn memory(bytes: Vec<u8>) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"zebrapass/blob/memory");
        digest.update(&bytes);
        Self {
            id: digest.finalize().into(),
            total: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            prefix: bytes,
            file: None,
        }
    }

    /// A snapshot: its prefix, then the file.
    ///
    /// # Errors
    ///
    /// The file cannot be read.
    pub fn snapshot(mut source: SnapshotSource) -> std::io::Result<Self> {
        let mut sample = vec![0u8; NAME_SAMPLE.min(usize::try_from(source.file_len).unwrap_or(0))];
        source.file.read_exact(&mut sample)?;
        let mut digest = Sha256::new();
        digest.update(b"zebrapass/blob/snapshot");
        digest.update(
            u64::try_from(source.prefix.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(&source.prefix);
        digest.update(source.file_len.to_be_bytes());
        digest.update(&sample);
        let total = u64::try_from(source.prefix.len())
            .ok()
            .and_then(|prefix| prefix.checked_add(source.file_len))
            .ok_or_else(|| std::io::Error::other("snapshot too large"))?;
        Ok(Self {
            id: digest.finalize().into(),
            prefix: source.prefix,
            file: Some(Mutex::new(source.file)),
            total,
        })
    }

    /// What names this transfer.
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Total length in bytes.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// The chunk at `offset`: [`CHUNK_LEN`] bytes, or what is left. `None`
    /// past the end, or when the file cannot be read.
    #[must_use]
    pub fn chunk(&self, offset: u64) -> Option<Vec<u8>> {
        if offset > self.total || (offset == self.total && self.total != 0) {
            return None;
        }
        let len = usize::try_from(self.total - offset).ok()?.min(CHUNK_LEN);
        let from = usize::try_from(offset).ok();
        let mut out = Vec::with_capacity(len);
        if let Some(from) = from.filter(|from| *from < self.prefix.len()) {
            let end = self.prefix.len().min(from + len);
            out.extend_from_slice(self.prefix.get(from..end)?);
        }
        let missing = len - out.len();
        if missing > 0 {
            let at = offset.checked_add(u64::try_from(out.len()).ok()?)?;
            let file_at = at.checked_sub(u64::try_from(self.prefix.len()).ok()?)?;
            let mut file = self.file.as_ref()?.lock().ok()?;
            file.seek(SeekFrom::Start(file_at)).ok()?;
            let start = out.len();
            out.resize(len, 0);
            file.read_exact(out.get_mut(start..)?).ok()?;
        }
        Some(out)
    }
}
