//! The two files a device keeps for a shared vault besides the vault file:
//! the member log and the local state. Both are sealed under keys derived
//! from the shared seed, so a device that has joined but not yet received the
//! vault file can store them.

use std::path::Path;

use frame::{
    decode_frames, encode_frames, open, parse, seal, spans, FrameMeta, ALG_CASCADE, KIND_REVISION,
};
use memberlog::{Entry, MemberLog, MAX_ENTRIES};
use record::Document;
use secret::Secret;

use crate::last_seen::LastSeen;
use crate::revocations::Revocations;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// What this device tracks for one shared vault, never synced.
#[derive(Debug, Default)]
pub struct SharedState {
    /// Highest accepted revision per record.
    pub last_seen: LastSeen,
    /// Accepted revocations of member devices.
    pub revocations: Revocations,
}

/// Write the member log: one sealed frame per entry, so the log is not
/// bounded by the size of a single frame.
///
/// # Errors
///
/// Encoding, sealing or write failure.
pub fn save_member_log(path: &Path, key: &Secret<[u8; 32]>, log: &MemberLog) -> anyhow::Result<()> {
    let mut frames = Vec::new();
    for entry in log.entries() {
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: u32::try_from(entry.seq)?,
            revision: 1,
            origin_device: entry.signer.device_id,
            timestamp_ms: entry.at_ms,
            alg: ALG_CASCADE,
        };
        frames.extend_from_slice(&seal(key, &meta, &entry.encode()?)?);
    }
    crate::write_atomic(path, &encode_frames(&frames)?)
}

/// Read the member log and verify it from its first entry against `anchor`.
///
/// # Errors
///
/// `member log unreadable` when the file cannot be read; frame
/// authentication failure; a frame out of place; any verification failure of
/// the log itself.
pub fn load_member_log(
    path: &Path,
    key: &Secret<[u8; 32]>,
    vault_id: [u8; 16],
    anchor: &[u8; 32],
) -> anyhow::Result<MemberLog> {
    let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("member log unreadable"))?;
    let frames = decode_frames(&bytes)?;
    let spans = spans(&frames)?;
    if spans.len() > MAX_ENTRIES {
        return Err(corrupted());
    }
    let entries = spans
        .iter()
        .enumerate()
        .map(|(index, (start, len))| {
            let frame = frames.get(*start..start + len).ok_or_else(corrupted)?;
            if u64::from(parse(frame)?.record_id) != u64::try_from(index)? {
                return Err(corrupted());
            }
            Entry::decode(open(key, frame)?.expose())
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    MemberLog::from_entries(vault_id, &entries, anchor)
}

impl SharedState {
    /// Write the state as one sealed frame.
    ///
    /// # Errors
    ///
    /// Encoding, sealing or write failure.
    pub fn save(&self, path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<()> {
        let mut doc = Document::new();
        self.last_seen.write(&mut doc);
        self.revocations.write(&mut doc)?;
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: 0,
            revision: 1,
            origin_device: [0xFF; 16],
            timestamp_ms: 0,
            alg: ALG_CASCADE,
        };
        crate::write_atomic(path, &seal(key, &meta, &doc.encode()?)?)
    }

    /// Read the state. A missing file is an error, not the empty state:
    /// deleting it must not reset what the device has already seen.
    ///
    /// # Errors
    ///
    /// `shared state unreadable` when the file cannot be read; frame
    /// authentication failure or a malformed document.
    pub fn load(path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("shared state unreadable"))?;
        let plaintext = open(key, &bytes)?;
        let doc = Document::parse(plaintext.expose())?;
        Ok(Self {
            last_seen: LastSeen::read(&doc)?,
            revocations: Revocations::read(&doc)?,
        })
    }
}
