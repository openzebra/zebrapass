//! The `local.meta` file: one standalone frame with this device's
//! metadata.
//!
//! The frame is sealed with `kdf::local_meta_key(vk, vault_id)` and lives
//! outside the container — it is a plain frame file, not part of the
//! AE1-wrapped body. Its payload is a document with the device id, the
//! identity point, the creation time, and a display name.

use std::path::Path;

use frame::{seal, FrameMeta, ALG_AEGIS256, KIND_REVISION};
use record::{
    Document, ValueType, TAG_CREATED_AT_MS, TAG_DEVICE_ID, TAG_NAME, TAG_SEEN_COMMIT,
    TAG_SEEN_GENERATION, TAG_USER_ID,
};
use secret::Secret;

/// The last file state this device accepted, for rollback detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeenCursor {
    /// Generation of the last accepted vault file.
    pub generation: u64,
    /// Commit tag of that file.
    pub commit_tag: [u8; 32],
}

/// This device's metadata for one vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMeta {
    /// The device that created the vault on this machine.
    pub device_id: [u8; 16],
    /// Identity point derived from the master seed (`x ‖ y`, 64 bytes).
    pub user_id: [u8; 64],
    /// Creation time in unix milliseconds.
    pub created_at_ms: u64,
    /// Display name of the vault on this device.
    pub name: String,
    /// Last accepted generation and commit tag; `None` on files written
    /// before rollback detection existed.
    pub seen: Option<SeenCursor>,
}

/// The document form of the metadata (tags `0x0201..0x0204`).
#[must_use]
pub fn meta_document(meta: &LocalMeta) -> Document {
    let mut doc = Document::new();
    doc.set_data(TAG_DEVICE_ID, ValueType::Bytes, &meta.device_id);
    doc.set_data(TAG_USER_ID, ValueType::Bytes, &meta.user_id);
    doc.set_data(TAG_CREATED_AT_MS, ValueType::Bytes, &meta.created_at_ms.to_le_bytes());
    doc.set_text(TAG_NAME, &meta.name);
    if let Some(seen) = meta.seen {
        doc.set_data(TAG_SEEN_GENERATION, ValueType::Bytes, &seen.generation.to_le_bytes());
        doc.set_data(TAG_SEEN_COMMIT, ValueType::Bytes, &seen.commit_tag);
    }
    doc
}

/// Rebuild the metadata from a document.
///
/// # Errors
///
/// `corrupted length` when a metadata field is missing or has the wrong
/// length.
pub fn meta_from_document(doc: &Document) -> anyhow::Result<LocalMeta> {
    let device_id: [u8; 16] = doc
        .data(TAG_DEVICE_ID)?
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let user_id: [u8; 64] = doc
        .data(TAG_USER_ID)?
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let raw_time = doc
        .data(TAG_CREATED_AT_MS)?
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let name = doc.text(TAG_NAME)?.unwrap_or_default().to_owned();
    let seen = match (
        doc.data(TAG_SEEN_GENERATION)?,
        doc.data(TAG_SEEN_COMMIT)?,
    ) {
        (None, None) => None,
        (Some(gen), Some(tag)) => {
            let generation = <[u8; 8]>::try_from(gen)
                .map_err(|_| anyhow::anyhow!("corrupted length"))?;
            let commit_tag = <[u8; 32]>::try_from(tag)
                .map_err(|_| anyhow::anyhow!("corrupted length"))?;
            Some(SeenCursor {
                generation: u64::from_le_bytes(generation),
                commit_tag,
            })
        }
        _ => anyhow::bail!("corrupted length"),
    };
    Ok(LocalMeta {
        device_id,
        user_id,
        created_at_ms: u64::from_le_bytes(raw_time),
        name,
        seen,
    })
}

/// Write `meta` to `path` as one standalone revision frame.
///
/// # Errors
///
/// Frame-sealing and atomic-write errors as in [`frame::seal`] and
/// [`crate::write_atomic`].
pub fn save_local_meta(
    path: &Path,
    meta: &LocalMeta,
    key: &Secret<[u8; 32]>,
) -> anyhow::Result<()> {
    let frame_meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: 0,
        revision: 1,
        origin_device: meta.device_id,
        timestamp_ms: meta.created_at_ms,
        alg: ALG_AEGIS256,
    };
    let frame_bytes = seal(key, &frame_meta, &meta_document(meta).encode()?)?;
    crate::write_atomic(path, &frame_bytes)
}

/// Read and open the metadata frame at `path`.
///
/// # Errors
///
/// `local metadata unreadable` when the file cannot be read; frame-open
/// errors as in [`frame::open`]; `corrupted length` when the document is
/// missing a metadata field.
pub fn load_local_meta(path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<LocalMeta> {
    let bytes =
        std::fs::read(path).map_err(|_| anyhow::anyhow!("local metadata unreadable"))?;
    let plaintext = frame::open(key, &bytes)?;
    let doc = Document::parse(plaintext.expose())?;
    meta_from_document(&doc)
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

    use std::fs;
    use std::path::PathBuf;

    use std::fmt::Write as _;

    use kdf::{frame_key, local_meta_key};
    use record::TAG_DEVICE_ID;

    use super::{load_local_meta, meta_document, meta_from_document, save_local_meta, LocalMeta};

    fn temp_dir(tag: &str) -> PathBuf {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let mut name = format!("zp-meta-{tag}-");
        for byte in suffix {
            write!(name, "{byte:02x}").unwrap();
        }
        let dir = std::env::temp_dir().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_meta() -> LocalMeta {
        LocalMeta {
            seen: Some(super::SeenCursor {
                generation: 9,
                commit_tag: [3u8; 32],
            }),
            device_id: [3; 16],
            user_id: [4; 64],
            created_at_ms: 1_700_000_000_123,
            name: String::from("Personal"),
        }
    }

    #[test]
    fn document_round_trip() {
        let doc = meta_document(&sample_meta());
        assert_eq!(meta_from_document(&doc).unwrap(), sample_meta());
        // A missing field is a clean error, not a default.
        let mut broken = meta_document(&sample_meta());
        broken.remove(TAG_DEVICE_ID);
        assert_eq!(
            meta_from_document(&broken).unwrap_err().to_string(),
            "corrupted length"
        );
    }

    #[test]
    fn file_round_trip_under_matching_key() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("local.meta");
        let vk = [9u8; 32];
        let vault_id = [7u8; 16];
        let key = local_meta_key(&vk, &vault_id).unwrap();
        save_local_meta(&path, &sample_meta(), &key).unwrap();
        let loaded = load_local_meta(&path, &key).unwrap();
        assert_eq!(loaded, sample_meta());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_key_cannot_read_metadata() {
        let dir = temp_dir("wrongkey");
        let path = dir.join("local.meta");
        let key = local_meta_key(&[9u8; 32], &[7u8; 16]).unwrap();
        save_local_meta(&path, &sample_meta(), &key).unwrap();
        let other = frame_key(&[9u8; 32], &[7u8; 16], 0).unwrap();
        assert_eq!(
            load_local_meta(&path, &other).unwrap_err().to_string(),
            "frame authentication failed"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
