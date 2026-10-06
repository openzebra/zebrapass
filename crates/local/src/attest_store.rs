//! The latest attestation of every record of a shared vault.
//!
//! A relay can only forward another writer's revision if it kept that
//! writer's signed attestation, so every attestation a device accepts or
//! makes is stored here, sealed under a key derived from the shared seed.
//! One frame per entry, like the member log.

use std::collections::BTreeMap;
use std::path::Path;

use frame::{
    decode_frames, encode_frames, open, parse, seal, spans, FrameMeta, ALG_CASCADE, KIND_REVISION,
};
use secret::Secret;
use session::Attestation;
use syncwire::{decode_attestation, encode_attestation};

use crate::limits::ATTESTATIONS_MAX;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// Attestations by record id.
#[derive(Debug, Default)]
pub struct AttestStore {
    by_record: BTreeMap<u32, Attestation>,
}

impl AttestStore {
    /// The stored attestation of `record_id`.
    #[must_use]
    pub fn get(&self, record_id: u32) -> Option<&Attestation> {
        self.by_record.get(&record_id)
    }

    /// How many records have one.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_record.len()
    }

    /// No record has one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_record.is_empty()
    }

    /// Keep `attestation` unless the store already holds one for a revision
    /// that wins over it.
    ///
    /// # Errors
    ///
    /// `attestation store full` for a new record at the bound. Nothing is
    /// evicted: a missing attestation would make a revision unservable.
    pub fn put(&mut self, attestation: Attestation) -> anyhow::Result<()> {
        let newer = |held: &Attestation| {
            (attestation.revision, attestation.origin_device) > (held.revision, held.origin_device)
        };
        match self.by_record.get(&attestation.record_id) {
            Some(held) if !newer(held) => return Ok(()),
            None if self.by_record.len() >= ATTESTATIONS_MAX => {
                anyhow::bail!("attestation store full");
            }
            _ => {}
        }
        self.by_record.insert(attestation.record_id, attestation);
        Ok(())
    }

    /// Write the store, one sealed frame per attestation.
    ///
    /// # Errors
    ///
    /// Encoding, sealing or write failure.
    pub fn save(&self, path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<()> {
        let mut frames = Vec::new();
        for attestation in self.by_record.values() {
            let meta = FrameMeta {
                kind: KIND_REVISION,
                record_id: attestation.record_id,
                revision: attestation.revision,
                origin_device: attestation.origin_device,
                timestamp_ms: 0,
                alg: ALG_CASCADE,
            };
            frames.extend_from_slice(&seal(key, &meta, &encode_attestation(attestation)?)?);
        }
        crate::write_atomic(path, &encode_frames(&frames)?)
    }

    /// Read the store. A missing file is an error, not an empty store.
    ///
    /// # Errors
    ///
    /// `attestation store unreadable` when the file cannot be read; frame
    /// authentication failure; a frame whose header does not match its
    /// contents, or records out of order.
    pub fn load(path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).map_err(|_| anyhow::anyhow!("attestation store unreadable"))?;
        let frames = decode_frames(&bytes)?;
        let spans = spans(&frames)?;
        if spans.len() > ATTESTATIONS_MAX {
            return Err(corrupted());
        }
        let mut store = Self::default();
        let mut last = None;
        for (start, len) in spans {
            let frame = frames.get(start..start + len).ok_or_else(corrupted)?;
            let header = parse(frame)?;
            let attestation = decode_attestation(open(key, frame)?.expose())?;
            let matches = header.record_id == attestation.record_id
                && header.revision == attestation.revision
                && header.origin_device == attestation.origin_device;
            if !matches || last.is_some_and(|before| before >= attestation.record_id) {
                return Err(corrupted());
            }
            last = Some(attestation.record_id);
            store.by_record.insert(attestation.record_id, attestation);
        }
        Ok(store)
    }
}
