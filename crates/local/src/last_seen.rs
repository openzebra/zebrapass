//! Highest revision this device accepted for each record, so a replayed or
//! rolled-back record from a peer is refused. Kept in the sealed sync
//! identity file; never synced.

use record::{Document, ValueType, SYNC_LAST_SEEN_PER_TAG, TAG_SYNC_LAST_SEEN_MIN};

use crate::limits::LAST_SEEN_MAX;

const ENTRY_LEN: usize = 12;

/// Per-record highest accepted revision, sorted by record id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LastSeen {
    entries: Vec<(u32, u64)>,
}

impl LastSeen {
    /// Highest accepted revision of `record_id`, if any.
    #[must_use]
    pub fn get(&self, record_id: u32) -> Option<u64> {
        self.entries
            .binary_search_by_key(&record_id, |entry| entry.0)
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|entry| entry.1)
    }

    /// Raise the stored revision of `record_id` to `revision`; a lower or
    /// equal revision never lowers it.
    ///
    /// # Errors
    ///
    /// `last-seen table full` when a new record would exceed the bound. The
    /// table never evicts: forgetting a revision would re-open a replay.
    pub fn note(&mut self, record_id: u32, revision: u64) -> anyhow::Result<()> {
        match self
            .entries
            .binary_search_by_key(&record_id, |entry| entry.0)
        {
            Ok(index) => {
                if let Some(entry) = self.entries.get_mut(index) {
                    entry.1 = entry.1.max(revision);
                }
            }
            Err(at) => {
                if self.entries.len() >= LAST_SEEN_MAX {
                    anyhow::bail!("last-seen table full");
                }
                self.entries.insert(at, (record_id, revision));
            }
        }
        Ok(())
    }

    /// Number of records tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No record is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn write(&self, doc: &mut Document) {
        self.entries
            .chunks(SYNC_LAST_SEEN_PER_TAG)
            .zip(TAG_SYNC_LAST_SEEN_MIN..)
            .for_each(|(chunk, tag)| {
                let mut bytes = Vec::with_capacity(chunk.len() * ENTRY_LEN);
                for (id, revision) in chunk {
                    bytes.extend_from_slice(&id.to_le_bytes());
                    bytes.extend_from_slice(&revision.to_le_bytes());
                }
                doc.set_data(tag, ValueType::Bytes, &bytes);
            });
    }

    pub(crate) fn read(doc: &Document) -> anyhow::Result<Self> {
        let mut entries = Vec::new();
        let mut shards = 0usize;
        for tag in (TAG_SYNC_LAST_SEEN_MIN..).take(record::SYNC_LAST_SEEN_TAGS) {
            let Some(bytes) = doc.data(tag)? else {
                break;
            };
            if bytes.len() % ENTRY_LEN != 0 || bytes.len() / ENTRY_LEN > SYNC_LAST_SEEN_PER_TAG {
                anyhow::bail!("corrupted length");
            }
            shards += 1;
            for chunk in bytes.chunks_exact(ENTRY_LEN) {
                let (id, revision) = chunk
                    .split_first_chunk::<4>()
                    .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
                let revision = <[u8; 8]>::try_from(revision)
                    .map_err(|_| anyhow::anyhow!("corrupted length"))?;
                entries.push((u32::from_le_bytes(*id), u64::from_le_bytes(revision)));
            }
        }
        let stray = (TAG_SYNC_LAST_SEEN_MIN..)
            .take(record::SYNC_LAST_SEEN_TAGS)
            .skip(shards)
            .any(|tag| doc.get(tag).is_some());
        let unsorted = entries.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(a, b)| a.0 >= b.0)
        });
        if stray || unsorted {
            anyhow::bail!("corrupted length");
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use record::Document;

    use super::LastSeen;

    #[test]
    fn note_only_raises_and_round_trips() {
        let mut seen = LastSeen::default();
        seen.note(9, 4).unwrap();
        seen.note(2, 7).unwrap();
        seen.note(9, 3).unwrap();
        seen.note(9, 6).unwrap();
        assert_eq!(seen.get(9), Some(6));
        assert_eq!(seen.get(2), Some(7));
        assert_eq!(seen.get(5), None);
        let mut doc = Document::new();
        seen.write(&mut doc);
        assert_eq!(LastSeen::read(&doc).unwrap(), seen);
    }

    #[test]
    fn a_table_larger_than_one_field_round_trips() {
        let mut seen = LastSeen::default();
        for id in 0..10_000u32 {
            seen.note(id, u64::from(id) + 1).unwrap();
        }
        let mut doc = Document::new();
        seen.write(&mut doc);
        doc.encode().unwrap();
        assert_eq!(LastSeen::read(&doc).unwrap(), seen);
    }

    #[test]
    fn a_full_table_refuses_new_records_instead_of_forgetting() {
        let mut seen = LastSeen::default();
        for id in 0..u32::try_from(crate::limits::LAST_SEEN_MAX).unwrap() {
            seen.note(id, 1).unwrap();
        }
        assert!(seen.note(u32::MAX, 1).is_err());
        seen.note(0, 5).unwrap();
        assert_eq!(seen.get(0), Some(5));
        let mut doc = Document::new();
        seen.write(&mut doc);
        assert!(doc.encode().is_ok());
        assert_eq!(LastSeen::read(&doc).unwrap().len(), seen.len());
    }

    #[test]
    fn unsorted_or_ragged_data_is_rejected() {
        let mut doc = Document::new();
        let mut bytes = Vec::new();
        for id in [5u32, 3] {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&1u64.to_le_bytes());
        }
        doc.set_data(
            record::TAG_SYNC_LAST_SEEN_MIN,
            record::ValueType::Bytes,
            &bytes,
        );
        assert!(LastSeen::read(&doc).is_err());
        doc.set_data(
            record::TAG_SYNC_LAST_SEEN_MIN,
            record::ValueType::Bytes,
            &[0u8; 13],
        );
        assert!(LastSeen::read(&doc).is_err());
    }
}
