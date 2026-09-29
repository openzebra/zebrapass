//! How often and how recently this device copied from each record, for
//! ordering the record list. Kept in the encrypted `local.meta`; never
//! synced.

use record::{Document, ValueType, TAG_USAGE};

use crate::limits::USAGE_MAX;

const ENTRY_LEN: usize = 16;
const DAY_MS: u64 = 86_400_000;
const AGE_WEIGHTS: [(u64, u64); 4] = [
    (4 * DAY_MS, 100),
    (14 * DAY_MS, 70),
    (31 * DAY_MS, 50),
    (90 * DAY_MS, 30),
];
const STALE_WEIGHT: u64 = 10;

/// Copy usage of one record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageEntry {
    /// Last copy in unix milliseconds.
    pub last_ms: u64,
    /// Record id.
    pub id: u32,
    /// Copies so far.
    pub count: u32,
}

impl UsageEntry {
    /// Frecency: the copy count weighted by how recent the last copy is.
    /// A last copy in the future counts as fresh.
    #[must_use]
    pub fn rank(&self, now_ms: u64) -> u64 {
        let age = now_ms.saturating_sub(self.last_ms);
        let weight = AGE_WEIGHTS
            .iter()
            .find(|(max_age, _)| age <= *max_age)
            .map_or(STALE_WEIGHT, |(_, weight)| *weight);
        u64::from(self.count).saturating_mul(weight)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.last_ms.to_le_bytes());
    }
}

impl TryFrom<&[u8]> for UsageEntry {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self> {
        let (id, rest) = bytes
            .split_first_chunk::<4>()
            .ok_or_else(corrupted_length)?;
        let (count, rest) = rest.split_first_chunk::<4>().ok_or_else(corrupted_length)?;
        let last_ms = <[u8; 8]>::try_from(rest).map_err(|_| corrupted_length())?;
        Ok(Self {
            last_ms: u64::from_le_bytes(last_ms),
            id: u32::from_le_bytes(*id),
            count: u32::from_le_bytes(*count),
        })
    }
}

/// Copy usage of every record this device copied from, sorted by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    entries: Vec<UsageEntry>,
}

impl Usage {
    /// Count one copy from record `id` at `now_ms`. At [`USAGE_MAX`]
    /// records, the lowest-ranked other record is forgotten first.
    pub fn note(&mut self, id: u32, now_ms: u64) {
        if let Ok(index) = self.entries.binary_search_by_key(&id, |entry| entry.id) {
            if let Some(entry) = self.entries.get_mut(index) {
                entry.count = entry.count.saturating_add(1);
                entry.last_ms = now_ms;
            }
            return;
        }
        if self.entries.len() >= USAGE_MAX {
            self.evict_lowest(now_ms);
        }
        let at = self.entries.partition_point(|entry| entry.id < id);
        self.entries.insert(
            at,
            UsageEntry {
                last_ms: now_ms,
                id,
                count: 1,
            },
        );
    }

    /// Usage of record `id`, if it was ever copied from.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&UsageEntry> {
        self.entries
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    /// Keep only records for which `keep` holds.
    pub fn retain(&mut self, keep: impl Fn(u32) -> bool) {
        self.entries.retain(|entry| keep(entry.id));
    }

    /// Number of records with usage.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No record has usage.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Write the usage into `doc`; nothing when empty.
    pub fn write(&self, doc: &mut Document) {
        if self.entries.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(self.entries.len() * ENTRY_LEN);
        self.entries
            .iter()
            .for_each(|entry| entry.encode(&mut bytes));
        doc.set_data(TAG_USAGE, ValueType::Bytes, &bytes);
    }

    /// Read the usage from `doc`; empty when the tag is absent.
    ///
    /// # Errors
    ///
    /// `corrupted length` for a size that is not whole entries or exceeds
    /// [`USAGE_MAX`]; `usage out of order` for unsorted or repeated ids.
    pub fn read(doc: &Document) -> anyhow::Result<Self> {
        let Some(bytes) = doc.data(TAG_USAGE)? else {
            return Ok(Self::default());
        };
        if bytes.len() % ENTRY_LEN != 0 || bytes.len() / ENTRY_LEN > USAGE_MAX {
            return Err(corrupted_length());
        }
        let entries = bytes
            .chunks_exact(ENTRY_LEN)
            .map(UsageEntry::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?;
        if !entries.windows(2).all(|pair| match pair {
            [left, right] => left.id < right.id,
            _ => false,
        }) {
            anyhow::bail!("usage out of order");
        }
        Ok(Self { entries })
    }

    fn evict_lowest(&mut self, now_ms: u64) {
        let lowest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| (entry.rank(now_ms), entry.last_ms))
            .map(|(index, _)| index);
        if let Some(index) = lowest {
            self.entries.remove(index);
        }
    }
}

fn corrupted_length() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests may unwrap and index"
    )]

    use record::{Document, ValueType, TAG_USAGE};

    use super::{Usage, UsageEntry, DAY_MS, ENTRY_LEN};
    use crate::limits::USAGE_MAX;

    const NOW: u64 = 1_800_000_000_000;

    fn written(usage: &Usage) -> Document {
        let mut doc = Document::new();
        usage.write(&mut doc);
        doc
    }

    fn with_raw(bytes: &[u8]) -> Document {
        let mut doc = Document::new();
        doc.set_data(TAG_USAGE, ValueType::Bytes, bytes);
        doc
    }

    #[test]
    fn round_trips_and_absent_tag_is_empty() {
        let mut usage = Usage::default();
        usage.note(9, NOW);
        usage.note(3, NOW - DAY_MS);
        usage.note(9, NOW);
        assert_eq!(Usage::read(&written(&usage)).unwrap(), usage);
        assert_eq!(usage.get(9).unwrap().count, 2);
        assert!(Usage::read(&Document::new()).unwrap().is_empty());
        assert!(written(&Usage::default()).get(TAG_USAGE).is_none());
    }

    #[test]
    fn rejects_partial_entries_oversize_and_disorder() {
        let message = |doc: &Document| Usage::read(doc).unwrap_err().to_string();
        assert_eq!(message(&with_raw(&[0; ENTRY_LEN + 1])), "corrupted length");
        assert_eq!(
            message(&with_raw(&vec![0; (USAGE_MAX + 1) * ENTRY_LEN])),
            "corrupted length"
        );
        let entry = |id: u32| {
            let mut bytes = Vec::new();
            UsageEntry {
                last_ms: NOW,
                id,
                count: 1,
            }
            .encode(&mut bytes);
            bytes
        };
        let unsorted = [entry(5), entry(2)].concat();
        let repeated = [entry(5), entry(5)].concat();
        assert_eq!(message(&with_raw(&unsorted)), "usage out of order");
        assert_eq!(message(&with_raw(&repeated)), "usage out of order");
    }

    #[test]
    fn recent_use_outranks_a_stale_high_count() {
        let stale = UsageEntry {
            last_ms: NOW - 200 * DAY_MS,
            id: 1,
            count: 9,
        };
        let fresh = UsageEntry {
            last_ms: NOW - DAY_MS,
            id: 2,
            count: 1,
        };
        assert!(fresh.rank(NOW) > stale.rank(NOW));
        assert!(stale.rank(NOW) > 0);
    }

    #[test]
    fn future_timestamps_and_counts_saturate() {
        let future = UsageEntry {
            last_ms: u64::MAX,
            id: 1,
            count: u32::MAX,
        };
        assert_eq!(future.rank(NOW), u64::from(u32::MAX) * 100);
        let mut usage = Usage::read(&with_raw(&{
            let mut bytes = Vec::new();
            future.encode(&mut bytes);
            bytes
        }))
        .unwrap();
        usage.note(1, NOW);
        assert_eq!(usage.get(1).unwrap().count, u32::MAX);
    }

    #[test]
    fn full_usage_forgets_the_lowest_rank() {
        let mut usage = Usage::default();
        for id in 0..u32::try_from(USAGE_MAX).unwrap() {
            usage.note(id, NOW);
            usage.note(id, NOW);
        }
        usage.note(0, NOW - 365 * DAY_MS);
        usage.note(9999, NOW);
        assert_eq!(usage.len(), USAGE_MAX);
        assert!(usage.get(0).is_none());
        assert!(usage.get(9999).is_some());
        usage.retain(|id| id != 9999);
        assert!(usage.get(9999).is_none());
    }
}
