//! Wrap directory: `wrap_count`, `generation`, and the entries that follow.
//!
//! `wrap_count` and `generation` are outside the static header, so editing the
//! directory does not change wrap or body associated data.

use crate::limits::{read_u16, read_u64, WRAP_DIR_HEADER_LEN};
use crate::wrap_entry::{parse_entry, WrapEntry};

/// Parsed wrap directory. Entry payloads borrow the file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapDir<'a> {
    /// Directory generation. Creation starts at 1; this layer accepts any `u64`.
    pub generation: u64,
    /// Wrap records, in file order.
    pub entries: Vec<WrapEntry<'a>>,
}

impl<'a> WrapDir<'a> {
    /// Parse a directory that occupies the whole slice.
    ///
    /// # Errors
    ///
    /// Same as [`Self::parse_prefix`], plus `corrupted length`
    /// when bytes remain after `wrap_count` entries.
    pub(crate) fn parse_exact(bytes: &'a [u8]) -> anyhow::Result<Self> {
        let (dir, tail) = Self::parse_prefix(bytes)?;
        if tail.is_empty() {
            Ok(dir)
        } else {
            Err(anyhow::anyhow!("corrupted length"))
        }
    }

    /// Parse `wrap_count` entries from the front of `bytes`.
    ///
    /// The unconsumed tail is the body when `bytes` is everything between the
    /// static header and the commit.
    ///
    /// # Errors
    ///
    /// Returns `corrupted length` when the prefix is shorter than
    /// `wrap_count` and `generation`, an entry is truncated or the wrong size,
    /// the kind is unknown, the wrong size, or a wrap id repeats. Returns `unsupported kem`
    /// for a device KEM other than sntrup1277.
    pub(crate) fn parse_prefix(bytes: &'a [u8]) -> anyhow::Result<(Self, &'a [u8])> {
        // Do not read wrap_count or generation until both fields fit.
        if bytes.len() < WRAP_DIR_HEADER_LEN {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let wrap_count = read_u16(bytes, 0)?;
        let generation = read_u64(bytes, 2)?;
        let mut offset = WRAP_DIR_HEADER_LEN;
        let mut entries = Vec::with_capacity(usize::from(wrap_count));
        for _ in 0..wrap_count {
            let (entry, next) = parse_entry(bytes, offset)?;
            entries.push(entry);
            offset = next;
        }
        check_entries(&entries)?;
        let tail = bytes.get(offset..).ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        Ok((
            Self {
                generation,
                entries,
            },
            tail,
        ))
    }
}

impl<'a> TryFrom<&'a [u8]> for WrapDir<'a> {
    type Error = anyhow::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse_exact(bytes)
    }
}

/// Build `wrap_count ‖ generation ‖ entries`.
///
/// # Errors
///
/// Returns `corrupted length` when `entries.len()` does not fit
/// in a `u16`, or when the concatenated length overflows `usize`.
pub fn encode_wrap_dir(generation: u64, entries: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let count = u16::try_from(entries.len()).map_err(|_| anyhow::anyhow!("corrupted length"))?;
    let payload = entries
        .iter()
        .try_fold(0usize, |acc, entry| acc.checked_add(entry.len()))
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let total = payload
        .checked_add(WRAP_DIR_HEADER_LEN)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    for entry in entries {
        out.extend_from_slice(entry);
    }
    Ok(out)
}

fn check_entries(entries: &[WrapEntry<'_>]) -> anyhow::Result<()> {
    // Ids are public labels, not MAC tags, so ordinary equality is enough. A
    // repeated id would make "remove this id" ambiguous and could leave a
    // hidden unlock path behind, so a file that carries one does not parse.
    let mut ids: Vec<[u8; 16]> = entries.iter().filter_map(id_of).collect();
    let submitted = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != submitted {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    Ok(())
}

/// The id an entry is addressed by, if its kind carries one.
const fn id_of(entry: &WrapEntry<'_>) -> Option<[u8; 16]> {
    match entry {
        WrapEntry::Password(_) => None,
        WrapEntry::Chip(chip) => Some(chip.id),
        WrapEntry::Device(device) => Some(device.device_id),
        WrapEntry::Prf(prf) => Some(prf.id),
    }
}
