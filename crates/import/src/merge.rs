//! Write reviewed records into an open vault, skipping exact duplicates.

use std::collections::HashMap;

use record::{Document, TAG_TITLE};
use session::{list_records, open_record, write_records_batch, Session, VaultFile};
use zeroize::{Zeroize, Zeroizing};

/// What a merge did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Merged {
    /// New record ids, in input order.
    pub ids: Vec<u32>,
    /// Records left out because an identical one already exists (in the
    /// vault or earlier in the same import).
    pub duplicates: usize,
}

/// Encoded documents grouped by title, so each record is compared only
/// with the few that share its title.
struct Known(HashMap<Box<str>, Vec<Zeroizing<Vec<u8>>>>);

impl Drop for Known {
    fn drop(&mut self) {
        for (mut title, _) in self.0.drain() {
            title.zeroize();
        }
    }
}

impl Known {
    /// `true` when `encoded` was already known; remembers it otherwise.
    fn seen(&mut self, title: &str, encoded: Zeroizing<Vec<u8>>) -> bool {
        let bucket = self.0.entry(title.into()).or_default();
        if bucket.iter().any(|known| secret::ct_eq(known, &encoded)) {
            return true;
        }
        bucket.push(encoded);
        false
    }
}

/// Write `records` into the vault in one generation. A record whose
/// encoding equals an existing record's (compared in constant time) is
/// skipped, so importing the same export twice adds nothing.
///
/// The caller persists the file afterwards.
///
/// # Errors
///
/// `corrupted length` when the frame log does not index; encode and write
/// errors as in [`session::write_records_batch`]. On error the vault is
/// unchanged.
pub fn into_session(
    session: &mut Session,
    file: &mut VaultFile,
    records: Vec<Document>,
) -> anyhow::Result<Merged> {
    let mut known = Known(HashMap::new());
    for row in list_records(session)? {
        if let Ok(doc) = open_record(session, row.id) {
            let title = doc.text(TAG_TITLE).ok().flatten().unwrap_or_default();
            known.seen(title, Zeroizing::new(doc.encode()?));
        }
    }
    let mut fresh = Vec::with_capacity(records.len());
    let mut duplicates = 0usize;
    for doc in records {
        let encoded = Zeroizing::new(doc.encode()?);
        let title = doc.text(TAG_TITLE).ok().flatten().unwrap_or_default();
        if known.seen(title, encoded) {
            duplicates += 1;
        } else {
            fresh.push(doc);
        }
    }
    let ids = write_records_batch(session, file, &fresh)?;
    Ok(Merged { ids, duplicates })
}
