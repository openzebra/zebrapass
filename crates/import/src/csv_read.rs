//! CSV rows into drafts under a [`Mapping`].

use csv::{ByteRecord, ReaderBuilder};

use crate::csv_map::{Mapping, Preset, Target};
use crate::item::{Draft, Item, ItemKind, Slot};
use crate::limits::MAX_CSV_COLUMNS;
use crate::report::{Report, SkipReason};

/// URL `LastPass` gives its secure notes.
const LASTPASS_NOTE_URL: &str = "http://sn";

/// Read a CSV export. `mapping` overrides the detected one.
///
/// # Errors
///
/// `no header row`; `too many columns`; `no known columns` when no header
/// names a standard field; `too many items`.
pub fn read(
    bytes: &[u8],
    mapping: Option<&Mapping>,
    folders_as_tags: bool,
    report: &mut Report,
) -> anyhow::Result<(Vec<Item>, Mapping)> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(bytes);
    let headers = reader
        .byte_headers()
        .map_err(|_| anyhow::anyhow!("no header row"))?
        .clone();
    if headers.len() > MAX_CSV_COLUMNS {
        anyhow::bail!("too many columns");
    }
    if headers.is_empty() {
        anyhow::bail!("no header row");
    }
    let names: Vec<String> = headers
        .iter()
        .map(|name| String::from_utf8_lossy(name).trim().to_owned())
        .collect();
    let mapping = match mapping {
        Some(mapping) if mapping.targets.len() == names.len() => mapping.clone(),
        Some(_) | None => Mapping::detect(&names.iter().map(String::as_str).collect::<Vec<_>>()),
    };
    if !mapping.useful() {
        anyhow::bail!("no known columns: is the first row a header?");
    }
    let mut items = Vec::new();
    let mut record = ByteRecord::new();
    for index in 0.. {
        match reader.read_byte_record(&mut record) {
            Ok(false) => break,
            Ok(true) if record.len() == names.len() => {
                match row(&record, &names, &mapping, folders_as_tags) {
                    Some(draft) => report.admit(&mut items, index, draft)?,
                    None => report.skip(index, SkipReason::Malformed, Box::from("")),
                }
            }
            Ok(true) | Err(_) => report.skip(index, SkipReason::Malformed, Box::from("")),
        }
    }
    Ok((items, mapping))
}

/// One row, or `None` when a cell is not UTF-8.
fn row(record: &ByteRecord, names: &[String], mapping: &Mapping, tags: bool) -> Option<Draft> {
    let mut draft = Draft::new(ItemKind::Login);
    for ((cell, name), target) in record.iter().zip(names).zip(mapping.targets.iter()) {
        let value = std::str::from_utf8(cell).ok()?;
        match target {
            Target::Field(Slot::Url)
                if mapping.preset == Preset::LastPass && value == LASTPASS_NOTE_URL =>
            {
                draft.set_kind(ItemKind::Note);
            }
            Target::Field(slot) => draft.put(*slot, value),
            Target::Folder if tags => draft.tag(value),
            Target::Tags => value.split(',').for_each(|tag| draft.tag(tag)),
            Target::Favorite => draft.favorite(matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )),
            Target::BitwardenFields => value
                .lines()
                .filter_map(|line| line.split_once(": "))
                .for_each(|(field, data)| draft.text(field, data)),
            Target::Custom => draft.text(name, value),
            Target::CustomSecret => draft.secret(name, value),
            Target::Folder | Target::Ignore => {}
        }
    }
    if !draft.has(Slot::Password) {
        draft.set_kind(ItemKind::Note);
    }
    Some(draft)
}
