//! Read exports of other password managers into record documents.
//!
//! Every reader fills a [`Draft`] per foreign item; [`Draft`] is the only
//! code that builds a [`record::Document`]. This crate never touches vault
//! keys: it turns untrusted bytes into documents plus a [`Report`] that
//! holds no secret.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "keepass transitively pulls a second syn major"
)]

mod bitwarden;
mod csv_map;
mod csv_read;
mod item;
#[cfg(feature = "kdbx")]
mod kdbx;
mod kdbx_header;
#[cfg(feature = "kdbx")]
mod keepass_keys;
mod limits;
mod report;
mod source;
mod text;

use zeroize::Zeroizing;

pub use csv_map::{Mapping, Preset, Target};
pub use item::{Draft, Item, ItemKind, Slot, CUSTOM_KIND};
pub use kdbx_header::{check as check_kdf_cost, kdf_cost, KdfCost};
pub use limits::{MAX_CSV_COLUMNS, MAX_CUSTOM, MAX_FIELD, MAX_IMPORT_FILE, MAX_ITEMS};
pub use report::{Report, Skip, SkipReason};
pub use source::{read_file, read_head, sniff, Source};

/// What to read.
pub struct Request {
    /// The export file's bytes.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Which parser to use.
    pub source: Source,
    /// CSV only: column targets; `None` detects them from the header.
    pub mapping: Option<Mapping>,
    /// Folder, group, and collection names become tags.
    pub folders_as_tags: bool,
    /// `.kdbx` only: the master password.
    pub password: Option<Zeroizing<Vec<u8>>>,
    /// `.kdbx` only: the key file's bytes.
    pub key_file: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Parsed items plus what happened.
#[derive(Debug)]
pub struct Parsed {
    /// Importable records, in source order.
    pub items: Vec<Item>,
    /// Counts and skips.
    pub report: Report,
    /// CSV only: the mapping that was used.
    pub mapping: Option<Mapping>,
}

/// Parse `request`.
///
/// # Errors
///
/// Format errors with a human message that never repeats file contents;
/// `not supported yet` for sources this build cannot read.
pub fn parse(request: &Request) -> anyhow::Result<Parsed> {
    let mut report = Report::default();
    let (items, mapping) = match request.source {
        Source::BitwardenJson => (
            bitwarden::read(&request.bytes, request.folders_as_tags, &mut report)?,
            None,
        ),
        Source::Csv => {
            let (items, mapping) = csv_read::read(
                &request.bytes,
                request.mapping.as_ref(),
                request.folders_as_tags,
                &mut report,
            )?;
            (items, Some(mapping))
        }
        #[cfg(feature = "kdbx")]
        Source::Kdbx => {
            let credentials = kdbx::Credentials {
                password: request.password.as_deref().map(Vec::as_slice),
                key_file: request.key_file.as_deref().map(Vec::as_slice),
            };
            (
                kdbx::read(
                    &request.bytes,
                    &credentials,
                    request.folders_as_tags,
                    &mut report,
                )?,
                None,
            )
        }
        #[cfg(not(feature = "kdbx"))]
        Source::Kdbx => anyhow::bail!("not supported yet"),
        Source::KeepassXml | Source::EnpassJson => {
            anyhow::bail!("not supported yet")
        }
    };
    Ok(Parsed {
        items,
        report,
        mapping,
    })
}
