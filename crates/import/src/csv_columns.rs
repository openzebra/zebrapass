//! CSV columns for a mapping editor: headers, a first-row sample shown
//! only where it cannot be a secret, and target cycling.

use std::path::Path;

use csv::{ByteRecord, ReaderBuilder};
use zeroize::Zeroizing;

use crate::csv_map::{Mapping, Target};
use crate::item::Slot;
use crate::limits::MAX_CSV_COLUMNS;
use crate::source::read_head;

/// Bytes read to find the header and the first row.
const HEAD_BYTES: u64 = 64 * 1024;

/// Every target a column can be set to, in cycling order.
pub const TARGETS: [Target; 14] = [
    Target::Field(Slot::Title),
    Target::Field(Slot::Url),
    Target::Field(Slot::Username),
    Target::Field(Slot::Email),
    Target::Field(Slot::Password),
    Target::Field(Slot::Notes),
    Target::Field(Slot::Totp),
    Target::Folder,
    Target::Tags,
    Target::Favorite,
    Target::Custom,
    Target::CustomSecret,
    Target::BitwardenFields,
    Target::Ignore,
];

impl Target {
    /// Display name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Field(Slot::Title) => "Title",
            Self::Field(Slot::Url) => "URL",
            Self::Field(Slot::Username) => "Username",
            Self::Field(Slot::Email) => "Email",
            Self::Field(Slot::Password) => "Password",
            Self::Field(Slot::Notes) => "Notes",
            Self::Field(Slot::Totp) => "TOTP",
            Self::Folder => "Folder → tag",
            Self::Tags => "Tags",
            Self::Favorite => "Favorite (1/true/yes)",
            Self::BitwardenFields => "Bitwarden fields",
            Self::Ignore => "Skip",
            Self::Custom => "Custom field",
            Self::CustomSecret => "Custom secret field",
        }
    }

    /// The next (or previous) target, wrapping around.
    #[must_use]
    pub fn cycle(self, forward: bool) -> Self {
        let len = TARGETS.len();
        let at = TARGETS
            .iter()
            .position(|target| *target == self)
            .unwrap_or(0);
        let next = if forward {
            (at + 1) % len
        } else {
            (at + len - 1) % len
        };
        TARGETS.get(next).copied().unwrap_or(self)
    }

    /// Whether values under this target are shown as samples: only fields
    /// that are never secret.
    #[must_use]
    pub const fn shows_sample(self) -> bool {
        match self {
            Self::Field(Slot::Title | Slot::Url | Slot::Username | Slot::Email)
            | Self::Folder
            | Self::Tags
            | Self::Favorite => true,
            Self::Field(Slot::Password | Slot::Notes | Slot::Totp)
            | Self::BitwardenFields
            | Self::Ignore
            | Self::Custom
            | Self::CustomSecret => false,
        }
    }
}

impl Mapping {
    /// Set what `column` feeds; out-of-range columns are ignored.
    pub fn set(&mut self, column: usize, target: Target) {
        if let Some(slot) = self.targets.get_mut(column) {
            *slot = target;
        }
    }

    /// Whether the detected mapping is worth a look before importing:
    /// an unknown export, or columns kept only as custom fields.
    #[must_use]
    pub fn needs_review(&self) -> bool {
        self.preset == crate::Preset::Generic
            || self
                .targets
                .iter()
                .any(|target| matches!(target, Target::Custom | Target::CustomSecret))
    }
}

/// One CSV column.
pub struct Column {
    /// Header text.
    pub header: Box<str>,
    sample: Zeroizing<String>,
}

impl std::fmt::Debug for Column {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Column")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl Column {
    /// The first-row value, only when `target` can never hold a secret.
    #[must_use]
    pub fn sample(&self, target: Target) -> Option<&str> {
        target.shows_sample().then_some(self.sample.as_str())
    }
}

/// Headers, first-row samples, and the detected mapping of the CSV at
/// `path`. Reads only the first 64 KiB.
///
/// # Errors
///
/// IO errors; `no header row`; `too many columns`.
pub fn csv_columns(path: &Path) -> anyhow::Result<(Box<[Column]>, Mapping)> {
    let (head, _) = read_head(path, HEAD_BYTES)?;
    let bytes = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&head);
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(bytes);
    let headers = reader
        .byte_headers()
        .map_err(|_| anyhow::anyhow!("no header row"))?
        .clone();
    if headers.is_empty() {
        anyhow::bail!("no header row");
    }
    if headers.len() > MAX_CSV_COLUMNS {
        anyhow::bail!("too many columns");
    }
    let mut first = ByteRecord::new();
    if reader.read_byte_record(&mut first).is_err() {
        first.clear();
    }
    let names: Vec<String> = headers
        .iter()
        .map(|name| String::from_utf8_lossy(name).trim().to_owned())
        .collect();
    let mapping = Mapping::detect(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let columns = names
        .into_iter()
        .enumerate()
        .map(|(index, header)| Column {
            header: header.into_boxed_str(),
            sample: Zeroizing::new(
                first
                    .get(index)
                    .map(|cell| String::from_utf8_lossy(cell).into_owned())
                    .unwrap_or_default(),
            ),
        })
        .collect();
    Ok((columns, mapping))
}
