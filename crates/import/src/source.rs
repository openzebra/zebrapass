//! Import sources, format sniffing, and bounded file reads.

use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::limits::MAX_IMPORT_FILE;

/// Leading bytes of every `KeePass` 2 database.
const KDBX_SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];

/// Where the records come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Bitwarden `.json` export (not password protected).
    BitwardenJson,
    /// `KeePass` / `KeePassXC` `.kdbx` database.
    Kdbx,
    /// `KeePass` XML export.
    KeepassXml,
    /// Enpass `.json` export.
    EnpassJson,
    /// CSV from a browser or another manager.
    Csv,
}

impl Source {
    /// Every source, in menu order.
    pub const ALL: [Self; 5] = [
        Self::BitwardenJson,
        Self::Kdbx,
        Self::KeepassXml,
        Self::EnpassJson,
        Self::Csv,
    ];

    /// Display name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BitwardenJson => "Bitwarden",
            Self::Kdbx => "KeePass / KeePassXC",
            Self::KeepassXml => "KeePass XML",
            Self::EnpassJson => "Enpass",
            Self::Csv => "CSV",
        }
    }

    /// Short file-kind note.
    #[must_use]
    pub const fn format(self) -> &'static str {
        match self {
            Self::BitwardenJson | Self::EnpassJson => ".json",
            Self::Kdbx => ".kdbx",
            Self::KeepassXml => ".xml",
            Self::Csv => "Chrome · Firefox · Safari · 1Password · …",
        }
    }

    /// Whether this build can read the source.
    #[must_use]
    pub const fn supported(self) -> bool {
        match self {
            Self::BitwardenJson | Self::KeepassXml | Self::EnpassJson | Self::Csv => true,
            Self::Kdbx => cfg!(feature = "kdbx"),
        }
    }

    /// Whether the export is plain text on disk (worth deleting afterwards).
    #[must_use]
    pub const fn plaintext(self) -> bool {
        match self {
            Self::BitwardenJson | Self::KeepassXml | Self::EnpassJson | Self::Csv => true,
            Self::Kdbx => false,
        }
    }
}

/// An unauthenticated guess from the first bytes and the file extension,
/// for a live hint only: the chosen source decides the parser.
#[must_use]
pub fn sniff(head: &[u8], extension: Option<&str>) -> Option<Source> {
    if head.starts_with(&KDBX_SIGNATURE) {
        return Some(Source::Kdbx);
    }
    let text = String::from_utf8_lossy(head);
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('<') {
        return text.contains("<KeePassFile").then_some(Source::KeepassXml);
    }
    if text.starts_with('{') {
        return Some(if text.contains("\"category\"") {
            Source::EnpassJson
        } else {
            Source::BitwardenJson
        });
    }
    let csv_extension = extension.is_some_and(|ext| ext.eq_ignore_ascii_case("csv"));
    let csv_header = text.lines().next().is_some_and(|line| line.contains(','));
    (csv_extension || csv_header).then_some(Source::Csv)
}

/// Read `path` into a zeroizing buffer, refusing files over
/// [`MAX_IMPORT_FILE`] before reading them.
///
/// # Errors
///
/// `file too large`; `not a file`; IO errors without the path.
pub fn read_file(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).map_err(|_| anyhow::anyhow!("can't open that file"))?;
    let meta = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("can't open that file"))?;
    if !meta.is_file() {
        anyhow::bail!("not a file");
    }
    if meta.len() > MAX_IMPORT_FILE {
        anyhow::bail!("file too large");
    }
    let capacity = usize::try_from(meta.len()).map_err(|_| anyhow::anyhow!("file too large"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_IMPORT_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("can't read that file"))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_IMPORT_FILE) {
        anyhow::bail!("file too large");
    }
    Ok(bytes)
}

/// The first `len` bytes of `path`, for [`sniff`].
///
/// # Errors
///
/// IO errors without the path.
pub fn read_head(path: &Path, len: u64) -> anyhow::Result<(Zeroizing<Vec<u8>>, u64)> {
    let file = std::fs::File::open(path).map_err(|_| anyhow::anyhow!("can't open that file"))?;
    let meta = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("can't open that file"))?;
    if !meta.is_file() {
        anyhow::bail!("not a file");
    }
    let mut head = Zeroizing::new(Vec::new());
    file.take(len)
        .read_to_end(&mut head)
        .map_err(|_| anyhow::anyhow!("can't read that file"))?;
    Ok((head, meta.len()))
}
