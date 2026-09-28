//! What the user reviews before anything is written: text-only rows, the
//! report, and which items are included.

use record::{Document, CUSTOM_TAGS, TAG_EMAIL, TAG_TITLE, TAG_USERNAME};
use zeroize::Zeroize;

use crate::item::{Item, ItemKind};
use crate::report::Report;
use crate::{Mapping, Parsed};

/// One review row. Text fields only; secrets never reach a row. Wiped on
/// drop.
#[derive(Debug)]
pub struct Row {
    /// Title.
    pub title: Box<str>,
    /// Username, or email when there is no username.
    pub username: Box<str>,
    /// Comma-separated tags.
    pub tags: Box<str>,
    /// Item kind.
    pub kind: ItemKind,
}

impl Drop for Row {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.tags.zeroize();
    }
}

impl Row {
    fn of(item: &Item) -> Self {
        let doc = &item.doc;
        let text = |tag| doc.text(tag).ok().flatten().unwrap_or_default();
        let username = match text(TAG_USERNAME) {
            "" => text(TAG_EMAIL),
            name => name,
        };
        Self {
            title: text(TAG_TITLE).into(),
            username: username.into(),
            tags: custom_text(doc, CUSTOM_TAGS).unwrap_or_default().into(),
            kind: item.kind,
        }
    }
}

/// Parsed items under review, each included until excluded.
#[derive(Debug)]
pub struct Review {
    parsed: Parsed,
    rows: Box<[Row]>,
    included: Vec<bool>,
}

impl From<Parsed> for Review {
    fn from(parsed: Parsed) -> Self {
        let rows = parsed.items.iter().map(Row::of).collect();
        let included = vec![true; parsed.items.len()];
        Self {
            parsed,
            rows,
            included,
        }
    }
}

impl Review {
    /// One row per item, in source order.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The parsed items (for checks the application runs itself).
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.parsed.items
    }

    /// Counts and skips.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.parsed.report
    }

    /// CSV only: how the columns were read.
    #[must_use]
    pub const fn mapping(&self) -> Option<&Mapping> {
        self.parsed.mapping.as_ref()
    }

    /// Whether item `index` will be imported.
    #[must_use]
    pub fn is_included(&self, index: usize) -> bool {
        self.included.get(index).copied().unwrap_or(false)
    }

    /// Include or exclude item `index`.
    pub fn toggle(&mut self, index: usize) {
        if let Some(on) = self.included.get_mut(index) {
            *on = !*on;
        }
    }

    /// Exclude everything when all are included; include everything
    /// otherwise.
    pub fn toggle_all(&mut self) {
        let all = self.included.iter().all(|on| *on);
        self.included.iter_mut().for_each(|on| *on = !all);
    }

    /// Items that will be imported.
    #[must_use]
    pub fn included_count(&self) -> usize {
        self.included.iter().filter(|on| **on).count()
    }

    /// The included documents, in source order. The rest are wiped.
    #[must_use]
    pub fn into_records(self) -> Vec<Document> {
        let Self {
            parsed, included, ..
        } = self;
        parsed
            .items
            .into_iter()
            .zip(included)
            .filter(|(_, on)| *on)
            .map(|(item, _)| *item.doc)
            .collect()
    }
}

/// Text of the custom field named `name`.
fn custom_text<'a>(doc: &'a Document, name: &str) -> Option<&'a str> {
    doc.fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| doc.custom_name(field.tag).ok().flatten() == Some(name))
        .and_then(|field| doc.text(field.tag).ok().flatten())
}
