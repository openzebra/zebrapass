//! Vault home: filters, fuzzy search, the record list, and the detail pane.

use std::cmp::Reverse;

use local::Usage;
use record::{
    Document, ValueType, TAG_EMAIL, TAG_NOTES, TAG_PASSWORD, TAG_TOTP, TAG_URL, TAG_USERNAME,
};

use crate::secure::health::HealthReport;
use crate::secure::reveal::RevealGuard;
use crate::ui::input::TextInput;
use crate::vault::records::{standard_label, RecordKind, Summary, CUSTOM_FAVORITE, CUSTOM_TAGS};

/// Longest search query.
pub const MAX_QUERY: usize = 128;
/// Most tag filters listed.
pub const MAX_TAG_FILTERS: usize = 24;

/// List filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Everything.
    All,
    /// Favorites.
    Favorites,
    /// Records with a password.
    Logins,
    /// Records without a password.
    Notes,
    /// Records with a TOTP secret.
    Totp,
    /// Weak passwords (after a health check).
    Weak,
    /// Reused passwords (after a health check).
    Reused,
    /// Old passwords (after a health check).
    Old,
    /// A tag.
    Tag(Box<str>),
}

impl Filter {
    /// Display label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::All => String::from("All"),
            Self::Favorites => String::from("Favorites"),
            Self::Logins => String::from("Logins"),
            Self::Notes => String::from("Notes"),
            Self::Totp => String::from("With TOTP"),
            Self::Weak => String::from("Weak"),
            Self::Reused => String::from("Reused"),
            Self::Old => String::from("Old (>1y)"),
            Self::Tag(tag) => format!("#{tag}"),
        }
    }

    /// Whether `summary` passes.
    #[must_use]
    pub fn keeps(&self, summary: &Summary, health: Option<&HealthReport>) -> bool {
        let flagged = |ids: &[u32]| ids.contains(&summary.id);
        match self {
            Self::All => true,
            Self::Favorites => summary.favorite,
            Self::Logins => summary.kind == RecordKind::Login,
            Self::Notes => summary.kind == RecordKind::Note,
            Self::Totp => summary.has_totp,
            Self::Weak => health.is_some_and(|report| flagged(&report.weak)),
            Self::Reused => {
                health.is_some_and(|report| report.reused.iter().any(|group| flagged(group)))
            }
            Self::Old => health.is_some_and(|report| flagged(&report.old)),
            Self::Tag(tag) => summary.tag_list().any(|item| item == &**tag),
        }
    }
}

/// Filters pane content with counts.
#[must_use]
pub fn filter_entries(cache: &[Summary], health: Option<&HealthReport>) -> Vec<(Filter, usize)> {
    let mut entries: Vec<Filter> = vec![
        Filter::Favorites,
        Filter::All,
        Filter::Logins,
        Filter::Notes,
        Filter::Totp,
    ];
    if health.is_some() {
        entries.extend([Filter::Weak, Filter::Reused, Filter::Old]);
    }
    let mut tags: Vec<&str> = cache.iter().flat_map(Summary::tag_list).collect();
    tags.sort_unstable();
    tags.dedup();
    entries.extend(
        tags.into_iter()
            .take(MAX_TAG_FILTERS)
            .map(|tag| Filter::Tag(tag.into())),
    );
    entries
        .into_iter()
        .map(|filter| {
            let count = cache
                .iter()
                .filter(|summary| filter.keeps(summary, health))
                .count();
            (filter, count)
        })
        .collect()
}

/// Indexes into `cache` that pass `filter` and `query`, in list order.
///
/// Without a query, the records this device copies from most (and most
/// recently) come first, then the rest by title; with one, the best match
/// comes first and usage breaks ties.
#[must_use]
pub fn visible(
    cache: &[Summary],
    filter: &Filter,
    query: &str,
    health: Option<&HealthReport>,
    usage: &Usage,
    now_ms: u64,
) -> Vec<usize> {
    let mut scored: Vec<(i32, usize)> = cache
        .iter()
        .enumerate()
        .filter(|(_, summary)| filter.keeps(summary, health))
        .filter_map(|(index, summary)| {
            summary
                .search_score(query.trim())
                .map(|score| (score, index))
        })
        .collect();
    let used = |index: usize| {
        cache
            .get(index)
            .and_then(|summary| usage.get(summary.id))
            .map_or((0, 0), |entry| (entry.rank(now_ms), entry.last_ms))
    };
    if query.trim().is_empty() {
        scored.sort_by_cached_key(|(_, index)| {
            let title = cache
                .get(*index)
                .map(|summary| summary.display_title().to_lowercase());
            (Reverse(used(*index)), title)
        });
    } else {
        scored.sort_by_key(|(score, index)| (Reverse(*score), Reverse(used(*index))));
    }
    scored.into_iter().map(|(_, index)| index).collect()
}

/// Which pane has focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    /// Filters.
    Filters,
    /// Record list.
    List,
    /// Record detail.
    Detail,
}

/// How a detail row renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// Plain text.
    Text,
    /// Masked secret.
    Secret,
    /// TOTP secret: shows the current code (masked until revealed), never the secret.
    Totp,
}

/// One detail row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Field tag.
    pub tag: u16,
    /// Label.
    pub label: String,
    /// Rendering.
    pub kind: RowKind,
    /// Copy key hint, if any.
    pub copy_key: Option<char>,
}

/// The open record.
#[derive(Debug)]
pub struct Detail {
    /// Record id.
    pub id: u32,
    /// Revision shown.
    pub revision: u64,
    /// Write time.
    pub timestamp_ms: u64,
    /// The document (wiped on drop).
    pub doc: Document,
    /// Rows in display order.
    pub rows: Vec<Row>,
    /// Focused row.
    pub cursor: usize,
    /// Reveal state.
    pub reveal: RevealGuard,
}

impl Detail {
    /// Detail of `doc`.
    #[must_use]
    pub fn new(id: u32, revision: u64, timestamp_ms: u64, doc: Document) -> Self {
        let rows = rows_of(&doc);
        let cursor = rows
            .iter()
            .position(|row| row.tag == TAG_PASSWORD)
            .unwrap_or(0);
        Self {
            id,
            revision,
            timestamp_ms,
            doc,
            rows,
            cursor,
            reveal: RevealGuard::default(),
        }
    }

    /// The focused row, or the first secret row when the focus is on text.
    #[must_use]
    pub fn secret_row(&self) -> Option<&Row> {
        self.rows
            .get(self.cursor)
            .filter(|row| row.kind != RowKind::Text)
            .or_else(|| self.rows.iter().find(|row| row.kind != RowKind::Text))
    }
}

/// Rows in the order a login is read: URL, username, email, password,
/// TOTP, notes, then custom fields.
#[must_use]
pub fn rows_of(doc: &Document) -> Vec<Row> {
    let standard = [
        (TAG_URL, Some('o')),
        (TAG_USERNAME, Some('u')),
        (TAG_EMAIL, Some('e')),
        (TAG_PASSWORD, Some('c')),
        (TAG_TOTP, Some('t')),
        (TAG_NOTES, None),
    ];
    let mut rows: Vec<Row> = standard
        .iter()
        .filter_map(|(tag, copy_key)| {
            doc.get(*tag).map(|field| Row {
                tag: *tag,
                label: standard_label(*tag).to_lowercase(),
                kind: kind_of(*tag, field.vtype),
                copy_key: *copy_key,
            })
        })
        .collect();
    rows.extend(
        doc.fields()
            .iter()
            .filter(|field| record::is_custom(field.tag) && field.vtype != ValueType::Bytes)
            .filter_map(|field| {
                let name = doc.custom_name(field.tag).ok().flatten()?;
                (name != CUSTOM_TAGS && name != CUSTOM_FAVORITE).then(|| Row {
                    tag: field.tag,
                    label: name.to_owned(),
                    kind: kind_of(field.tag, field.vtype),
                    copy_key: None,
                })
            }),
    );
    rows
}

const fn kind_of(tag: u16, vtype: ValueType) -> RowKind {
    match (tag, vtype) {
        (TAG_TOTP, _) => RowKind::Totp,
        (_, ValueType::Secret | ValueType::Bytes) => RowKind::Secret,
        (_, ValueType::Text) => RowKind::Text,
    }
}

/// Home state.
#[derive(Debug)]
pub struct Home {
    /// Search query.
    pub query: TextInput,
    /// The search box has focus.
    pub searching: bool,
    /// Active filter.
    pub filter: Filter,
    /// Focused pane.
    pub pane: Pane,
    /// Selected row among the visible records.
    pub selected: usize,
    /// Cursor in the filters pane.
    pub filter_cursor: usize,
    /// The open record.
    pub detail: Option<Box<Detail>>,
    /// Narrow layout: the detail replaces the list.
    pub stacked: bool,
}

impl Default for Home {
    fn default() -> Self {
        Self {
            query: TextInput::new(MAX_QUERY),
            searching: false,
            filter: Filter::All,
            pane: Pane::List,
            selected: 0,
            filter_cursor: 1,
            detail: None,
            stacked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests may unwrap and index"
    )]

    use local::Usage;
    use record::{Document, TAG_TITLE};

    use super::{visible, Filter};
    use crate::vault::records::{Summary, CUSTOM_FAVORITE};

    const NOW: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 86_400_000;

    fn summary(id: u32, title: &str, favorite: bool) -> Summary {
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, title);
        if favorite {
            doc.set_custom(0x8000, CUSTOM_FAVORITE, record::ValueType::Text, b"1")
                .unwrap();
        }
        Summary::of(id, 1, 0, &doc)
    }

    fn cache() -> Vec<Summary> {
        vec![
            summary(0, "alpha", true),
            summary(1, "bank", true),
            summary(2, "cloud", false),
            summary(3, "delta", false),
            summary(4, "bankside", false),
        ]
    }

    fn ids(cache: &[Summary], indexes: &[usize]) -> Vec<u32> {
        indexes.iter().map(|index| cache[*index].id).collect()
    }

    #[test]
    fn most_used_first_then_titles() {
        let cache = cache();
        let mut usage = Usage::default();
        assert_eq!(
            ids(
                &cache,
                &visible(&cache, &Filter::All, "", None, &usage, NOW)
            ),
            [0, 1, 4, 2, 3]
        );
        usage.note(3, NOW - DAY_MS);
        usage.note(2, NOW - 200 * DAY_MS);
        usage.note(2, NOW - 200 * DAY_MS);
        usage.note(2, NOW - 200 * DAY_MS);
        assert_eq!(
            ids(
                &cache,
                &visible(&cache, &Filter::All, "", None, &usage, NOW)
            ),
            [3, 2, 0, 1, 4]
        );
    }

    #[test]
    fn favorites_rank_by_use_too() {
        let cache = cache();
        let mut usage = Usage::default();
        usage.note(1, NOW);
        assert_eq!(
            ids(
                &cache,
                &visible(&cache, &Filter::Favorites, "", None, &usage, NOW)
            ),
            [1, 0]
        );
    }

    #[test]
    fn search_relevance_wins_and_use_breaks_ties() {
        let cache = vec![summary(0, "bank", false), summary(1, "bank", false)];
        let mut usage = Usage::default();
        usage.note(1, NOW);
        assert_eq!(
            ids(
                &cache,
                &visible(&cache, &Filter::All, "bank", None, &usage, NOW)
            ),
            [1, 0]
        );
        let cache = vec![
            summary(0, "bank", false),
            summary(1, "b-a-n-k notes", false),
        ];
        let mut usage = Usage::default();
        usage.note(1, NOW);
        let order = visible(&cache, &Filter::All, "bank", None, &usage, NOW);
        let scores: Vec<i32> = order
            .iter()
            .map(|index| cache[*index].search_score("bank").unwrap())
            .collect();
        assert!(scores.windows(2).all(|pair| pair[0] >= pair[1]));
    }
}
