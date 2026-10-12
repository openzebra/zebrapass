//! Record summaries for the list, custom-field helpers, and fuzzy search.
//!
//! Summaries carry only text-typed fields (title, username, URL, tags).
//! Secret-typed fields are never copied into the cache and never searched.
//! The cache is wiped on drop, which happens on lock.

use record::{
    Document, ValueType, TAG_CUSTOM_MIN, TAG_EMAIL, TAG_NOTES, TAG_PASSWORD, TAG_TITLE, TAG_TOTP,
    TAG_URL, TAG_USERNAME,
};
use session::Session;
use zeroize::Zeroize;

pub use record::{CUSTOM_FAVORITE, CUSTOM_TAGS};

/// What a record is, for its list glyph and filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    /// Has a password.
    Login,
    /// No password.
    Note,
    /// Did not open (shown, never hidden).
    Unreadable,
}

/// One list row.
#[derive(Debug)]
pub struct Summary {
    /// Revision of the winning frame.
    pub revision: u64,
    /// Advisory write time.
    pub timestamp_ms: u64,
    /// Record id.
    pub id: u32,
    /// Row kind.
    pub kind: RecordKind,
    /// Has a TOTP secret.
    pub has_totp: bool,
    /// Marked as favorite.
    pub favorite: bool,
    /// Title.
    pub title: Box<str>,
    /// Username, or email when there is no username.
    pub username: Box<str>,
    /// URL.
    pub url: Box<str>,
    /// Comma-separated tags.
    pub tags: Box<str>,
}

impl Drop for Summary {
    fn drop(&mut self) {
        for text in [
            &mut self.title,
            &mut self.username,
            &mut self.url,
            &mut self.tags,
        ] {
            text.zeroize();
        }
    }
}

impl Summary {
    /// Build the row for `doc`.
    #[must_use]
    pub fn of(id: u32, revision: u64, timestamp_ms: u64, doc: &Document) -> Self {
        let text = |tag| doc.text(tag).ok().flatten().unwrap_or_default();
        let username = match text(TAG_USERNAME) {
            "" => text(TAG_EMAIL),
            name => name,
        };
        Self {
            revision,
            timestamp_ms,
            id,
            kind: if doc.get(TAG_PASSWORD).is_some() {
                RecordKind::Login
            } else {
                RecordKind::Note
            },
            has_totp: doc.get(TAG_TOTP).is_some(),
            favorite: custom_text(doc, CUSTOM_FAVORITE) == Some("1"),
            title: text(TAG_TITLE).into(),
            username: username.into(),
            url: text(TAG_URL).into(),
            tags: custom_text(doc, CUSTOM_TAGS).unwrap_or_default().into(),
        }
    }

    /// Placeholder for a record that did not open.
    #[must_use]
    pub fn unreadable(id: u32, revision: u64, timestamp_ms: u64) -> Self {
        Self {
            revision,
            timestamp_ms,
            id,
            kind: RecordKind::Unreadable,
            has_totp: false,
            favorite: false,
            title: format!("unreadable record #{id}").into(),
            username: Box::from(""),
            url: Box::from(""),
            tags: Box::from(""),
        }
    }

    /// Title, or a placeholder for untitled records.
    #[must_use]
    pub fn display_title(&self) -> &str {
        if self.title.is_empty() {
            "(untitled)"
        } else {
            &self.title
        }
    }

    /// Tags as trimmed, non-empty items.
    pub fn tag_list(&self) -> impl Iterator<Item = &str> {
        self.tags
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
    }

    /// Best fuzzy score of `query` against the searchable fields.
    #[must_use]
    pub fn search_score(&self, query: &str) -> Option<i32> {
        [
            (&*self.title, 3),
            (&*self.username, 2),
            (&*self.url, 1),
            (&*self.tags, 1),
        ]
        .iter()
        .filter_map(|(text, weight)| fuzzy_score(query, text).map(|score| score * weight))
        .max()
    }
}

/// Open every live record into a summary. Records that fail to open are
/// listed as unreadable instead of being hidden.
///
/// # Errors
///
/// `corrupted length` when the frame log does not index.
pub fn build_cache(session: &Session) -> anyhow::Result<Box<[Summary]>> {
    Ok(session::list_records(session)?
        .iter()
        .filter_map(|row| match session::open_record(session, row.id) {
            Ok(doc) if is_shared_reference(&doc) => None,
            Ok(doc) => Some(Summary::of(row.id, row.revision, row.timestamp_ms, &doc)),
            Err(_) => Some(Summary::unreadable(row.id, row.revision, row.timestamp_ms)),
        })
        .collect())
}

/// Whether `doc` is the record that points at a shared vault: those are not
/// logins or notes and never appear in the list.
#[must_use]
pub fn is_shared_reference(doc: &Document) -> bool {
    doc.data(record::TAG_SHARED_MARK).ok().flatten() == Some(&[1u8][..])
}

/// Text of the custom field named `name`.
#[must_use]
pub fn custom_text<'a>(doc: &'a Document, name: &str) -> Option<&'a str> {
    let tag = custom_tag(doc, name)?;
    doc.text(tag).ok().flatten()
}

/// Tag of the custom field named `name`.
#[must_use]
pub fn custom_tag(doc: &Document, name: &str) -> Option<u16> {
    doc.fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| doc.custom_name(field.tag).ok().flatten() == Some(name))
        .map(|field| field.tag)
}

/// The next free custom tag.
#[must_use]
pub fn next_custom_tag(doc: &Document) -> Option<u16> {
    doc.fields()
        .iter()
        .map(|field| field.tag)
        .filter(|tag| record::is_custom(*tag))
        .max()
        .map_or(Some(TAG_CUSTOM_MIN), |tag| tag.checked_add(1))
}

/// Set (or with `None`, remove) a named custom text field.
///
/// # Errors
///
/// `custom name too long` for an over-long name; `too many fields` when no
/// custom tag is left.
pub fn set_custom_text(doc: &mut Document, name: &str, value: Option<&str>) -> anyhow::Result<()> {
    let existing = custom_tag(doc, name);
    match (existing, value) {
        (Some(tag), None | Some("")) => {
            doc.remove(tag);
            Ok(())
        }
        (None, None | Some("")) => Ok(()),
        (tag, Some(text)) => {
            let tag = tag
                .or_else(|| next_custom_tag(doc))
                .ok_or_else(|| anyhow::anyhow!("too many fields"))?;
            doc.set_custom(tag, name, ValueType::Text, text.as_bytes())
        }
    }
}

/// Human label of a standard tag.
#[must_use]
pub const fn standard_label(tag: u16) -> &'static str {
    match tag {
        TAG_TITLE => "Title",
        TAG_URL => "URL",
        TAG_USERNAME => "Username",
        TAG_EMAIL => "Email",
        TAG_PASSWORD => "Password",
        TAG_NOTES => "Notes",
        TAG_TOTP => "TOTP",
        _ => "Field",
    }
}

/// Subsequence match with bonuses for consecutive letters, word starts, and
/// a prefix. `None` when `query` is not a subsequence of `text`. ASCII
/// case-insensitive.
#[must_use]
pub fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let mut score = 0i32;
    let mut wanted = query.chars().map(|ch| ch.to_ascii_lowercase()).peekable();
    let mut previous: Option<char> = None;
    let mut matched_previous = false;
    for (position, ch) in text.chars().enumerate() {
        let Some(&next) = wanted.peek() else { break };
        let lower = ch.to_ascii_lowercase();
        if lower == next {
            wanted.next();
            score += 1;
            if matched_previous {
                score += 4;
            }
            if previous.is_none_or(|prev| !prev.is_alphanumeric()) {
                score += 6;
            }
            if position == 0 {
                score += 8;
            }
            matched_previous = true;
        } else {
            matched_previous = false;
        }
        previous = Some(ch);
    }
    wanted.peek().is_none().then_some(score)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE, TAG_USERNAME};

    use super::{custom_text, fuzzy_score, set_custom_text, RecordKind, Summary, CUSTOM_TAGS};

    #[test]
    fn fuzzy_prefers_prefix_and_word_starts() {
        assert!(fuzzy_score("git", "GitHub").unwrap() > fuzzy_score("git", "legit tool").unwrap());
        assert!(fuzzy_score("gh", "GitHub").is_some());
        assert!(fuzzy_score("xyz", "GitHub").is_none());
    }

    #[test]
    fn summary_never_carries_secret_fields() {
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, "GitHub");
        doc.set_text(TAG_USERNAME, "octocat");
        doc.set_data(TAG_PASSWORD, ValueType::Secret, b"hunter2");
        set_custom_text(&mut doc, CUSTOM_TAGS, Some("work, code")).unwrap();
        let summary = Summary::of(1, 1, 0, &doc);
        assert_eq!(summary.kind, RecordKind::Login);
        assert_eq!(summary.tag_list().collect::<Vec<_>>(), ["work", "code"]);
        let dump = format!("{summary:?}");
        assert!(!dump.contains("hunter2"));
        assert!(summary.search_score("hunter").is_none());
        set_custom_text(&mut doc, CUSTOM_TAGS, None).unwrap();
        assert!(custom_text(&doc, CUSTOM_TAGS).is_none());
    }
}
