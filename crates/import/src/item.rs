//! The one mapping path from a foreign item to a [`Document`].

use record::{
    Document, ValueType, CUSTOM_FAVORITE, CUSTOM_TAGS, MAX_CUSTOM_NAME, TAG_CUSTOM_MIN, TAG_EMAIL,
    TAG_NOTES, TAG_PASSWORD, TAG_TITLE, TAG_TOTP, TAG_URL, TAG_USERNAME,
};
use zeroize::Zeroizing;

use crate::limits::{MAX_CUSTOM, MAX_FIELD};
use crate::report::SkipReason;

/// Name of the custom field that records a non-login kind.
pub const CUSTOM_KIND: &str = "kind";

/// Title given to an item with no title, URL, or username.
const FALLBACK_TITLE: &str = "Imported item";

/// What a foreign item is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ItemKind {
    /// Website login.
    #[default]
    Login,
    /// Secure note.
    Note,
    /// Payment card.
    Card,
    /// Identity document or profile.
    Identity,
    /// SSH key.
    SshKey,
}

impl ItemKind {
    /// Number of kinds, for per-kind counters.
    pub const COUNT: usize = 5;

    /// Position in per-kind counters.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Login => 0,
            Self::Note => 1,
            Self::Card => 2,
            Self::Identity => 3,
            Self::SshKey => 4,
        }
    }

    /// Value of the `kind` custom field; `None` for kinds the record model
    /// already tells apart (a login has a password, a note does not).
    #[must_use]
    pub const fn marker(self) -> Option<&'static str> {
        match self {
            Self::Login | Self::Note => None,
            Self::Card => Some("card"),
            Self::Identity => Some("identity"),
            Self::SshKey => Some("ssh-key"),
        }
    }
}

/// A standard record field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Title.
    Title,
    /// URL.
    Url,
    /// Username.
    Username,
    /// Email.
    Email,
    /// Password (secret).
    Password,
    /// Notes.
    Notes,
    /// TOTP secret or `otpauth://` URI (secret).
    Totp,
}

impl Slot {
    const COUNT: usize = 7;

    const fn index(self) -> usize {
        match self {
            Self::Title => 0,
            Self::Url => 1,
            Self::Username => 2,
            Self::Email => 3,
            Self::Password => 4,
            Self::Notes => 5,
            Self::Totp => 6,
        }
    }

    const fn tag(self) -> u16 {
        match self {
            Self::Title => TAG_TITLE,
            Self::Url => TAG_URL,
            Self::Username => TAG_USERNAME,
            Self::Email => TAG_EMAIL,
            Self::Password => TAG_PASSWORD,
            Self::Notes => TAG_NOTES,
            Self::Totp => TAG_TOTP,
        }
    }

    const fn vtype(self) -> ValueType {
        match self {
            Self::Password | Self::Totp => ValueType::Secret,
            Self::Title | Self::Url | Self::Username | Self::Email | Self::Notes => ValueType::Text,
        }
    }

    /// Custom-field name for a second value of this slot.
    const fn label(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Url => "url",
            Self::Username => "username",
            Self::Email => "email",
            Self::Password => "password",
            Self::Notes => "notes",
            Self::Totp => "totp",
        }
    }
}

struct Custom {
    name: Box<str>,
    vtype: ValueType,
    data: Zeroizing<Vec<u8>>,
}

/// One foreign item being mapped. Every value lives in a zeroizing buffer.
#[derive(Default)]
pub struct Draft {
    slots: [Zeroizing<Vec<u8>>; Slot::COUNT],
    custom: Vec<Custom>,
    tags: Vec<Box<str>>,
    kind: ItemKind,
    favorite: bool,
    too_large: bool,
    too_many: bool,
}

impl std::fmt::Debug for Draft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Draft")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Draft {
    /// An empty draft of `kind`.
    #[must_use]
    pub fn new(kind: ItemKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Fill a standard field. Blank values are ignored; a second value for a
    /// filled field becomes a custom field (`url 2`, `url 3`, …).
    pub fn put(&mut self, slot: Slot, value: &str) {
        let value = trim_value(slot, value);
        if value.is_empty() {
            return;
        }
        if !self.fits(value) {
            return;
        }
        match self.slots.get_mut(slot.index()) {
            Some(field) if field.is_empty() => field.extend_from_slice(value.as_bytes()),
            Some(_) => {
                let taken = self
                    .custom
                    .iter()
                    .filter(|custom| custom.name.starts_with(slot.label()))
                    .count();
                let name = format!("{} {}", slot.label(), taken + 2);
                self.push_custom(&name, slot.vtype(), value.as_bytes());
            }
            None => {}
        }
    }

    /// Add a custom text field. Blank values are ignored.
    pub fn text(&mut self, name: &str, value: &str) {
        if !value.trim().is_empty() {
            self.push_custom(name, ValueType::Text, value.as_bytes());
        }
    }

    /// Add a custom secret field. Empty values are ignored.
    pub fn secret(&mut self, name: &str, value: &str) {
        if !value.is_empty() {
            self.push_custom(name, ValueType::Secret, value.as_bytes());
        }
    }

    /// Add a tag. Commas (the tag separator) become spaces; blanks and
    /// repeats are dropped.
    pub fn tag(&mut self, tag: &str) {
        let tag = tag.trim().replace(',', " ");
        if !tag.is_empty() && !self.tags.iter().any(|known| **known == *tag) {
            self.tags.push(tag.into_boxed_str());
        }
    }

    /// Mark as favorite.
    pub const fn favorite(&mut self, on: bool) {
        self.favorite = on;
    }

    /// The item kind.
    pub const fn set_kind(&mut self, kind: ItemKind) {
        self.kind = kind;
    }

    /// Whether a standard field holds a value.
    #[must_use]
    pub fn has(&self, slot: Slot) -> bool {
        self.slots
            .get(slot.index())
            .is_some_and(|field| !field.is_empty())
    }

    /// The title, when set: the only text a report may repeat.
    #[must_use]
    pub fn title(&self) -> &str {
        self.slot(Slot::Title)
    }

    fn slot(&self, slot: Slot) -> &str {
        self.slots
            .get(slot.index())
            .and_then(|field| std::str::from_utf8(field).ok())
            .unwrap_or_default()
    }

    const fn fits(&mut self, value: &str) -> bool {
        let fits = value.len() <= MAX_FIELD;
        self.too_large |= !fits;
        fits
    }

    fn push_custom(&mut self, name: &str, vtype: ValueType, data: &[u8]) {
        if data.len() > MAX_FIELD {
            self.too_large = true;
            return;
        }
        if self.custom.len() >= MAX_CUSTOM {
            self.too_many = true;
            return;
        }
        self.custom.push(Custom {
            name: custom_name(name),
            vtype,
            data: Zeroizing::new(data.to_vec()),
        });
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(|field| field.is_empty()) && self.custom.is_empty()
    }

    /// Title fallback: URL host, then username, then a fixed label.
    fn fill_title(&mut self) {
        if !self.title().is_empty() {
            return;
        }
        let fallback = match (host(self.slot(Slot::Url)), self.slot(Slot::Username)) {
            (Some(host), _) => host.to_owned(),
            (None, user) if !user.is_empty() => user.to_owned(),
            (None, _) => FALLBACK_TITLE.to_owned(),
        };
        let fallback = Zeroizing::new(fallback);
        if let Some(title) = self.slots.get_mut(Slot::Title.index()) {
            title.extend_from_slice(fallback.as_bytes());
        }
    }
}

/// One importable record. The document wipes itself on drop.
pub struct Item {
    /// The record document.
    pub doc: Box<Document>,
    /// What it was in the source.
    pub kind: ItemKind,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl TryFrom<Draft> for Item {
    type Error = SkipReason;

    fn try_from(mut draft: Draft) -> Result<Self, SkipReason> {
        if draft.too_large {
            return Err(SkipReason::TooLarge);
        }
        if draft.too_many {
            return Err(SkipReason::TooManyFields);
        }
        if draft.is_empty() {
            return Err(SkipReason::Empty);
        }
        draft.fill_title();
        let mut doc = Document::new();
        for slot in [
            Slot::Title,
            Slot::Url,
            Slot::Username,
            Slot::Email,
            Slot::Password,
            Slot::Notes,
            Slot::Totp,
        ] {
            if let Some(value) = draft.slots.get(slot.index()).filter(|v| !v.is_empty()) {
                doc.set_data(slot.tag(), slot.vtype(), value);
            }
        }
        let tags = Zeroizing::new(draft.tags.join(", "));
        let meta = [
            (CUSTOM_TAGS, tags.as_str()),
            (CUSTOM_FAVORITE, if draft.favorite { "1" } else { "" }),
            (CUSTOM_KIND, draft.kind.marker().unwrap_or_default()),
        ];
        let customs = draft
            .custom
            .iter()
            .map(|custom| (&*custom.name, custom.vtype, custom.data.as_slice()))
            .chain(
                meta.iter()
                    .filter(|(_, value)| !value.is_empty())
                    .map(|(name, value)| (*name, ValueType::Text, value.as_bytes())),
            );
        for ((name, vtype, data), tag) in customs.zip(TAG_CUSTOM_MIN..) {
            if data.len() > MAX_FIELD {
                return Err(SkipReason::TooLarge);
            }
            doc.set_custom(tag, name, vtype, data)
                .map_err(|_| SkipReason::TooLarge)?;
        }
        let encoded = doc.encode().map_err(|_| SkipReason::TooLarge)?;
        drop(Zeroizing::new(encoded));
        Ok(Self {
            doc: Box::new(doc),
            kind: draft.kind,
        })
    }
}

/// Passwords and TOTP keep their exact bytes; other fields are trimmed.
fn trim_value(slot: Slot, value: &str) -> &str {
    match slot {
        Slot::Password => value,
        Slot::Title | Slot::Url | Slot::Username | Slot::Email | Slot::Notes | Slot::Totp => {
            value.trim()
        }
    }
}

/// A custom name that fits the record limit and does not shadow a field
/// this application reads (`tags`, `favorite`, `kind`).
fn custom_name(name: &str) -> Box<str> {
    let name = name.trim();
    let name = if name.is_empty() { "field" } else { name };
    let reserved = [CUSTOM_TAGS, CUSTOM_FAVORITE, CUSTOM_KIND].contains(&name);
    let suffix = if reserved { " (imported)" } else { "" };
    let budget = MAX_CUSTOM_NAME - suffix.len();
    let cut = name
        .char_indices()
        .map(|(at, ch)| at + ch.len_utf8())
        .take_while(|end| *end <= budget)
        .last()
        .unwrap_or(0);
    let mut out = String::with_capacity(cut + suffix.len());
    out.push_str(name.get(..cut).unwrap_or_default());
    out.push_str(suffix);
    out.into_boxed_str()
}

/// Host part of a URL-like string, without scheme, credentials, port, or path.
fn host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{custom_name, host};

    #[test]
    fn host_strips_scheme_credentials_and_port() {
        assert_eq!(
            host("https://user:pw@www.example.com:8443/a?b"),
            Some("example.com")
        );
        assert_eq!(host("example.org/login"), Some("example.org"));
        assert_eq!(host(""), None);
    }

    #[test]
    fn custom_names_are_bounded_and_never_reserved() {
        assert_eq!(&*custom_name("tags"), "tags (imported)");
        assert_eq!(&*custom_name("  "), "field");
        let long = "é".repeat(100);
        assert!(custom_name(&long).len() <= record::MAX_CUSTOM_NAME);
    }
}
