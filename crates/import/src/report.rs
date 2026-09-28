//! What an import did. Holds counts and titles only, never a secret.

use zeroize::Zeroize;

use crate::item::{Draft, Item, ItemKind};
use crate::limits::MAX_ITEMS;

/// Why an item was left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// No field carried a value.
    Empty,
    /// In the source's trash.
    Trashed,
    /// A value or the whole record is over the record limits.
    TooLarge,
    /// More custom fields than one record may hold.
    TooManyFields,
    /// The source row or entry did not parse.
    Malformed,
}

impl SkipReason {
    /// Short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Trashed => "in trash",
            Self::TooLarge => "too large",
            Self::TooManyFields => "too many fields",
            Self::Malformed => "unreadable",
        }
    }
}

/// One skipped item.
#[derive(Debug)]
pub struct Skip {
    /// Position in the source, from 0.
    pub index: usize,
    /// Why.
    pub reason: SkipReason,
    /// Its title (a text field), possibly empty.
    pub title: Box<str>,
}

impl Drop for Skip {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}

/// Counts and skips of one import.
#[derive(Debug, Default)]
pub struct Report {
    /// Items left out, in source order.
    pub skipped: Vec<Skip>,
    /// Imported items per [`ItemKind::index`].
    pub kinds: [u32; ItemKind::COUNT],
    /// Attachments that could not be imported.
    pub attachments: u32,
    /// Passkeys that could not be imported.
    pub passkeys: u32,
    /// Items whose password history was dropped.
    pub history: u32,
    /// Linked custom fields that were dropped.
    pub linked_fields: u32,
}

impl Report {
    /// Map `draft` into `items`, or record why it was skipped.
    ///
    /// # Errors
    ///
    /// `too many items` once `items` holds [`MAX_ITEMS`].
    pub fn admit(
        &mut self,
        items: &mut Vec<Item>,
        index: usize,
        draft: Draft,
    ) -> anyhow::Result<()> {
        if items.len() >= MAX_ITEMS {
            anyhow::bail!("too many items");
        }
        let title: Box<str> = draft.title().into();
        match Item::try_from(draft) {
            Ok(item) => {
                if let Some(count) = self.kinds.get_mut(item.kind.index()) {
                    *count = count.saturating_add(1);
                }
                items.push(item);
            }
            Err(reason) => self.skip(index, reason, title),
        }
        Ok(())
    }

    /// Record a skipped item.
    pub fn skip(&mut self, index: usize, reason: SkipReason, title: Box<str>) {
        self.skipped.push(Skip {
            index,
            reason,
            title,
        });
    }

    /// Items imported.
    #[must_use]
    pub fn imported(&self) -> u32 {
        self.kinds
            .iter()
            .fold(0, |sum, count| sum.saturating_add(*count))
    }
}
