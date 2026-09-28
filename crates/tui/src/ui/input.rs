//! Plain (non-secret) text input: names, search queries, URLs, titles.
//!
//! Values that may still be sensitive (titles, usernames) are wiped on drop.

use zeroize::Zeroize;

/// A single-line text field.
pub struct TextInput {
    value: String,
    cursor: usize,
    max: usize,
}

impl std::fmt::Debug for TextInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextInput")
            .field("len", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl Drop for TextInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl TextInput {
    /// An empty field that holds at most `max` bytes.
    #[must_use]
    pub const fn new(max: usize) -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            max,
        }
    }

    /// A field pre-filled with `value` (truncated at a char boundary to `max`).
    #[must_use]
    pub fn with_value(value: &str, max: usize) -> Self {
        let mut input = Self::new(max);
        input.insert_str(value);
        input
    }

    /// Current text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Byte offset of the cursor.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the field is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Byte limit.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Change the byte limit; never below the current length.
    pub fn set_max(&mut self, max: usize) {
        self.max = max.max(self.value.len());
    }

    /// Insert one character; `false` when it would pass the limit or is a
    /// control character.
    pub fn insert_char(&mut self, ch: char) -> bool {
        if ch.is_control() || self.value.len() + ch.len_utf8() > self.max {
            return false;
        }
        self.value.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
        true
    }

    /// Insert pasted text up to the first line break; returns characters kept.
    pub fn insert_str(&mut self, text: &str) -> usize {
        text.chars()
            .take_while(|ch| *ch != '\n' && *ch != '\r')
            .take_while(|ch| self.insert_char(*ch))
            .count()
    }

    /// Delete before the cursor.
    pub fn backspace(&mut self) {
        if let Some((index, _)) = self
            .value
            .get(..self.cursor)
            .and_then(|head| head.char_indices().next_back())
        {
            self.value.remove(index);
            self.cursor = index;
        }
    }

    /// Delete after the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
        }
    }

    /// Cursor one character left.
    pub fn left(&mut self) {
        if let Some((index, _)) = self
            .value
            .get(..self.cursor)
            .and_then(|head| head.char_indices().next_back())
        {
            self.cursor = index;
        }
    }

    /// Cursor one character right.
    pub fn right(&mut self) {
        if let Some(ch) = self
            .value
            .get(self.cursor..)
            .and_then(|tail| tail.chars().next())
        {
            self.cursor += ch.len_utf8();
        }
    }

    /// Cursor to the start.
    pub const fn home(&mut self) {
        self.cursor = 0;
    }

    /// Cursor to the end.
    pub fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// Empty the field.
    pub fn clear(&mut self) {
        self.value.zeroize();
        self.cursor = 0;
    }

    /// Replace the text.
    pub fn set(&mut self, value: &str) {
        self.clear();
        self.insert_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::TextInput;

    #[test]
    fn edits_respect_limit_and_boundaries() {
        let mut input = TextInput::new(6);
        assert_eq!(input.insert_str("héllo world"), 5);
        assert_eq!(input.value(), "héllo");
        input.left();
        input.backspace();
        assert_eq!(input.value(), "hélo");
        input.home();
        input.delete();
        assert_eq!(input.value(), "élo");
        assert!(!input.insert_char('\u{7}'));
    }
}
