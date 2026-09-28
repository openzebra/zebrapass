//! BIP39 phrase entry with prefix autocomplete.
//!
//! Finished words are stored as wordlist indexes, never as strings; only the
//! word being typed is held as letters. Both buffers are zeroizing. Checksum
//! validation is not done here: [`seed::SeedPhrase::parse`] is the one
//! validator, called on submit.

use std::ops::Range;

use secrecy::SecretString;
use zeroize::Zeroizing;

/// Longest phrase accepted.
pub const MAX_WORDS: usize = 24;
/// Shortest phrase `SeedPhrase::parse` accepts.
pub const MIN_WORDS: usize = 12;
/// Longest BIP39 English word.
pub const MAX_WORD_LEN: usize = 8;

/// What a keystroke did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typed {
    /// The letter was added to the current word.
    Letter,
    /// The letter completed a unique prefix and the word was committed.
    Committed,
    /// The letter continued the word that was just auto-committed.
    Swallowed,
    /// No wordlist word starts with that; nothing changed.
    Rejected,
}

/// Phrase being typed.
pub struct PhraseInput {
    words: Zeroizing<Vec<u16>>,
    current: Zeroizing<Vec<u8>>,
    /// After an auto-commit, the rest of that word as the user keeps typing
    /// it: `(word index, letters already consumed)`.
    tail: Option<(u16, usize)>,
}

impl std::fmt::Debug for PhraseInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PhraseInput([REDACTED])")
    }
}

impl Default for PhraseInput {
    fn default() -> Self {
        Self {
            words: Zeroizing::new(Vec::with_capacity(MAX_WORDS)),
            current: Zeroizing::new(Vec::with_capacity(MAX_WORD_LEN)),
            tail: None,
        }
    }
}

impl PhraseInput {
    /// Number of finished words.
    #[must_use]
    pub fn count(&self) -> usize {
        self.words.len()
    }

    /// Letters of the word being typed.
    #[must_use]
    pub fn current(&self) -> &[u8] {
        &self.current
    }

    /// Whether the phrase has a length `SeedPhrase::parse` may accept.
    #[must_use]
    pub fn plausible(&self) -> bool {
        self.current.is_empty()
            && (MIN_WORDS..=MAX_WORDS).contains(&self.words.len())
            && self.words.len() % 3 == 0
    }

    /// Type one character.
    pub fn type_char(&mut self, ch: char) -> Typed {
        let lower = ch.to_ascii_lowercase();
        if !lower.is_ascii_lowercase() {
            return Typed::Rejected;
        }
        let Ok(byte) = u8::try_from(lower) else {
            return Typed::Rejected;
        };
        if self.swallow(byte) {
            return Typed::Swallowed;
        }
        if self.words.len() >= MAX_WORDS || self.current.len() >= MAX_WORD_LEN {
            return Typed::Rejected;
        }
        self.current.push(byte);
        let matches = prefix_range(&self.current);
        match matches.len() {
            0 => {
                self.current.pop();
                Typed::Rejected
            }
            1 => {
                let consumed = self.current.len();
                self.commit(matches.start);
                self.tail = u16::try_from(matches.start)
                    .ok()
                    .map(|word| (word, consumed));
                Typed::Committed
            }
            _ => Typed::Letter,
        }
    }

    fn swallow(&mut self, byte: u8) -> bool {
        let Some((word, consumed)) = self.tail else {
            return false;
        };
        let next = seed::EN
            .get(usize::from(word))
            .and_then(|text| text.as_bytes().get(consumed))
            .copied();
        if next == Some(byte) {
            self.tail = Some((word, consumed + 1));
            true
        } else {
            self.tail = None;
            false
        }
    }

    /// Finish the current word (Space): an exact or unique match commits.
    /// Returns `false` when the letters are ambiguous and not a word.
    pub fn space(&mut self) -> bool {
        self.tail = None;
        if self.current.is_empty() {
            return true;
        }
        let matches = prefix_range(&self.current);
        let exact = matches.clone().find(|index| {
            seed::EN
                .get(*index)
                .is_some_and(|word| word.as_bytes() == self.current.as_slice())
        });
        match (exact, matches.len()) {
            (Some(index), _) => {
                self.commit(index);
                true
            }
            (None, 1) => {
                self.commit(matches.start);
                true
            }
            _ => false,
        }
    }

    /// Accept the first suggestion (Tab).
    pub fn accept_suggestion(&mut self) -> bool {
        let matches = prefix_range(&self.current);
        if self.current.is_empty() || matches.is_empty() {
            return false;
        }
        self.commit(matches.start);
        true
    }

    /// Delete a letter, or reopen the last word for editing.
    pub fn backspace(&mut self) {
        self.tail = None;
        if self.current.pop().is_some() {
            return;
        }
        if let Some(word) = self
            .words
            .pop()
            .and_then(|index| seed::EN.get(usize::from(index)))
        {
            self.current.extend_from_slice(word.as_bytes());
        }
    }

    /// Up to `limit` wordlist words that start with the current letters.
    #[must_use]
    pub fn suggestions(&self, limit: usize) -> &'static [&'static str] {
        if self.current.is_empty() {
            return &[];
        }
        let range = prefix_range(&self.current);
        let end = range.end.min(range.start + limit);
        seed::EN.get(range.start..end).unwrap_or(&[])
    }

    /// Finished word `index`, for a deliberate reveal.
    #[must_use]
    pub fn word(&self, index: usize) -> Option<&'static str> {
        self.words
            .get(index)
            .and_then(|word| seed::EN.get(usize::from(*word)).copied())
    }

    /// The phrase as the single-spaced string `SeedPhrase::parse` takes.
    #[must_use]
    pub fn to_secret(&self) -> SecretString {
        let words: Vec<&str> = (0..self.words.len())
            .filter_map(|index| self.word(index))
            .collect();
        let len =
            words.iter().map(|word| word.len()).sum::<usize>() + words.len().saturating_sub(1);
        let mut text = String::with_capacity(len);
        for (position, word) in words.iter().enumerate() {
            if position > 0 {
                text.push(' ');
            }
            text.push_str(word);
        }
        SecretString::new(text.into_boxed_str())
    }

    /// Forget everything typed.
    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.words);
        zeroize::Zeroize::zeroize(&mut *self.current);
        self.tail = None;
    }

    fn commit(&mut self, index: usize) {
        if let Ok(word) = u16::try_from(index) {
            if self.words.len() < MAX_WORDS {
                self.words.push(word);
            }
        }
        zeroize::Zeroize::zeroize(&mut *self.current);
    }
}

/// Typed UTF-8 bytes as a `SecretString` (the BIP39 passphrase). The copy
/// is allocated at its exact size, so boxing it does not reallocate.
#[must_use]
pub fn secret_string(bytes: &[u8]) -> Option<SecretString> {
    let text = std::str::from_utf8(bytes).ok()?;
    Some(SecretString::new(text.to_owned().into_boxed_str()))
}

/// Wordlist indexes whose word starts with `prefix`. The list is sorted.
#[must_use]
pub fn prefix_range(prefix: &[u8]) -> Range<usize> {
    let start = seed::EN.partition_point(|word| word.as_bytes() < prefix);
    let len = seed::EN
        .get(start..)
        .unwrap_or(&[])
        .iter()
        .take_while(|word| word.as_bytes().starts_with(prefix))
        .count();
    start..start + len
}

/// Index of `word` in the wordlist.
#[must_use]
pub fn word_index(word: &[u8]) -> Option<usize> {
    seed::EN
        .binary_search_by(|probe| probe.as_bytes().cmp(word))
        .ok()
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{prefix_range, PhraseInput, Typed};

    fn type_word(input: &mut PhraseInput, word: &str) {
        for ch in word.chars() {
            input.type_char(ch);
        }
        input.space();
    }

    #[test]
    fn unique_prefix_commits_and_swallows_the_rest() {
        let mut input = PhraseInput::default();
        assert_eq!(input.type_char('z'), Typed::Letter);
        assert_eq!(input.type_char('e'), Typed::Letter);
        assert_eq!(input.type_char('b'), Typed::Committed);
        assert_eq!(input.type_char('r'), Typed::Swallowed);
        assert_eq!(input.type_char('a'), Typed::Swallowed);
        assert!(input.space());
        assert_eq!(input.count(), 1);
        assert_eq!(input.word(0), Some("zebra"));
    }

    #[test]
    fn short_words_commit_on_space() {
        let mut input = PhraseInput::default();
        type_word(&mut input, "act");
        type_word(&mut input, "abandon");
        assert_eq!(input.to_secret().expose_secret(), "act abandon");
        assert_eq!(input.type_char('7'), Typed::Rejected);
        assert_eq!(input.type_char('x'), Typed::Rejected);
        assert_eq!(input.type_char('y'), Typed::Letter);
        assert_eq!(input.type_char('q'), Typed::Rejected);
    }

    #[test]
    fn backspace_reopens_the_last_word() {
        let mut input = PhraseInput::default();
        type_word(&mut input, "abandon");
        input.backspace();
        assert_eq!(input.count(), 0);
        assert_eq!(input.current(), b"abandon");
    }

    #[test]
    fn prefixes_are_found_in_the_sorted_list() {
        assert_eq!(prefix_range(b"zoo").len(), 1);
        assert!(prefix_range(b"ab").len() > 3);
        assert!(prefix_range(b"qq").is_empty());
    }
}
