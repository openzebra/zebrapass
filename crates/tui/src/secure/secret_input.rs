//! Editable secret buffer: typed passwords, notes, and pasted secrets.
//!
//! The bytes live in a `Zeroizing<Vec<u8>>`. Growth is manual: a new
//! zeroizing buffer is allocated, the bytes are copied, and the old one is
//! wiped when it drops, so a reallocation never leaves a stray copy in freed
//! memory. Input past `max` is refused before any buffer grows.

use std::fmt;

use zeroize::Zeroizing;

/// First allocation for a non-empty buffer.
const INITIAL_CAPACITY: usize = 32;

/// Positions of the typing wave: one per mask cell.
pub const PHASES: u8 = 12;

/// A UTF-8 secret being typed. No `Clone`, no `Display`, redacted `Debug`.
pub struct SecretInput {
    buf: Zeroizing<Vec<u8>>,
    cursor: usize,
    max: usize,
    phase: u8,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

impl SecretInput {
    /// An empty input that holds at most `max` bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            cursor: 0,
            max,
            phase: 0,
        }
    }

    /// Where the typing wave of the mask sits. It jumps to a random other
    /// place on every edit, so it shows each keystroke without counting
    /// them: its position says nothing about the length.
    #[must_use]
    pub const fn phase(&self) -> u8 {
        self.phase
    }

    /// Move the typing wave. Cosmetic: when the OS RNG fails the wave just
    /// stays where it is.
    fn stir(&mut self) {
        let mut byte = [0u8; 1];
        if getrandom::fill(&mut byte).is_ok() {
            let hop = 1 + byte[0] % (PHASES - 1);
            self.phase = (self.phase + hop) % PHASES;
        }
    }

    /// Byte limit.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Lower the byte limit; never below the current length.
    pub fn set_max(&mut self, max: usize) {
        self.max = max.max(self.buf.len());
    }

    /// Current length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Allocated capacity, for tests that pin the growth policy.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.buf
    }

    /// Insert one character at the cursor. `false` when it would pass `max`.
    pub fn insert_char(&mut self, ch: char) -> bool {
        let mut utf8 = [0u8; 4];
        let encoded = ch.encode_utf8(&mut utf8).as_bytes();
        let inserted = self.insert_bytes(encoded);
        zeroize::Zeroize::zeroize(&mut utf8);
        if inserted {
            self.stir();
        }
        inserted
    }

    /// Insert a pasted string at the cursor. Returns how many characters
    /// fitted; the rest is refused.
    pub fn insert_str(&mut self, text: &str) -> usize {
        text.chars()
            .take_while(|ch| *ch != '\n' && *ch != '\r')
            .take_while(|ch| self.insert_char(*ch))
            .count()
    }

    fn insert_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(needed) = self.buf.len().checked_add(bytes.len()) else {
            return false;
        };
        if needed > self.max {
            return false;
        }
        self.ensure_capacity(needed);
        let tail = self.buf.split_off(self.cursor);
        let tail = Zeroizing::new(tail);
        self.buf.extend_from_slice(bytes);
        self.buf.extend_from_slice(&tail);
        self.cursor += bytes.len();
        true
    }

    /// Grow into a fresh zeroizing buffer so the old bytes are wiped, never
    /// left behind by `Vec`'s own reallocation.
    fn ensure_capacity(&mut self, needed: usize) {
        // `split_off` in `insert_bytes` allocates the tail separately, so the
        // main buffer needs room for the whole result.
        if needed <= self.buf.capacity() {
            return;
        }
        let target = needed
            .max(self.buf.capacity().saturating_mul(2))
            .max(INITIAL_CAPACITY)
            .min(self.max.max(needed));
        let mut grown = Zeroizing::new(Vec::with_capacity(target));
        grown.extend_from_slice(&self.buf);
        self.buf = grown;
    }

    /// Delete the character before the cursor.
    pub fn backspace(&mut self) {
        let start = self.prev_boundary();
        if start < self.cursor {
            self.buf.drain(start..self.cursor);
            self.cursor = start;
            self.stir();
        }
    }

    /// Delete the character after the cursor.
    pub fn delete(&mut self) {
        let end = self.next_boundary();
        if end > self.cursor {
            self.buf.drain(self.cursor..end);
            self.stir();
        }
    }

    /// Move the cursor one character left.
    pub fn left(&mut self) {
        self.cursor = self.prev_boundary();
    }

    /// Move the cursor one character right.
    pub fn right(&mut self) {
        self.cursor = self.next_boundary();
    }

    /// Cursor to the start.
    pub const fn home(&mut self) {
        self.cursor = 0;
    }

    /// Cursor to the end.
    pub fn end(&mut self) {
        self.cursor = self.buf.len();
    }

    /// Wipe the contents; the allocation is kept (and was zeroed).
    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.buf);
        self.cursor = 0;
    }

    /// Replace the contents with `bytes` (for generated values). Refused and
    /// left unchanged when `bytes` is longer than `max`.
    pub fn set(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.max {
            return false;
        }
        self.clear();
        self.ensure_capacity(bytes.len());
        self.buf.extend_from_slice(bytes);
        self.cursor = self.buf.len();
        true
    }

    /// Move the contents out, leaving the input empty.
    pub fn take(&mut self) -> Zeroizing<Vec<u8>> {
        self.cursor = 0;
        std::mem::replace(&mut self.buf, Zeroizing::new(Vec::new()))
    }

    fn prev_boundary(&self) -> usize {
        let mut index = self.cursor;
        while index > 0 {
            index -= 1;
            if self.is_boundary(index) {
                return index;
            }
        }
        0
    }

    fn next_boundary(&self) -> usize {
        let mut index = self.cursor;
        while index < self.buf.len() {
            index += 1;
            if self.is_boundary(index) {
                return index;
            }
        }
        self.buf.len()
    }

    fn is_boundary(&self, index: usize) -> bool {
        // UTF-8 continuation bytes are `0b10xx_xxxx`.
        self.buf.get(index).is_none_or(|byte| byte & 0xC0 != 0x80)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{SecretInput, PHASES};

    #[test]
    fn edits_at_the_cursor_on_char_boundaries() {
        let mut input = SecretInput::new(64);
        for ch in "pässwörd".chars() {
            assert!(input.insert_char(ch));
        }
        input.left();
        input.backspace();
        assert_eq!(input.expose(), "pässwöd".as_bytes());
        input.home();
        input.delete();
        assert_eq!(input.expose(), "ässwöd".as_bytes());
        input.end();
        assert!(input.insert_char('!'));
        assert_eq!(input.expose(), "ässwöd!".as_bytes());
    }

    #[test]
    fn refuses_input_past_the_limit_without_growing() {
        let mut input = SecretInput::new(4);
        assert_eq!(input.insert_str("abcdef"), 4);
        assert_eq!(input.expose(), b"abcd");
        assert!(input.capacity() <= 4);
        assert!(!input.insert_char('x'));
        assert!(input.capacity() <= 4);
        assert!(!input.set(b"12345"));
        assert_eq!(input.expose(), b"abcd");
    }

    #[test]
    fn debug_is_redacted() {
        let mut input = SecretInput::new(16);
        input.insert_str("hunter2");
        assert_eq!(format!("{input:?}"), "SecretInput([REDACTED])");
    }

    #[test]
    fn take_empties_the_input() {
        let mut input = SecretInput::new(16);
        input.insert_str("abc");
        let taken = input.take();
        assert_eq!(taken.as_slice(), b"abc");
        assert!(input.is_empty());
    }

    #[test]
    fn every_edit_moves_the_typing_wave() {
        let mut input = SecretInput::new(64);
        for ch in "correct horse".chars() {
            let before = input.phase();
            assert!(input.insert_char(ch));
            assert_ne!(input.phase(), before, "typing moves the wave");
            assert!(input.phase() < PHASES);
        }
        let before = input.phase();
        input.backspace();
        assert_ne!(input.phase(), before, "backspace moves the wave");
        let before = input.phase();
        input.left();
        assert_eq!(input.phase(), before, "cursor moves are not edits");
    }

    #[test]
    fn the_wave_does_not_count_characters() {
        let phases: std::collections::BTreeSet<u8> = (0..64)
            .map(|_| {
                let mut input = SecretInput::new(16);
                input.insert_str("abc");
                input.phase()
            })
            .collect();
        assert!(
            phases.len() > 1,
            "the same length lands on different phases"
        );
    }
}
