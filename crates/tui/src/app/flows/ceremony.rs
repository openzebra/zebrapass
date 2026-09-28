//! Showing the new phrase one row at a time, then proving it was saved.

use std::time::{Duration, Instant};

use seed::SeedPhrase;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::secure::generator::{random_below, EntropyError};
use crate::secure::phrase_input::word_index;
use crate::secure::reveal::{RevealGuard, RevealKey};

/// Rows of the phrase grid.
pub const ROWS: usize = 5;
/// Words per row.
pub const PER_ROW: usize = 5;
/// Words in a new phrase.
pub const WORDS: usize = 24;
/// Cards on the verify step.
pub const CARDS: usize = 3;
/// Choices per card.
pub const CHOICES: usize = 4;

/// The words of `phrase`, borrowed.
pub fn words(phrase: &SeedPhrase) -> impl Iterator<Item = &str> {
    phrase.phrase_normalized().split(' ')
}

/// Focusable parts of the phrase step, in Tab order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CeremonyFocus {
    /// The phrase grid: arrows pick a row, Space reveals it.
    #[default]
    Grid,
    /// The "I wrote it down" checkbox: Space ticks it.
    Written,
    /// The continue button.
    Continue,
}

impl CeremonyFocus {
    const fn shift(self, forward: bool) -> Self {
        match (self, forward) {
            (Self::Grid, true) | (Self::Continue, false) => Self::Written,
            (Self::Written, true) | (Self::Grid, false) => Self::Continue,
            (Self::Continue, true) | (Self::Written, false) => Self::Grid,
        }
    }
}

/// Phrase display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ceremony {
    /// Focused part.
    pub focus: CeremonyFocus,
    /// Row that a reveal shows.
    pub row: usize,
    /// "I wrote it down" ticked.
    pub written: bool,
    /// Reveal of one row.
    pub reveal: RevealGuard,
    /// The reveal is a true hold (released on key up).
    pub holding: bool,
}

impl Ceremony {
    /// Whether row `row` shows plaintext.
    #[must_use]
    pub fn row_shown(&self, row: usize) -> bool {
        self.reveal
            .is_shown(RevealKey(u32::try_from(row).unwrap_or(u32::MAX)))
    }

    /// Handle an action; `true` means the step is done.
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> bool {
        match action {
            Action::NextField | Action::PrevField => {
                self.focus = self.focus.shift(action == Action::NextField);
                if self.reveal.hide() {
                    ctx.redraw();
                }
            }
            Action::Reveal if self.focus == CeremonyFocus::Written => {
                self.written = !self.written;
            }
            Action::Reveal if self.focus == CeremonyFocus::Continue => {}
            Action::Reveal => {
                let key = RevealKey(u32::try_from(self.row).unwrap_or(0));
                if ctx.caps.key_release {
                    self.reveal.show(key, ctx.now);
                    self.holding = true;
                } else if self.reveal.toggle(key, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Up | Action::Down => {
                self.focus = CeremonyFocus::Grid;
                self.row = if action == Action::Up {
                    self.row.saturating_sub(1)
                } else {
                    (self.row + 1).min(ROWS - 1)
                };
                if self.reveal.any() {
                    self.reveal
                        .show(RevealKey(u32::try_from(self.row).unwrap_or(0)), ctx.now);
                    ctx.redraw();
                }
            }
            Action::ToggleWritten => self.written = !self.written,
            Action::Confirm => {
                if self.reveal.hide() {
                    ctx.redraw();
                }
                if !self.written {
                    self.focus = CeremonyFocus::Written;
                }
                return self.written;
            }
            _ => {}
        }
        false
    }

    /// Space released: end a true hold.
    pub const fn release(&mut self, ctx: &mut Ctx) {
        if self.holding {
            self.holding = false;
            if self.reveal.hide() {
                ctx.redraw();
            }
        }
    }
}

/// Outcome of a verify keystroke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyEvent {
    /// Keep going.
    Stay,
    /// All three picks were right.
    Passed,
    /// At least one pick was wrong (which one is not said).
    Failed,
}

/// Three cards: pick word #n among four BIP39 words.
pub struct Verify {
    positions: [usize; CARDS],
    options: [[u16; CHOICES]; CARDS],
    picks: [usize; CARDS],
    /// Focused card.
    pub card: usize,
    /// Cards confirmed so far.
    pub confirmed: usize,
    /// Shake animation end.
    pub shake_until: Option<Instant>,
    /// The last check failed.
    pub failed: bool,
}

impl std::fmt::Debug for Verify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verify([REDACTED])")
    }
}

impl Drop for Verify {
    fn drop(&mut self) {
        self.positions.zeroize();
        self.options.iter_mut().for_each(Zeroize::zeroize);
        self.picks.zeroize();
    }
}

impl Verify {
    /// Draw three distinct positions and three decoys each from the OS RNG.
    ///
    /// # Errors
    ///
    /// [`EntropyError`] when the OS RNG fails.
    pub fn new(phrase: &SeedPhrase) -> Result<Self, EntropyError> {
        let mut positions = [0usize; CARDS];
        let mut filled = 0;
        while filled < CARDS {
            let candidate = random_below(WORDS)?;
            if !positions
                .get(..filled)
                .is_some_and(|taken| taken.contains(&candidate))
            {
                if let Some(slot) = positions.get_mut(filled) {
                    *slot = candidate;
                }
                filled += 1;
            }
        }
        positions.sort_unstable();
        let mut options = [[0u16; CHOICES]; CARDS];
        for (card, position) in positions.iter().enumerate() {
            let word = words(phrase).nth(*position).unwrap_or("");
            let correct = word_index(word.as_bytes()).ok_or(EntropyError)?;
            let row = options.get_mut(card).ok_or(EntropyError)?;
            fill_choices(row, correct)?;
        }
        Ok(Self {
            positions,
            options,
            picks: [0; CARDS],
            card: 0,
            confirmed: 0,
            shake_until: None,
            failed: false,
        })
    }

    /// 1-based word number asked on `card`.
    #[must_use]
    pub fn position(&self, card: usize) -> usize {
        self.positions.get(card).map_or(0, |position| position + 1)
    }

    /// The four choices on `card`.
    #[must_use]
    pub fn choices(&self, card: usize) -> [&'static str; CHOICES] {
        let row = self.options.get(card).copied().unwrap_or_default();
        row.map(|index| seed::EN.get(usize::from(index)).copied().unwrap_or(""))
    }

    /// Selected choice on `card`.
    #[must_use]
    pub fn pick(&self, card: usize) -> usize {
        self.picks.get(card).copied().unwrap_or(0)
    }

    /// Handle an action against `phrase`.
    pub fn on_action(&mut self, action: Action, phrase: &SeedPhrase, now: Instant) -> VerifyEvent {
        match action {
            Action::Up | Action::Down => {
                if let Some(pick) = self.picks.get_mut(self.card) {
                    *pick = if action == Action::Up {
                        pick.saturating_sub(1)
                    } else {
                        (*pick + 1).min(CHOICES - 1)
                    };
                }
            }
            Action::Left => {
                self.card = self
                    .card
                    .saturating_sub(1)
                    .max(self.confirmed.min(CARDS - 1));
            }
            Action::Right => self.card = (self.card + 1).min(self.confirmed.min(CARDS - 1)),
            Action::Confirm => {
                self.confirmed = (self.confirmed + 1).min(CARDS);
                self.card = self.confirmed.min(CARDS - 1);
                if self.confirmed == CARDS {
                    return self.check(phrase, now);
                }
            }
            _ => {}
        }
        VerifyEvent::Stay
    }

    /// Compare every pick in constant time; no early exit, no per-card result.
    fn check(&mut self, phrase: &SeedPhrase, now: Instant) -> VerifyEvent {
        let mut all = Choice::from(1);
        for card in 0..CARDS {
            let chosen = self
                .choices(card)
                .get(self.pick(card))
                .copied()
                .unwrap_or("");
            let expected = words(phrase)
                .nth(self.position(card).saturating_sub(1))
                .unwrap_or("");
            all &= chosen.as_bytes().ct_eq(expected.as_bytes());
        }
        if bool::from(all) {
            VerifyEvent::Passed
        } else {
            self.failed = true;
            self.shake_until = Some(now + Duration::from_millis(360));
            self.confirmed = 0;
            self.card = 0;
            self.picks = [0; CARDS];
            VerifyEvent::Failed
        }
    }

    /// Horizontal shake offset for this frame.
    #[must_use]
    pub fn shake(&self, now: Instant) -> i16 {
        self.shake_until
            .filter(|until| *until > now)
            .map_or(0, |until| {
                let phase = until.saturating_duration_since(now).as_millis() / 120;
                if phase % 2 == 0 {
                    2
                } else {
                    -2
                }
            })
    }
}

/// Put `correct` and three distinct random decoys into `row`, shuffled.
fn fill_choices(row: &mut [u16; CHOICES], correct: usize) -> Result<(), EntropyError> {
    let correct = u16::try_from(correct).map_err(|_| EntropyError)?;
    let mut chosen = [correct; CHOICES];
    let mut filled = 1;
    while filled < CHOICES {
        let candidate = u16::try_from(random_below(seed::EN.len())?).map_err(|_| EntropyError)?;
        if !chosen
            .get(..filled)
            .is_some_and(|taken| taken.contains(&candidate))
        {
            if let Some(slot) = chosen.get_mut(filled) {
                *slot = candidate;
            }
            filled += 1;
        }
    }
    let slot = random_below(CHOICES)?;
    chosen.swap(0, slot);
    *row = chosen;
    chosen.zeroize();
    Ok(())
}
