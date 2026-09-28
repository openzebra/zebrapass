//! Reveal state for one masked secret at a time.
//!
//! A reveal ends on key release (when the terminal reports releases), on a
//! second press, on a 5 s timeout, or when anything else takes focus. When a
//! reveal ends the app forces a full redraw, so the plaintext cells are
//! overwritten in both of ratatui's buffers and on the terminal.

use std::time::{Duration, Instant};

/// A revealed secret hides itself after this long.
pub const REVEAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Which secret on the current screen is revealed. Screens pick the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevealKey(pub u32);

/// Reveal state machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevealGuard {
    shown: Option<(RevealKey, Instant)>,
}

impl RevealGuard {
    /// Reveal `key` until the timeout.
    pub const fn show(&mut self, key: RevealKey, now: Instant) {
        self.shown = Some((key, now));
    }

    /// Toggle `key`: a second press hides it. Returns `true` when the
    /// toggle hid a secret (the caller forces a full redraw).
    pub fn toggle(&mut self, key: RevealKey, now: Instant) -> bool {
        match self.shown {
            Some((shown, _)) if shown == key => {
                self.shown = None;
                true
            }
            Some(_) => {
                self.shown = Some((key, now));
                true
            }
            None => {
                self.shown = Some((key, now));
                false
            }
        }
    }

    /// Hide whatever is shown. Returns `true` when something was shown.
    pub const fn hide(&mut self) -> bool {
        let was = self.shown.is_some();
        self.shown = None;
        was
    }

    /// Expire an old reveal. Returns `true` when it just hid.
    pub fn tick(&mut self, now: Instant) -> bool {
        match self.shown {
            Some((_, since)) if now.saturating_duration_since(since) >= REVEAL_TIMEOUT => {
                self.shown = None;
                true
            }
            _ => false,
        }
    }

    /// Whether `key` is revealed right now.
    #[must_use]
    pub fn is_shown(&self, key: RevealKey) -> bool {
        self.shown.is_some_and(|(shown, _)| shown == key)
    }

    /// Whether anything is revealed.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.shown.is_some()
    }

    /// Seconds left before auto-hide, for the countdown hint.
    #[must_use]
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.shown
            .map(|(_, since)| REVEAL_TIMEOUT.saturating_sub(now.saturating_duration_since(since)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{RevealGuard, RevealKey, REVEAL_TIMEOUT};

    #[test]
    fn reveal_times_out_and_toggles() {
        let start = Instant::now();
        let mut guard = RevealGuard::default();
        let key = RevealKey(7);
        assert!(!guard.toggle(key, start));
        assert!(guard.is_shown(key));
        assert!(!guard.tick(start + Duration::from_secs(1)));
        assert!(guard.tick(start + REVEAL_TIMEOUT));
        assert!(!guard.is_shown(key));
        guard.show(key, start);
        assert!(guard.toggle(key, start));
        assert!(!guard.any());
    }
}
