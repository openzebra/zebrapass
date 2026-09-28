//! Shared keystroke handling for inputs and hold-to-confirm.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::secure::secret_input::SecretInput;
use crate::ui::input::TextInput;

/// What an input did with a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    /// The key changed the input or its cursor.
    Consumed,
    /// The key was input, but a limit refused it.
    Refused,
    /// Not an editing key.
    Ignored,
}

/// The character of a plain printable key press.
#[must_use]
pub fn printable(event: &KeyEvent) -> Option<char> {
    let modified = event
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    match event.code {
        KeyCode::Char(ch) if !modified && !ch.is_control() => Some(ch),
        _ => None,
    }
}

/// Apply an editing key to a text input.
pub fn edit_text(input: &mut TextInput, event: &KeyEvent) -> Edit {
    if let Some(ch) = printable(event) {
        return if input.insert_char(ch) {
            Edit::Consumed
        } else {
            Edit::Refused
        };
    }
    match event.code {
        KeyCode::Backspace => input.backspace(),
        KeyCode::Delete => input.delete(),
        KeyCode::Left => input.left(),
        KeyCode::Right => input.right(),
        KeyCode::Home => input.home(),
        KeyCode::End => input.end(),
        _ => return Edit::Ignored,
    }
    Edit::Consumed
}

/// Apply an editing key to a secret input.
pub fn edit_secret(input: &mut SecretInput, event: &KeyEvent) -> Edit {
    if let Some(ch) = printable(event) {
        return if input.insert_char(ch) {
            Edit::Consumed
        } else {
            Edit::Refused
        };
    }
    match event.code {
        KeyCode::Backspace => input.backspace(),
        KeyCode::Delete => input.delete(),
        KeyCode::Left => input.left(),
        KeyCode::Right => input.right(),
        KeyCode::Home => input.home(),
        KeyCode::End => input.end(),
        _ => return Edit::Ignored,
    }
    Edit::Consumed
}

/// How long a dangerous action must be held.
pub const HOLD_TIME: Duration = Duration::from_millis(1500);

/// Hold-to-confirm. With key-release events it is a true hold: releasing
/// early cancels. Without them the press starts the fill and a second press
/// after it fills confirms; any other key cancels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hold {
    started: Option<Instant>,
    filled: bool,
}

impl Hold {
    /// Confirm key pressed (or auto-repeated). Returns `true` to fire.
    pub fn press(&mut self, now: Instant, releases: bool) -> bool {
        match (self.started, releases) {
            (None, _) => {
                self.started = Some(now);
                self.filled = false;
                false
            }
            (Some(_), false) if self.filled => {
                *self = Self::default();
                true
            }
            (Some(_), _) => false,
        }
    }

    /// Confirm key released: an unfinished hold is cancelled.
    pub fn release(&mut self, releases: bool) {
        if releases {
            *self = Self::default();
        }
    }

    /// Advance. Returns `true` when a true hold completes.
    pub fn tick(&mut self, now: Instant, releases: bool) -> bool {
        let Some(started) = self.started else {
            return false;
        };
        if now.saturating_duration_since(started) < HOLD_TIME {
            return false;
        }
        if releases {
            *self = Self::default();
            true
        } else {
            self.filled = true;
            false
        }
    }

    /// Cancel.
    pub fn cancel(&mut self) {
        *self = Self::default();
    }

    /// Fill fraction `0.0..=1.0`.
    #[must_use]
    pub fn progress(&self, now: Instant) -> f64 {
        self.started.map_or(0.0, |started| {
            (now.saturating_duration_since(started).as_secs_f64() / HOLD_TIME.as_secs_f64())
                .min(1.0)
        })
    }

    /// Waiting for the second press (no release events).
    #[must_use]
    pub const fn awaiting_second_press(&self) -> bool {
        self.filled
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Hold, HOLD_TIME};

    #[test]
    fn true_hold_fires_after_the_hold_time_and_release_cancels() {
        let start = Instant::now();
        let mut hold = Hold::default();
        assert!(!hold.press(start, true));
        assert!(!hold.tick(start + Duration::from_millis(500), true));
        hold.release(true);
        assert!(!hold.tick(start + HOLD_TIME, true));
        assert!(!hold.press(start, true));
        assert!(hold.tick(start + HOLD_TIME, true));
    }

    #[test]
    fn fallback_needs_a_second_press_after_the_fill() {
        let start = Instant::now();
        let mut hold = Hold::default();
        assert!(!hold.press(start, false));
        assert!(!hold.press(start + Duration::from_millis(100), false));
        assert!(!hold.tick(start + HOLD_TIME, false));
        assert!(hold.awaiting_second_press());
        assert!(hold.press(start + HOLD_TIME, false));
    }
}
