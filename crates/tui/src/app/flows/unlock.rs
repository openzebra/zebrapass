//! Unlock screen: pick a factor the wrap directory offers, submit it to the
//! worker, and show one uniform error with exponential backoff.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use seed::SeedPhrase;
use session::WrapDirectory;

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::editing::{edit_secret, printable};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::secure::phrase_input::{secret_string, PhraseInput};
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::VaultRef;
use crate::vault::error::UnlockError;
use crate::vault::factors::{presence, views, FactorKind, Presence};
use crate::vault::open::{read_directory, Credential};

/// Longest password accepted.
pub const MAX_PASSWORD: usize = 1024;
/// Longest BIP39 passphrase accepted.
pub const MAX_PASSPHRASE: usize = 256;
/// Longest wait between attempts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Which factor the user presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Human password.
    Password,
    /// Recovery phrase.
    Recovery,
    /// Development chip.
    Chip,
}

/// Focus inside recovery mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryField {
    /// The words.
    Phrase,
    /// The optional 25th word.
    Passphrase,
}

/// Unlock screen state.
#[derive(Debug)]
pub struct UnlockState {
    /// Known vaults.
    pub vaults: Vec<VaultRef>,
    /// Selected vault.
    pub current: usize,
    /// Public directory of the selected vault.
    pub directory: Result<WrapDirectory, UnlockError>,
    /// Presented factor.
    pub mode: Mode,
    /// Password being typed.
    pub password: SecretInput,
    /// Recovery words.
    pub phrase: PhraseInput,
    /// Recovery passphrase.
    pub passphrase: SecretInput,
    /// Focus in recovery mode.
    pub recovery_field: RecoveryField,
    /// Failed attempts this visit.
    pub attempts: u32,
    /// No new attempt before this.
    pub retry_at: Option<Instant>,
    /// Last outcome.
    pub error: Option<UnlockError>,
    /// Vault picker cursor, while open.
    pub picker: Option<usize>,
    /// Reveal of the password field.
    pub reveal: RevealGuard,
}

/// Reveal key of the password field.
pub const REVEAL_PASSWORD: RevealKey = RevealKey(1);

impl UnlockState {
    /// Unlock screen for `vaults[current]`.
    #[must_use]
    pub fn new(vaults: Vec<VaultRef>, current: usize, ctx: &Ctx) -> Self {
        let mut state = Self {
            vaults,
            current,
            directory: Err(UnlockError::Io),
            mode: Mode::Password,
            password: SecretInput::new(MAX_PASSWORD),
            phrase: PhraseInput::default(),
            passphrase: SecretInput::new(MAX_PASSPHRASE),
            recovery_field: RecoveryField::Phrase,
            attempts: 0,
            retry_at: None,
            error: None,
            picker: None,
            reveal: RevealGuard::default(),
        };
        state.select(current, ctx);
        state
    }

    /// The selected vault.
    #[must_use]
    pub fn vault(&self) -> Option<&VaultRef> {
        self.vaults.get(self.current)
    }

    /// Which factor kinds the selected vault has.
    #[must_use]
    pub fn presence(&self, ctx: &Ctx) -> Presence {
        self.directory
            .as_ref()
            .map(|directory| presence(directory, &ctx.chips))
            .unwrap_or_default()
    }

    /// Modes this vault offers, in Tab order.
    #[must_use]
    pub fn modes(&self, ctx: &Ctx) -> Vec<Mode> {
        let found = self.presence(ctx);
        [
            (Mode::Password, found.password),
            (Mode::Chip, found.owned_chips > 0),
            (Mode::Recovery, found.recovery),
        ]
        .iter()
        .filter(|(_, present)| *present)
        .map(|(mode, _)| *mode)
        .collect()
    }

    fn select(&mut self, index: usize, ctx: &Ctx) {
        self.current = index.min(self.vaults.len().saturating_sub(1));
        self.directory = self.vault().map_or(Err(UnlockError::Io), |vault| {
            read_directory(&vault.paths.vault_file)
        });
        self.password.clear();
        self.phrase.clear();
        self.passphrase.clear();
        self.error = None;
        self.attempts = 0;
        self.retry_at = None;
        let found = self.presence(ctx);
        self.mode = self.modes(ctx).first().copied().unwrap_or(Mode::Password);
        if found.hw_keys > 0 && !found.password && found.owned_chips == 0 && !found.recovery {
            self.error = Some(UnlockError::NeedsHwKey);
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if let Some(cursor) = self.picker {
            return self.on_picker(event, cursor, ctx);
        }
        let recovery_words =
            self.mode == Mode::Recovery && self.recovery_field == RecoveryField::Phrase;
        if recovery_words {
            if let Some(ch) = printable(event) {
                if ch == ' ' {
                    if !self.phrase.space() {
                        ctx.toast(Tone::Warn, "Keep typing: that is not a whole word yet.");
                    }
                } else {
                    self.phrase.type_char(ch);
                }
                return Nav::Stay;
            }
            if event.code == KeyCode::Backspace {
                self.phrase.backspace();
                return Nav::Stay;
            }
        }
        if let Some(action) = resolve(Scope::Unlock, event) {
            return self.on_action(action, ctx);
        }
        let input = match (self.mode, self.recovery_field) {
            (Mode::Recovery, RecoveryField::Passphrase) => &mut self.passphrase,
            (Mode::Recovery, RecoveryField::Phrase) | (Mode::Chip, _) => return Nav::Stay,
            (Mode::Password, _) => &mut self.password,
        };
        edit_secret(input, event);
        Nav::Stay
    }

    fn on_picker(&mut self, event: &KeyEvent, cursor: usize, ctx: &Ctx) -> Nav {
        match event.code {
            KeyCode::Up => self.picker = Some(cursor.saturating_sub(1)),
            KeyCode::Down => {
                self.picker = Some((cursor + 1).min(self.vaults.len().saturating_sub(1)));
            }
            KeyCode::Enter => {
                self.picker = None;
                self.select(cursor, ctx);
            }
            KeyCode::Esc => self.picker = None,
            _ => {}
        }
        Nav::Stay
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        match (self.mode, self.recovery_field) {
            (Mode::Password, _) => {
                self.password.insert_str(text);
            }
            (Mode::Recovery, RecoveryField::Passphrase) => {
                self.passphrase.insert_str(text);
            }
            (Mode::Recovery, RecoveryField::Phrase) => {
                for ch in text.chars() {
                    if ch.is_whitespace() {
                        self.phrase.space();
                    } else {
                        self.phrase.type_char(ch);
                    }
                }
                self.phrase.space();
            }
            (Mode::Chip, _) => {}
        }
    }

    /// Handle an action.
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Confirm => self.submit(ctx),
            Action::SwitchFactor => {
                let modes = self.modes(ctx);
                let at = modes
                    .iter()
                    .position(|mode| *mode == self.mode)
                    .unwrap_or(0);
                self.mode = modes
                    .get((at + 1) % modes.len().max(1))
                    .copied()
                    .unwrap_or(Mode::Password);
                self.reveal_off(ctx);
            }
            Action::UseRecovery => {
                self.mode = Mode::Recovery;
                self.recovery_field = RecoveryField::Phrase;
                self.reveal_off(ctx);
            }
            Action::SwitchVault if self.vaults.len() > 1 => self.picker = Some(self.current),
            Action::SwitchVault => ctx.toast(Tone::Info, "Only one vault on this device."),
            Action::Up | Action::Down if self.mode == Mode::Recovery => {
                self.recovery_field = match self.recovery_field {
                    RecoveryField::Phrase => RecoveryField::Passphrase,
                    RecoveryField::Passphrase => RecoveryField::Phrase,
                };
            }
            Action::RevealField if self.mode == Mode::Password => {
                if self.reveal.toggle(REVEAL_PASSWORD, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Back => {
                self.password.clear();
                self.phrase.clear();
                self.passphrase.clear();
                self.reveal_off(ctx);
            }
            Action::Quit => return Nav::Quit,
            _ => {}
        }
        Nav::Stay
    }

    const fn reveal_off(&mut self, ctx: &mut Ctx) {
        if self.reveal.hide() {
            ctx.redraw();
        }
    }

    fn submit(&mut self, ctx: &mut Ctx) {
        if ctx.busy() {
            return;
        }
        if let Some(at) = self.retry_at.filter(|at| *at > ctx.now) {
            let wait = at.saturating_duration_since(ctx.now).as_secs() + 1;
            ctx.toast(Tone::Info, format!("Wait {wait}s before the next attempt."));
            return;
        }
        let Some(paths) = self.vault().map(|vault| vault.paths.clone()) else {
            return;
        };
        let cost = match &self.directory {
            Ok(directory) => views(directory, &ctx.chips)
                .iter()
                .find(|view| view.kind == FactorKind::Password)
                .and_then(|view| view.cost),
            Err(error) => {
                self.error = Some(*error);
                return;
            }
        };
        let credential = match self.mode {
            Mode::Password => {
                if self.password.is_empty() {
                    return;
                }
                Credential::Password(self.password.take())
            }
            Mode::Recovery => match self.parse_phrase() {
                Ok(phrase) => Credential::Phrase(Box::new(phrase)),
                Err(message) => {
                    ctx.toast(Tone::Warn, message);
                    return;
                }
            },
            #[cfg(feature = "dev-chip")]
            Mode::Chip => Credential::Chip,
            #[cfg(not(feature = "dev-chip"))]
            Mode::Chip => return,
        };
        self.reveal_off(ctx);
        let cost = if self.mode == Mode::Password {
            cost
        } else {
            None
        };
        ctx.start(Job::Unlock(paths, credential), Task::Unlock(cost));
    }

    fn parse_phrase(&mut self) -> Result<SeedPhrase, &'static str> {
        if !self.phrase.plausible() {
            return Err("Enter all 12, 15, 18, 21, or 24 words.");
        }
        let passphrase =
            secret_string(self.passphrase.expose()).ok_or("The passphrase is not valid text.")?;
        let parsed = SeedPhrase::parse(&self.phrase.to_secret(), &passphrase)
            .map_err(|_| "That phrase is not valid. Check the words and their order.")?;
        self.phrase.clear();
        self.passphrase.clear();
        Ok(parsed)
    }

    /// Record a failed attempt: uniform message, exponential backoff.
    pub fn failed(&mut self, error: UnlockError, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        self.retry_at = Some(now + backoff(self.attempts));
        self.error = Some(error);
    }
}

/// `min(2^(n-1), 30)` seconds before attempt `n + 1`.
#[must_use]
pub fn backoff(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << exponent).min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::backoff;

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(5), Duration::from_secs(16));
        assert_eq!(backoff(9), Duration::from_secs(30));
    }
}
