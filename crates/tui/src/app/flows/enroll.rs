//! "How will you unlock on this device?" — shared by create and restore.

use crossterm::event::KeyEvent;
use subtle::ConstantTimeEq;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::edit_secret;
use crate::app::flows::unlock::MAX_PASSWORD;
use crate::app::keymap::{resolve, Scope};
use crate::secure::generator::{generate, GenMode, GenSpec};
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::secure::strength::{estimate, Strength, StrengthLabel};
use crate::ui::widgets::toast::Tone;
use crate::vault::chip::Chips;
use crate::vault::create::Enrollment;

/// Factor cards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollFactor {
    /// Argon2id password.
    Password,
    /// This device's keys in the keyring.
    Device,
    /// Secure chip.
    Chip,
    /// Hardware key (not built yet).
    HwKey,
}

impl EnrollFactor {
    /// Cards in display order.
    pub const ALL: [Self; 4] = [Self::Password, Self::Device, Self::Chip, Self::HwKey];
}

/// Focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollFocus {
    /// The factor cards.
    Cards,
    /// New password.
    Password,
    /// Repeat.
    Repeat,
}

/// Reveal key of the password field.
pub const REVEAL_NEW: RevealKey = RevealKey(10);
/// Reveal key of the repeat field.
pub const REVEAL_REPEAT: RevealKey = RevealKey(11);

/// Enroll step state.
#[derive(Debug)]
pub struct EnrollState {
    /// Chosen card.
    pub factor: EnrollFactor,
    /// Focus.
    pub focus: EnrollFocus,
    /// New password.
    pub password: SecretInput,
    /// Repeat.
    pub repeat: SecretInput,
    /// Reveal state.
    pub reveal: RevealGuard,
    /// Validation message.
    pub message: Option<&'static str>,
    /// The file already has a password factor (restore).
    pub existing_password: bool,
}

/// What the step decided.
#[derive(Debug)]
pub enum EnrollEvent {
    /// Keep editing.
    Stay,
    /// Go back a step.
    Back,
    /// Enroll this.
    Done(Enrollment),
}

impl EnrollState {
    /// Fresh step; `existing_password` allows keeping the file's password.
    #[must_use]
    pub fn new(existing_password: bool) -> Self {
        Self {
            factor: EnrollFactor::Password,
            focus: EnrollFocus::Password,
            password: SecretInput::new(MAX_PASSWORD),
            repeat: SecretInput::new(MAX_PASSWORD),
            reveal: RevealGuard::default(),
            message: None,
            existing_password,
        }
    }

    /// Strength of the new password.
    #[must_use]
    pub fn strength(&self) -> Strength {
        estimate(self.password.expose())
    }

    /// Whether both entries match, compared in constant time; `None` until
    /// the repeat has input.
    #[must_use]
    pub fn matches(&self) -> Option<bool> {
        (!self.repeat.is_empty())
            .then(|| bool::from(self.password.expose().ct_eq(self.repeat.expose())))
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> EnrollEvent {
        if let Some(action) = resolve(Scope::Enroll, event) {
            if !(matches!(action, Action::Left | Action::Right) && self.focus != EnrollFocus::Cards)
            {
                return self.on_action(action, ctx);
            }
        }
        let input = match self.focus {
            EnrollFocus::Cards => return EnrollEvent::Stay,
            EnrollFocus::Password => &mut self.password,
            EnrollFocus::Repeat => &mut self.repeat,
        };
        edit_secret(input, event);
        self.message = None;
        EnrollEvent::Stay
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        match self.focus {
            EnrollFocus::Cards => {}
            EnrollFocus::Password => {
                self.password.insert_str(text);
            }
            EnrollFocus::Repeat => {
                self.repeat.insert_str(text);
            }
        }
    }

    fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> EnrollEvent {
        match action {
            Action::Left | Action::Right => self.cycle_factor(action == Action::Right),
            Action::NextField | Action::PrevField => {
                let forward = action == Action::NextField;
                if self.focus == EnrollFocus::Cards {
                    self.cycle_factor(forward);
                } else {
                    self.focus = match (self.focus, forward) {
                        (EnrollFocus::Password, true) => EnrollFocus::Repeat,
                        (EnrollFocus::Repeat, true) | (EnrollFocus::Password, false) => {
                            EnrollFocus::Cards
                        }
                        (EnrollFocus::Repeat | EnrollFocus::Cards, _) => EnrollFocus::Password,
                    };
                    if self.reveal.hide() {
                        ctx.redraw();
                    }
                }
            }
            Action::Up | Action::Down => {
                let down = action == Action::Down;
                let next = match (self.focus, down) {
                    (EnrollFocus::Cards, true) | (EnrollFocus::Repeat, false) => {
                        Some(EnrollFocus::Password)
                    }
                    (EnrollFocus::Password, true) => Some(EnrollFocus::Repeat),
                    (EnrollFocus::Password | EnrollFocus::Cards, false) => Some(EnrollFocus::Cards),
                    (EnrollFocus::Repeat, true) => None,
                };
                if let Some(focus) = next {
                    self.focus = focus;
                    if self.reveal.hide() {
                        ctx.redraw();
                    }
                }
            }
            Action::GeneratePassphrase => self.generate(ctx),
            Action::RevealField => {
                let key = if self.focus == EnrollFocus::Repeat {
                    REVEAL_REPEAT
                } else {
                    REVEAL_NEW
                };
                if self.reveal.toggle(key, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Confirm => {
                match self.focus {
                    // Enter on the password card just descends into the input.
                    EnrollFocus::Cards if self.factor == EnrollFactor::Password => {
                        self.focus = EnrollFocus::Password;
                    }
                    EnrollFocus::Password => {
                        self.focus = EnrollFocus::Repeat;
                        if self.reveal.hide() {
                            ctx.redraw();
                        }
                    }
                    EnrollFocus::Cards | EnrollFocus::Repeat => return self.confirm(),
                }
            }
            Action::Back => return EnrollEvent::Back,
            _ => {}
        }
        EnrollEvent::Stay
    }

    fn cycle_factor(&mut self, forward: bool) {
        let at = EnrollFactor::ALL
            .iter()
            .position(|factor| *factor == self.factor)
            .unwrap_or(0);
        let len = EnrollFactor::ALL.len();
        let next = if forward { at + 1 } else { at + len - 1 } % len;
        self.factor = EnrollFactor::ALL
            .get(next)
            .copied()
            .unwrap_or(EnrollFactor::Password);
        self.message = None;
    }

    fn generate(&mut self, ctx: &mut Ctx) {
        let spec = GenSpec::for_mode(GenMode::Passphrase);
        match generate(&spec) {
            Ok(value) => {
                self.password.set(&value);
                self.repeat.set(&value);
                self.factor = EnrollFactor::Password;
                self.focus = EnrollFocus::Password;
                self.reveal.show(REVEAL_NEW, ctx.now);
                ctx.toast(
                    Tone::Info,
                    format!(
                        "Generated a 6-word passphrase ({:.0} bits). Learn it before it hides.",
                        spec.entropy_bits()
                    ),
                );
            }
            Err(_) => ctx.toast(Tone::Danger, "The system random source failed."),
        }
    }

    fn confirm(&mut self) -> EnrollEvent {
        match self.factor {
            // TODO(hw-key): FIDO2 PRF enrollment plugs in here; until then it fails closed.
            EnrollFactor::HwKey => self.message = Some("Hardware keys are not available yet."),
            EnrollFactor::Device => return EnrollEvent::Done(Enrollment::Device),
            EnrollFactor::Chip if !Chips::available() => {
                self.message =
                    Some("No secure chip backend in this build (Secure Enclave is not built yet).");
            }
            EnrollFactor::Chip => return chip_enrollment(),
            EnrollFactor::Password => {
                if self.existing_password && self.password.is_empty() && self.repeat.is_empty() {
                    return EnrollEvent::Done(Enrollment::KeepExisting);
                }
                if self.password.is_empty() {
                    self.message = Some("Choose a password.");
                } else if self.matches() != Some(true) {
                    self.message = Some("The two entries do not match.");
                } else if self.strength().label == StrengthLabel::VeryWeak {
                    self.message = Some("Too weak. Try a few random words (Ctrl-G).");
                } else {
                    self.repeat.clear();
                    return EnrollEvent::Done(Enrollment::Password(self.password.take()));
                }
            }
        }
        EnrollEvent::Stay
    }
}

#[cfg(feature = "dev-chip")]
const fn chip_enrollment() -> EnrollEvent {
    EnrollEvent::Done(Enrollment::Chip)
}

#[cfg(not(feature = "dev-chip"))]
const fn chip_enrollment() -> EnrollEvent {
    EnrollEvent::Stay
}
