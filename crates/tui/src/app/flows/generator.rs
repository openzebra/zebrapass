//! Password generator overlay. The preview is shown unmasked because the user
//! is choosing it; the buffer is zeroizing and a reroll replaces it.

use crossterm::event::KeyEvent;
use zeroize::Zeroizing;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::keymap::{resolve, Scope};
use crate::secure::generator::{generate, CharSets, GenSpec};
use crate::ui::widgets::toast::Tone;

/// What the generator decided.
#[derive(Debug)]
pub enum GenEvent {
    /// Keep open.
    Stay,
    /// Close without using.
    Close,
    /// Put this value into the target field.
    Use(Zeroizing<Vec<u8>>),
}

/// Generator state.
pub struct GeneratorState {
    /// Request.
    pub spec: GenSpec,
    /// Current value.
    pub value: Zeroizing<Vec<u8>>,
    /// Editor field to fill, when opened from the editor.
    pub target: Option<usize>,
}

impl std::fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratorState")
            .field("spec", &self.spec)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl GeneratorState {
    /// Open with a fresh value.
    #[must_use]
    pub fn new(target: Option<usize>, ctx: &mut Ctx) -> Self {
        let mut state = Self {
            spec: GenSpec::default(),
            value: Zeroizing::new(Vec::new()),
            target,
        };
        state.reroll(ctx);
        state
    }

    fn reroll(&mut self, ctx: &mut Ctx) {
        match generate(&self.spec) {
            Ok(value) => self.value = value,
            Err(_) => ctx.toast(
                Tone::Danger,
                "The system random source failed. Nothing was generated.",
            ),
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> GenEvent {
        let Some(action) = resolve(Scope::Generator, event) else {
            return GenEvent::Stay;
        };
        let toggle = |sets: CharSets, bit| sets.toggle(bit);
        match action {
            Action::Left => self.spec.nudge(-1),
            Action::Right => self.spec.nudge(1),
            Action::NextMode => self.spec.next_mode(),
            Action::ToggleLower => self.spec.sets = toggle(self.spec.sets, CharSets::LOWER),
            Action::ToggleUpper => self.spec.sets = toggle(self.spec.sets, CharSets::UPPER),
            Action::ToggleDigits => self.spec.sets = toggle(self.spec.sets, CharSets::DIGITS),
            Action::ToggleSymbols => self.spec.sets = toggle(self.spec.sets, CharSets::SYMBOLS),
            Action::ToggleLookalike => {
                self.spec.sets = toggle(self.spec.sets, CharSets::NO_LOOKALIKE);
            }
            Action::Reroll => {}
            Action::CopyGenerated => {
                ctx.copy(&self.value, "generated password");
                return GenEvent::Stay;
            }
            Action::Confirm => {
                if self.target.is_some() {
                    return GenEvent::Use(std::mem::replace(
                        &mut self.value,
                        Zeroizing::new(Vec::new()),
                    ));
                }
                ctx.copy(&self.value, "generated password");
                return GenEvent::Close;
            }
            Action::Back => return GenEvent::Close,
            _ => return GenEvent::Stay,
        }
        self.reroll(ctx);
        GenEvent::Stay
    }
}
