//! Restore from phrase: type the words, point at the vault file (a backup or
//! a copy from another device), then enroll this device's own factor.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use seed::SeedPhrase;
use session::KdfProfile;

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::editing::{edit_secret, edit_text, printable, Edit};
use crate::app::flows::enroll::{EnrollEvent, EnrollState};
use crate::app::flows::unlock::MAX_PASSPHRASE;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::secure::phrase_input::{secret_string, PhraseInput, Typed};
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::ui::input::TextInput;
use crate::vault::create::{Enrollment, RestoreVault};
use crate::vault::discover::discover;
use crate::vault::factors::presence;
use crate::vault::limits::{MAX_PATH_INPUT, MAX_VAULT_NAME};
use crate::vault::open::read_directory;

/// Reveal key of the last finished word.
pub const REVEAL_LAST: RevealKey = RevealKey(20);

/// Restore step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreStep {
    /// Words and file.
    Phrase,
    /// This device's factor.
    Enroll,
}

/// Focus on the phrase step, in Tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreField {
    /// The words.
    Phrase,
    /// Vault file path.
    Source,
    /// Display name.
    Name,
    /// Optional 25th word.
    Passphrase,
}

impl RestoreField {
    const ORDER: [Self; 4] = [Self::Phrase, Self::Source, Self::Name, Self::Passphrase];

    fn shift(self, forward: bool) -> Self {
        let at = Self::ORDER
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let next = if forward {
            at + 1
        } else {
            at + Self::ORDER.len() - 1
        };
        Self::ORDER
            .get(next % Self::ORDER.len())
            .copied()
            .unwrap_or(Self::Phrase)
    }
}

/// Restore state.
#[derive(Debug)]
pub struct RestoreState {
    /// Step.
    pub step: RestoreStep,
    /// Words.
    pub phrase: PhraseInput,
    /// Optional passphrase.
    pub passphrase: SecretInput,
    /// Vault file path.
    pub source: TextInput,
    /// Display name.
    pub name: TextInput,
    /// Focus.
    pub field: RestoreField,
    /// The word being typed is hidden.
    pub hide_current: bool,
    /// Reveal of the last finished word.
    pub reveal: RevealGuard,
    /// The validated phrase, between the two steps.
    pub parsed: Option<Box<SeedPhrase>>,
    /// Factor step.
    pub enroll: EnrollState,
    /// Unlock factors in the file at `source`; `None` when it is not a vault.
    pub source_factors: Option<usize>,
    /// Last problem.
    pub error: Option<&'static str>,
}

impl RestoreState {
    /// Restore screen, pre-filled with `source` or the first vault on disk.
    #[must_use]
    pub fn new(source: Option<PathBuf>, ctx: &Ctx) -> Self {
        let guess = source.or_else(|| ctx.vault_file.clone()).or_else(|| {
            discover(&ctx.base)
                .into_iter()
                .next()
                .map(|vault| vault.paths.vault_file)
        });
        let path = guess
            .as_deref()
            .map(Path::to_string_lossy)
            .unwrap_or_default();
        let mut state = Self {
            step: RestoreStep::Phrase,
            phrase: PhraseInput::default(),
            passphrase: SecretInput::new(MAX_PASSPHRASE),
            source: TextInput::with_value(&path, MAX_PATH_INPUT),
            name: TextInput::with_value("Personal", MAX_VAULT_NAME),
            field: RestoreField::Phrase,
            hide_current: false,
            reveal: RevealGuard::default(),
            parsed: None,
            enroll: EnrollState::new(false),
            source_factors: None,
            error: None,
        };
        state.check_source();
        state
    }

    /// Re-read the wrap directory at `source`. Unauthenticated: this only
    /// tells the user whether the path points at a vault.
    fn check_source(&mut self) {
        self.source_factors = read_directory(Path::new(self.source.value().trim()))
            .ok()
            .map(|directory| directory.factors.len());
    }

    /// Keymap scope.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self.step {
            RestoreStep::Phrase => Scope::Restore,
            RestoreStep::Enroll => Scope::Enroll,
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if self.step == RestoreStep::Enroll {
            return match self.enroll.on_key(event, ctx) {
                EnrollEvent::Stay => Nav::Stay,
                EnrollEvent::Back => {
                    self.parsed = None;
                    self.step = RestoreStep::Phrase;
                    Nav::Stay
                }
                EnrollEvent::Done(factor) => {
                    self.finish(factor, ctx);
                    Nav::Stay
                }
            };
        }
        if self.field == RestoreField::Phrase {
            if let Some(ch) = printable(event).filter(|ch| *ch != ' ') {
                if self.phrase.type_char(ch) == Typed::Rejected {
                    self.error = Some("No BIP39 word starts like that.");
                } else {
                    self.error = None;
                }
                return Nav::Stay;
            }
            if event.code == KeyCode::Backspace {
                self.phrase.backspace();
                return Nav::Stay;
            }
        }
        let text_field = matches!(
            self.field,
            RestoreField::Source | RestoreField::Name | RestoreField::Passphrase
        );
        match resolve(Scope::Restore, event) {
            // Space types into text fields; Tab still moves between them.
            Some(Action::NextWord) if text_field => {}
            Some(action) => return self.on_action(action, ctx),
            None => {}
        }
        match self.field {
            RestoreField::Phrase => {}
            RestoreField::Passphrase => {
                edit_secret(&mut self.passphrase, event);
            }
            RestoreField::Source => {
                if edit_text(&mut self.source, event) == Edit::Consumed {
                    self.check_source();
                }
            }
            RestoreField::Name => {
                edit_text(&mut self.name, event);
            }
        }
        Nav::Stay
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        if self.step == RestoreStep::Enroll {
            self.enroll.on_paste(text);
            return;
        }
        match self.field {
            RestoreField::Phrase => {
                for ch in text.chars() {
                    if ch.is_whitespace() {
                        self.phrase.space();
                    } else {
                        self.phrase.type_char(ch);
                    }
                }
                self.phrase.space();
            }
            RestoreField::Passphrase => {
                self.passphrase.insert_str(text);
            }
            RestoreField::Source => {
                self.source.insert_str(text);
                self.check_source();
            }
            RestoreField::Name => {
                self.name.insert_str(text);
            }
        }
    }

    fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::NextWord if self.field == RestoreField::Phrase => {
                if !self.phrase.space() {
                    self.error = Some("Ambiguous: keep typing or press Tab to accept.");
                }
            }
            // Tab completes the word being typed; with nothing to complete it
            // moves on, like Tab everywhere else.
            Action::AcceptSuggestion => {
                let accepted =
                    self.field == RestoreField::Phrase && self.phrase.accept_suggestion();
                if !accepted {
                    self.field = self.field.shift(true);
                }
            }
            Action::RevealWord => {
                if self.phrase.count() > 0 && self.reveal.toggle(REVEAL_LAST, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::HideWord => {
                self.hide_current = !self.hide_current;
                ctx.redraw();
            }
            Action::NextField | Action::PrevField => {
                self.field = self.field.shift(action == Action::NextField);
            }
            Action::Confirm => self.enter_enroll(ctx),
            Action::Back => return Nav::To(crate::app::flows::gate::initial_screen(ctx)),
            _ => {}
        }
        Nav::Stay
    }

    fn enter_enroll(&mut self, ctx: &mut Ctx) {
        if !self.phrase.plausible() {
            self.error = Some("Enter all 12, 15, 18, 21, or 24 words.");
            return;
        }
        let Some(passphrase) = secret_string(self.passphrase.expose()) else {
            self.error = Some("The passphrase is not valid text.");
            return;
        };
        let Ok(parsed) = SeedPhrase::parse(&self.phrase.to_secret(), &passphrase) else {
            self.error = Some("That phrase is not valid. Check the words and their order.");
            return;
        };
        if self.name.value().trim().is_empty() {
            self.error = Some("Give the vault a name.");
            return;
        }
        let Ok(directory) = read_directory(Path::new(self.source.value().trim())) else {
            self.error = Some("No ZebraPass vault file at that path.");
            return;
        };
        let existing = presence(&directory, &ctx.chips).password;
        self.parsed = Some(Box::new(parsed));
        self.phrase.clear();
        self.passphrase.clear();
        self.error = None;
        self.enroll = EnrollState::new(existing);
        self.step = RestoreStep::Enroll;
        if self.reveal.hide() {
            ctx.redraw();
        }
    }

    fn finish(&mut self, factor: Enrollment, ctx: &mut Ctx) {
        let Some(phrase) = self.parsed.take() else {
            return;
        };
        let request = RestoreVault {
            phrase,
            name: self.name.value().trim().to_owned(),
            base: ctx.base.clone(),
            source: PathBuf::from(self.source.value().trim()),
            profile: KdfProfile::Balanced,
            factor,
        };
        ctx.start(Job::Restore(Box::new(request)), Task::Restore);
    }

    /// The restore job failed with the uniform error.
    pub fn failed(&mut self, message: &'static str) {
        self.step = RestoreStep::Phrase;
        self.error = Some(message);
        self.enroll = EnrollState::new(false);
    }
}
