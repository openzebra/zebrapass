//! Restore from phrase, with an optional vault file or device address.
//!
//! The file is only a bootstrap shortcut; the network always carries the data
//! after unlock. Then this device's own factor is enrolled.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use p2p_net::{BeaconConfig, BeaconListener};
use seed::SeedPhrase;
use session::KdfProfile;

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::editing::{edit_secret, edit_text, printable, Edit};
use crate::app::flows::enroll::{EnrollEvent, EnrollState};
pub use crate::app::flows::restore_field::RestoreField;
use crate::app::flows::unlock::MAX_PASSPHRASE;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::secure::phrase_input::{secret_string, PhraseInput, Typed};
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::create::{Enrollment, RestoreSource, RestoreVault};
use crate::vault::factors::presence;
use crate::vault::limits::{MAX_PATH_INPUT, MAX_VAULT_NAME};
use crate::vault::open::read_directory;

/// Longest address typed in: a bracketed IPv6 address with a port.
const MAX_ADDRESS_INPUT: usize = 64;

/// Devices found on the network that are kept as candidates.
pub const MAX_FOUND: usize = 16;

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

/// Restore state.
#[derive(Debug)]
pub struct RestoreState {
    /// Step.
    pub step: RestoreStep,
    /// Words.
    pub phrase: PhraseInput,
    /// Optional passphrase.
    pub passphrase: SecretInput,
    /// Optional vault file path; empty means sync over the network.
    pub source: TextInput,
    /// Optional address of another device of the account.
    pub address: TextInput,
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
    /// Where the vault comes from, resolved when the factor step opens.
    resolved: Option<RestoreSource>,
    /// Factor step.
    pub enroll: EnrollState,
    /// Unlock factors in the file at `source`; `None` when it is not a vault.
    pub source_factors: Option<usize>,
    /// Last problem.
    pub error: Option<&'static str>,
    /// Addresses of other devices of the account found on this network, by
    /// their beacons. Only candidates: nothing is dialed until the person
    /// continues.
    pub found: Vec<Box<str>>,
    /// Listens for those beacons while the phrase in the form is valid.
    listener: Option<BeaconListener>,
    /// Where beacons are heard; `None` when the command line did not ask.
    beacon: Option<BeaconConfig>,
    /// The candidate last put in the address field.
    picked: usize,
}

impl RestoreState {
    /// Restore screen. The file field starts empty, so the network is the
    /// default path; only an explicit `source` pre-fills it.
    #[must_use]
    pub fn new(source: Option<PathBuf>, ctx: &Ctx) -> Self {
        let path = source.map_or_else(String::new, |path| path.to_string_lossy().into_owned());
        let mut state = Self {
            step: RestoreStep::Phrase,
            phrase: PhraseInput::default(),
            passphrase: SecretInput::new(MAX_PASSPHRASE),
            source: TextInput::with_value(&path, MAX_PATH_INPUT),
            address: TextInput::with_value("", MAX_ADDRESS_INPUT),
            name: TextInput::with_value("Personal", MAX_VAULT_NAME),
            field: RestoreField::Phrase,
            hide_current: false,
            reveal: RevealGuard::default(),
            parsed: None,
            resolved: None,
            enroll: EnrollState::new(false),
            source_factors: None,
            error: None,
            found: Vec::new(),
            listener: None,
            beacon: ctx.beacon,
            picked: 0,
        };
        state.check_source();
        state
    }

    /// The address typed in, validated as an address this device may dial:
    /// the advertise rules, with loopback allowed because the user chose it.
    ///
    /// # Errors
    ///
    /// A short reason to show as is.
    pub fn peer_address(&self) -> Result<Box<str>, &'static str> {
        local::parse_peer_address(self.address.value(), true)
    }

    /// Keep listening for beacons of the account the phrase in the form
    /// belongs to, while it is a whole, valid phrase; otherwise stop and
    /// forget what was found.
    fn refresh_listener(&mut self) {
        let seed = (self.beacon.is_some() && self.phrase.plausible())
            .then(|| secret_string(self.passphrase.expose()))
            .flatten()
            .and_then(|passphrase| SeedPhrase::parse(&self.phrase.to_secret(), &passphrase).ok());
        let (Some(seed), Some(config)) = (seed, self.beacon) else {
            self.listener = None;
            self.found.clear();
            return;
        };
        if self
            .listener
            .as_ref()
            .is_some_and(|l| l.is_for(seed.seed()))
        {
            return;
        }
        self.found.clear();
        self.picked = 0;
        self.listener = BeaconListener::start(seed.seed(), config).ok();
    }

    /// Run the timers of the screen and take in the beacons heard; `true`
    /// when something needs drawing again.
    pub fn tick(&mut self, now: std::time::Instant, reveal_after: std::time::Duration) -> bool {
        let revealed = self.reveal.tick(now, reveal_after);
        let enrolled = self.enroll.reveal.tick(now, reveal_after);
        let found = self.poll_beacons();
        revealed || enrolled || found
    }

    /// Take in the beacons heard since the last call; `true` when the list
    /// changed. Each address passes the parser the address field uses.
    pub fn poll_beacons(&mut self) -> bool {
        let (Some(listener), Some(config)) = (self.listener.as_ref(), self.beacon) else {
            return false;
        };
        let before = self.found.len();
        for address in listener.poll() {
            let Ok(address) = local::parse_peer_address(&address.to_string(), config.loopback)
            else {
                continue;
            };
            if self.found.len() < MAX_FOUND && !self.found.contains(&address) {
                self.found.push(address);
            }
        }
        self.found.len() != before
    }

    /// Put the next found device in the address field. It is not used until
    /// the person continues.
    fn use_found(&mut self) {
        if self.found.is_empty() {
            return;
        }
        let at = if self.address.value() == self.found.get(self.picked).map_or("", |a| a) {
            (self.picked + 1) % self.found.len()
        } else {
            self.picked.min(self.found.len() - 1)
        };
        if let Some(address) = self.found.get(at) {
            self.address = TextInput::with_value(address, MAX_ADDRESS_INPUT);
            self.picked = at;
            self.error = None;
        }
    }

    /// A file path is typed in and it is not a vault file. An empty field is
    /// a valid state, never a problem.
    #[must_use]
    pub fn file_problem(&self) -> bool {
        !self.source.value().trim().is_empty() && self.source_factors.is_none()
    }

    /// Re-read the wrap directory at `source`. Unauthenticated: this only
    /// tells the user whether the path points at a vault.
    fn check_source(&mut self) {
        let path = self.source.value().trim();
        self.source_factors = (!path.is_empty())
            .then(|| read_directory(Path::new(path)).ok())
            .flatten()
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
        let edits_phrase = self.step == RestoreStep::Phrase
            && matches!(self.field, RestoreField::Phrase | RestoreField::Passphrase);
        let nav = self.handle_key(event, ctx);
        if edits_phrase && self.step == RestoreStep::Phrase {
            self.refresh_listener();
        }
        nav
    }

    fn handle_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if self.step == RestoreStep::Enroll {
            return match self.enroll.on_key(event, ctx) {
                EnrollEvent::Stay => Nav::Stay,
                EnrollEvent::Back => {
                    self.parsed = None;
                    self.field = RestoreField::Phrase;
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
            RestoreField::Source
                | RestoreField::Address
                | RestoreField::Name
                | RestoreField::Passphrase
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
            RestoreField::Address => {
                edit_text(&mut self.address, event);
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
                self.refresh_listener();
            }
            RestoreField::Passphrase => {
                self.passphrase.insert_str(text);
                self.refresh_listener();
            }
            RestoreField::Source => {
                self.source.insert_str(text);
                self.check_source();
            }
            RestoreField::Address => {
                self.address.insert_str(text);
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
            Action::RestoreFound => self.use_found(),
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
        let Some((source, existing)) = self.resolve_source(ctx) else {
            return;
        };
        self.resolved = Some(source);
        self.parsed = Some(Box::new(parsed));
        self.listener = None;
        self.phrase.clear();
        self.passphrase.clear();
        self.error = None;
        self.enroll = EnrollState::new(existing);
        self.step = RestoreStep::Enroll;
        if self.reveal.hide() {
            ctx.redraw();
        }
    }

    /// Where the vault comes from, and whether its file already has a
    /// password factor. A typed file wins over an address; with no file an
    /// address is required, typed or heard from a beacon.
    fn resolve_source(&mut self, ctx: &mut Ctx) -> Option<(RestoreSource, bool)> {
        let path = self.source.value().trim();
        if !path.is_empty() {
            let Ok(directory) = read_directory(Path::new(path)) else {
                self.error = Some("No ZebraPass vault file at that path.");
                return None;
            };
            let existing = presence(&directory, None).password;
            return Some((RestoreSource::File(PathBuf::from(path)), existing));
        }
        let address = if self.address.value().trim().is_empty() {
            let Some(found) = self.found.get(self.picked).or_else(|| self.found.first()) else {
                ctx.toast(
                    Tone::Warn,
                    "Give a device address, or let the beacon find one.",
                );
                return None;
            };
            found.clone()
        } else {
            match self.peer_address() {
                Ok(address) => address,
                Err(problem) => {
                    self.error = Some(problem);
                    return None;
                }
            }
        };
        Some((RestoreSource::Network(address), false))
    }

    fn finish(&mut self, factor: Enrollment, ctx: &mut Ctx) {
        let (Some(phrase), Some(source)) = (self.parsed.take(), self.resolved.take()) else {
            return;
        };
        let request = RestoreVault {
            phrase,
            name: self.name.value().trim().to_owned(),
            base: ctx.base.clone(),
            source,
            profile: KdfProfile::Balanced,
            factor,
        };
        ctx.start(Job::Restore(Box::new(request)), Task::Restore);
    }

    /// The restore job failed with the uniform error.
    pub fn failed(&mut self, message: &'static str) {
        // The phrase was wiped when the job started: type it again.
        self.field = RestoreField::Phrase;
        self.step = RestoreStep::Phrase;
        self.error = Some(message);
        self.enroll = EnrollState::new(false);
    }
}
