//! The import wizard's screen state: which step is shown, what is typed,
//! and where the cursor is. Every import decision lives in the `import`
//! crate; this module only routes keys to it.
//!
//! The same state serves two targets: restoring into a new vault (where
//! the `ZebraPass` phrase is also offered) and importing into the open
//! vault. The caller turns an [`ImportEvent`] into navigation.

use std::path::PathBuf;

use crossterm::event::KeyEvent;
use import::{expand_home, inspect, Credentials, FileHint, Load, Parsed, Review, Source};
use record::{Document, TAG_TOTP};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::create::CreateState;
use crate::app::flows::editing::{edit_secret, edit_text};
use crate::app::flows::gate::initial_screen;
use crate::app::flows::import_mapping::Columns;
use crate::app::flows::restore::RestoreState;
use crate::app::flows::unlock::MAX_PASSWORD;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::{Nav, Screen};
use crate::app::worker::Job;
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::secure::totp::Totp;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::limits::MAX_PATH_INPUT;

/// Rows moved by Page Up / Page Down.
const PAGE: usize = 10;

/// Reveal slot of the database password.
pub const REVEAL_PASSWORD: RevealKey = RevealKey(1);

/// One entry of the first step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// A `ZebraPass` vault file and its recovery phrase.
    Phrase,
    /// Another manager's export.
    From(Source),
}

/// Every entry of the first step, in display order.
pub const CHOICES: [Choice; 6] = [
    Choice::Phrase,
    Choice::From(Source::BitwardenJson),
    Choice::From(Source::Kdbx),
    Choice::From(Source::KeepassXml),
    Choice::From(Source::EnpassJson),
    Choice::From(Source::Csv),
];

/// Where the records go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A vault created after the review.
    NewVault,
    /// The vault that is open now.
    OpenVault,
}

/// Wizard step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportStep {
    /// Phrase or another manager.
    Source,
    /// The export file.
    File,
    /// A `.kdbx` database's password and key file.
    Unlock,
    /// Which CSV column feeds what.
    Mapping,
    /// What will be imported.
    Preview,
}

/// Focus on the unlock step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockField {
    /// Master password.
    Password,
    /// Key-file path.
    KeyFile,
}

/// What the wizard asks its owner to do.
#[derive(Debug)]
pub enum ImportEvent {
    /// Nothing.
    Stay,
    /// Esc on the first step.
    Leave,
    /// The `ZebraPass` phrase was chosen.
    Phrase,
    /// The reviewed records to write.
    Records(Vec<Document>),
}

/// The review with its cursor.
#[derive(Debug)]
pub struct Preview {
    /// Rows, report, and include marks.
    pub review: Review,
    /// Selected row.
    pub cursor: usize,
    /// TOTP fields this application cannot produce codes for.
    pub bad_totp: usize,
}

impl Preview {
    fn new(review: Review) -> Self {
        let bad_totp = review
            .items()
            .iter()
            .filter_map(|item| item.doc.data(TAG_TOTP).ok().flatten())
            .filter(|field| Totp::try_from(*field).is_err())
            .count();
        Self {
            review,
            cursor: 0,
            bad_totp,
        }
    }
}

/// Wizard state.
#[derive(Debug)]
pub struct ImportState {
    /// Where the records go.
    pub target: Target,
    /// Step.
    pub step: ImportStep,
    /// Selected entry of [`Self::choices`].
    pub cursor: usize,
    /// Export file path as typed.
    pub path: TextInput,
    /// What the path points at.
    pub hint: FileHint,
    /// The export under review.
    pub preview: Option<Box<Preview>>,
    /// CSV columns and their targets.
    pub columns: Option<Box<Columns>>,
    /// `.kdbx` master password.
    pub password: SecretInput,
    /// `.kdbx` key-file path, optional.
    pub key_file: TextInput,
    /// Focus on the unlock step.
    pub field: UnlockField,
    /// Password reveal timer.
    pub reveal: RevealGuard,
    /// Why the last read failed.
    pub error: Option<Box<str>>,
}

impl ImportState {
    /// Start on the first step.
    #[must_use]
    pub fn new(target: Target) -> Self {
        Self {
            target,
            step: ImportStep::Source,
            cursor: 0,
            path: TextInput::new(MAX_PATH_INPUT),
            hint: FileHint::Missing,
            preview: None,
            columns: None,
            password: SecretInput::new(MAX_PASSWORD),
            key_file: TextInput::new(MAX_PATH_INPUT),
            field: UnlockField::Password,
            reveal: RevealGuard::default(),
            error: None,
        }
    }

    /// Entries of the first step: the phrase only when restoring.
    #[must_use]
    pub fn choices(&self) -> &'static [Choice] {
        match self.target {
            Target::NewVault => &CHOICES,
            Target::OpenVault => CHOICES.get(1..).unwrap_or_default(),
        }
    }

    /// The selected source; `Bitwarden` while the phrase row is selected.
    #[must_use]
    pub fn source(&self) -> Source {
        match self.choices().get(self.cursor) {
            Some(Choice::From(source)) => *source,
            Some(Choice::Phrase) | None => Source::BitwardenJson,
        }
    }

    /// Keymap scope.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self.step {
            ImportStep::Source => Scope::Import,
            ImportStep::File => Scope::ImportFile,
            ImportStep::Unlock => Scope::ImportUnlock,
            ImportStep::Mapping => Scope::ImportMapping,
            ImportStep::Preview => Scope::ImportPreview,
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> ImportEvent {
        let action = resolve(self.scope(), event);
        match (self.step, action) {
            (ImportStep::Source, Some(action)) => return self.on_source(action, ctx),
            (ImportStep::File, Some(action)) => self.on_file(action, ctx),
            (ImportStep::File, None) => {
                edit_text(&mut self.path, event);
                self.hint = inspect(&self.resolved_path());
            }
            (ImportStep::Unlock, Some(action)) => self.on_unlock(action, ctx),
            (ImportStep::Unlock, None) => {
                match self.field {
                    UnlockField::Password => edit_secret(&mut self.password, event),
                    UnlockField::KeyFile => edit_text(&mut self.key_file, event),
                };
            }
            (ImportStep::Mapping, Some(action)) => self.on_mapping(action, ctx),
            (ImportStep::Preview, Some(action)) => return self.on_preview(action, ctx),
            (ImportStep::Source | ImportStep::Mapping | ImportStep::Preview, None) => {}
        }
        ImportEvent::Stay
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        let line = text.trim_end_matches(['\n', '\r']);
        match (self.step, self.field) {
            (ImportStep::File, _) => {
                self.path.insert_str(line);
                self.hint = inspect(&self.resolved_path());
            }
            (ImportStep::Unlock, UnlockField::Password) => {
                self.password.insert_str(line);
            }
            (ImportStep::Unlock, UnlockField::KeyFile) => {
                self.key_file.insert_str(line);
            }
            (ImportStep::Source | ImportStep::Mapping | ImportStep::Preview, _) => {}
        }
    }

    /// The worker finished reading the export.
    pub fn parsed(&mut self, outcome: Result<Box<Parsed>, String>, ctx: &mut Ctx) {
        match outcome {
            Ok(parsed) if parsed.items.is_empty() => {
                self.error = Some("Nothing in that file can be imported.".into());
            }
            Ok(parsed) => {
                self.error = None;
                self.preview = Some(Box::new(Preview::new(Review::from(*parsed))));
                self.step = ImportStep::Preview;
                ctx.redraw();
            }
            Err(message) => self.error = Some(message.into_boxed_str()),
        }
    }

    /// Hide a revealed password now.
    pub const fn hide(&mut self, ctx: &mut Ctx) {
        if self.reveal.hide() {
            ctx.redraw();
        }
    }

    /// The typed path with a leading `~` expanded.
    #[must_use]
    pub fn resolved_path(&self) -> PathBuf {
        expand_home(self.path.value())
    }

    fn on_source(&mut self, action: Action, ctx: &mut Ctx) -> ImportEvent {
        let last = self.choices().len().saturating_sub(1);
        match action {
            Action::Up => self.cursor = self.cursor.saturating_sub(1),
            Action::Down => self.cursor = (self.cursor + 1).min(last),
            Action::Back => return ImportEvent::Leave,
            Action::Confirm => match self.choices().get(self.cursor) {
                Some(Choice::Phrase) => return ImportEvent::Phrase,
                Some(Choice::From(source)) if source.supported() => {
                    self.error = None;
                    self.step = ImportStep::File;
                    self.hint = inspect(&self.resolved_path());
                }
                Some(Choice::From(_)) => ctx.toast(
                    Tone::Info,
                    "Not available in this build. Export from that app as CSV and choose CSV.",
                ),
                None => {}
            },
            _ => {}
        }
        ImportEvent::Stay
    }

    fn on_file(&mut self, action: Action, ctx: &mut Ctx) {
        match action {
            Action::Back => {
                self.error = None;
                self.columns = None;
                self.step = ImportStep::Source;
            }
            Action::Confirm => match self.hint {
                FileHint::Missing => self.error = Some("No readable file at that path.".into()),
                FileHint::Found(..) if self.source() == Source::Csv => {
                    self.error = None;
                    self.open_columns(ctx);
                }
                FileHint::Found(..) if self.source() == Source::Kdbx => {
                    self.error = None;
                    self.field = UnlockField::Password;
                    self.step = ImportStep::Unlock;
                }
                FileHint::Found(..) => {
                    self.error = None;
                    self.read(Credentials::default(), ctx);
                }
            },
            _ => {}
        }
    }

    fn on_unlock(&mut self, action: Action, ctx: &mut Ctx) {
        match action {
            Action::NextField | Action::PrevField => {
                self.field = match self.field {
                    UnlockField::Password => UnlockField::KeyFile,
                    UnlockField::KeyFile => UnlockField::Password,
                };
            }
            Action::RevealField if self.field == UnlockField::Password => {
                if self.reveal.toggle(REVEAL_PASSWORD, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Back => {
                self.password.clear();
                self.hide(ctx);
                self.error = None;
                self.step = ImportStep::File;
            }
            Action::Confirm => {
                let key_file = self.key_file.value().trim();
                if self.password.is_empty() && key_file.is_empty() {
                    self.error = Some("Enter the database password or its key file.".into());
                    return;
                }
                let credentials = Credentials {
                    key_file: (!key_file.is_empty()).then(|| expand_home(key_file)),
                    password: (!self.password.is_empty()).then(|| self.password.take()),
                };
                self.hide(ctx);
                self.error = None;
                self.read(credentials, ctx);
            }
            _ => {}
        }
    }

    /// Queue the read of the export on the worker.
    pub(crate) fn read(&self, credentials: Credentials, ctx: &mut Ctx) {
        let load = Load {
            path: self.resolved_path(),
            source: self.source(),
            credentials,
            mapping: self.mapping(),
        };
        ctx.start(Job::ParseImport(Box::new(load)), Task::Import);
    }

    fn on_preview(&mut self, action: Action, ctx: &mut Ctx) -> ImportEvent {
        match action {
            Action::Back => {
                self.preview = None;
                self.step = if self.columns.is_some() {
                    ImportStep::Mapping
                } else {
                    ImportStep::File
                };
                return ImportEvent::Stay;
            }
            Action::Confirm => return self.take_records(ctx),
            Action::EditColumns if self.columns.is_some() => {
                self.preview = None;
                self.step = ImportStep::Mapping;
                return ImportEvent::Stay;
            }
            _ => {}
        }
        let Some(preview) = self.preview.as_deref_mut() else {
            return ImportEvent::Stay;
        };
        let last = preview.review.rows().len().saturating_sub(1);
        match action {
            Action::Up => preview.cursor = preview.cursor.saturating_sub(1),
            Action::Down => preview.cursor = (preview.cursor + 1).min(last),
            Action::PageUp => preview.cursor = preview.cursor.saturating_sub(PAGE),
            Action::PageDown => preview.cursor = (preview.cursor + PAGE).min(last),
            Action::Top => preview.cursor = 0,
            Action::Bottom => preview.cursor = last,
            Action::ToggleInclude => preview.review.toggle(preview.cursor),
            Action::ToggleAll => preview.review.toggle_all(),
            _ => {}
        }
        ImportEvent::Stay
    }

    fn take_records(&mut self, ctx: &mut Ctx) -> ImportEvent {
        let empty = self
            .preview
            .as_ref()
            .is_none_or(|preview| preview.review.included_count() == 0);
        if empty {
            ctx.toast(Tone::Info, "Include at least one item (Space).");
            return ImportEvent::Stay;
        }
        self.preview.take().map_or(ImportEvent::Stay, |preview| {
            ImportEvent::Records(preview.review.into_records())
        })
    }
}

/// Navigation for the restore-or-import screen, where records become a
/// new vault.
pub fn new_vault_nav(event: ImportEvent, source: Source, ctx: &mut Ctx) -> Nav {
    match event {
        ImportEvent::Stay => Nav::Stay,
        ImportEvent::Leave => Nav::To(initial_screen(ctx)),
        ImportEvent::Phrase => Nav::To(Screen::Restore(Box::new(RestoreState::new(None)))),
        ImportEvent::Records(records) => Nav::To(Screen::Create(Box::new(
            CreateState::with_records(ctx, records, source.label()),
        ))),
    }
}
