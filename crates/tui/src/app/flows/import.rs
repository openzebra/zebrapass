//! Restore or import: pick the `ZebraPass` phrase or another manager, read
//! its export, review it, then create a vault that receives it.
//!
//! The export is read and parsed on the worker thread. Parsed documents
//! live in this state until they move into the create wizard; dropping the
//! state (back, lock, quit) wipes them.

use std::path::{Path, PathBuf};

use crossterm::event::KeyEvent;
use import::{Parsed, Source};
use record::{Document, TAG_TOTP};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::create::CreateState;
use crate::app::flows::editing::edit_text;
use crate::app::flows::gate::initial_screen;
use crate::app::flows::restore::RestoreState;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::{Nav, Screen};
use crate::app::worker::Job;
use crate::secure::totp::Totp;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::limits::MAX_PATH_INPUT;
use crate::vault::records::Summary;

/// Bytes read from the export for the live format hint.
const SNIFF_BYTES: u64 = 4096;

/// Rows moved by Page Up / Page Down.
const PAGE: usize = 10;

/// One entry of the first step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// A `ZebraPass` vault file and its recovery phrase.
    Phrase,
    /// Another manager's export.
    From(Source),
}

/// The first step, in display order.
pub const CHOICES: [Choice; 6] = [
    Choice::Phrase,
    Choice::From(Source::BitwardenJson),
    Choice::From(Source::Kdbx),
    Choice::From(Source::KeepassXml),
    Choice::From(Source::EnpassJson),
    Choice::From(Source::Csv),
];

/// Wizard step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportStep {
    /// Phrase or another manager.
    Source,
    /// The export file.
    File,
    /// What will be imported.
    Preview,
}

/// What the path points at, from its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileHint {
    /// Nothing readable there.
    Missing,
    /// A file whose format was guessed (`None`: unknown), and its size.
    Found(Option<Source>, u64),
}

/// The parsed export under review.
#[derive(Debug)]
pub struct Preview {
    /// Parsed items and the report.
    pub parsed: Box<Parsed>,
    /// Text-only rows for the list (wiped on drop).
    pub rows: Box<[Summary]>,
    /// Per item: imported when `true`.
    pub included: Vec<bool>,
    /// Selected row.
    pub cursor: usize,
    /// TOTP fields that will not produce codes.
    pub bad_totp: usize,
}

impl Preview {
    fn new(parsed: Box<Parsed>) -> Self {
        let rows: Box<[Summary]> = parsed
            .items
            .iter()
            .zip(0u32..)
            .map(|(item, index)| Summary::of(index, 0, 0, &item.doc))
            .collect();
        let bad_totp = parsed
            .items
            .iter()
            .filter_map(|item| item.doc.data(TAG_TOTP).ok().flatten())
            .filter(|field| Totp::try_from(*field).is_err())
            .count();
        Self {
            included: vec![true; parsed.items.len()],
            parsed,
            rows,
            cursor: 0,
            bad_totp,
        }
    }

    /// Items that will be imported.
    #[must_use]
    pub fn count(&self) -> usize {
        self.included.iter().filter(|on| **on).count()
    }
}

/// Wizard state.
#[derive(Debug)]
pub struct ImportState {
    /// Step.
    pub step: ImportStep,
    /// Selected entry of [`CHOICES`].
    pub cursor: usize,
    /// Export file path as typed.
    pub path: TextInput,
    /// What the path points at.
    pub hint: FileHint,
    /// The export under review.
    pub preview: Option<Box<Preview>>,
    /// Why the last read failed.
    pub error: Option<Box<str>>,
}

impl ImportState {
    /// Start on the first step.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            step: ImportStep::Source,
            cursor: 0,
            path: TextInput::new(MAX_PATH_INPUT),
            hint: FileHint::Missing,
            preview: None,
            error: None,
        }
    }

    /// The selected source; `Bitwarden` while the phrase row is selected.
    #[must_use]
    pub fn source(&self) -> Source {
        match CHOICES.get(self.cursor) {
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
            ImportStep::Preview => Scope::ImportPreview,
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        let action = resolve(self.scope(), event);
        match (self.step, action) {
            (ImportStep::Source, Some(action)) => self.on_source(action, ctx),
            (ImportStep::File, Some(action)) => self.on_file(action, ctx),
            (ImportStep::File, None) => {
                edit_text(&mut self.path, event);
                self.check_path();
                Nav::Stay
            }
            (ImportStep::Preview, Some(action)) => self.on_preview(action, ctx),
            (ImportStep::Source | ImportStep::Preview, None) => Nav::Stay,
        }
    }

    /// Paste into the path field.
    pub fn on_paste(&mut self, text: &str) {
        if self.step == ImportStep::File {
            self.path.insert_str(text.trim_end_matches(['\n', '\r']));
            self.check_path();
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
                self.preview = Some(Box::new(Preview::new(parsed)));
                self.step = ImportStep::Preview;
                ctx.redraw();
            }
            Err(message) => self.error = Some(message.into_boxed_str()),
        }
    }

    fn on_source(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Up => self.cursor = self.cursor.saturating_sub(1),
            Action::Down => self.cursor = (self.cursor + 1).min(CHOICES.len() - 1),
            Action::Back => return Nav::To(initial_screen(ctx)),
            Action::Confirm => match CHOICES.get(self.cursor) {
                Some(Choice::Phrase) => {
                    return Nav::To(Screen::Restore(Box::new(RestoreState::new(None, ctx))));
                }
                Some(Choice::From(source)) if source.supported() => {
                    self.error = None;
                    self.step = ImportStep::File;
                    self.check_path();
                }
                Some(Choice::From(_)) => ctx.toast(
                    Tone::Info,
                    "Not available yet. Export from that app as CSV and choose CSV.",
                ),
                None => {}
            },
            _ => {}
        }
        Nav::Stay
    }

    fn on_file(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Back => {
                self.error = None;
                self.step = ImportStep::Source;
            }
            Action::Confirm => match self.hint {
                FileHint::Missing => self.error = Some("No readable file at that path.".into()),
                FileHint::Found(..) => {
                    self.error = None;
                    let job = Job::ParseImport(self.resolved_path(), self.source());
                    ctx.start(job, Task::Import);
                }
            },
            _ => {}
        }
        Nav::Stay
    }

    fn on_preview(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        if action == Action::Back {
            self.preview = None;
            self.step = ImportStep::File;
            return Nav::Stay;
        }
        if action == Action::Confirm {
            return self.create_vault(ctx);
        }
        let Some(preview) = self.preview.as_deref_mut() else {
            return Nav::Stay;
        };
        let last = preview.rows.len().saturating_sub(1);
        match action {
            Action::Up => preview.cursor = preview.cursor.saturating_sub(1),
            Action::Down => preview.cursor = (preview.cursor + 1).min(last),
            Action::PageUp => preview.cursor = preview.cursor.saturating_sub(PAGE),
            Action::PageDown => preview.cursor = (preview.cursor + PAGE).min(last),
            Action::Top => preview.cursor = 0,
            Action::Bottom => preview.cursor = last,
            Action::ToggleInclude => {
                if let Some(on) = preview.included.get_mut(preview.cursor) {
                    *on = !*on;
                }
            }
            Action::ToggleAll => {
                let all = preview.included.iter().all(|on| *on);
                preview.included.iter_mut().for_each(|on| *on = !all);
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Hand the included documents to the create wizard.
    fn create_vault(&mut self, ctx: &mut Ctx) -> Nav {
        if self
            .preview
            .as_ref()
            .is_none_or(|preview| preview.count() == 0)
        {
            ctx.toast(Tone::Info, "Include at least one item (Space).");
            return Nav::Stay;
        }
        let Some(preview) = self.preview.take() else {
            return Nav::Stay;
        };
        let Preview {
            parsed, included, ..
        } = *preview;
        let records: Vec<Document> = parsed
            .items
            .into_iter()
            .zip(included)
            .filter(|(_, on)| *on)
            .map(|(item, _)| *item.doc)
            .collect();
        let source = self.source().label();
        Nav::To(Screen::Create(Box::new(CreateState::with_records(
            ctx, records, source,
        ))))
    }

    /// The typed path with a leading `~` expanded.
    #[must_use]
    pub fn resolved_path(&self) -> PathBuf {
        expand_home(self.path.value().trim())
    }

    /// Re-read the first bytes at the path for the live hint.
    fn check_path(&mut self) {
        let path = self.resolved_path();
        self.hint = if self.path.value().trim().is_empty() {
            FileHint::Missing
        } else {
            import::read_head(&path, SNIFF_BYTES).map_or(FileHint::Missing, |(head, size)| {
                let extension = path.extension().and_then(|ext| ext.to_str());
                FileHint::Found(import::sniff(&head, extension), size)
            })
        };
    }
}

impl Default for ImportState {
    fn default() -> Self {
        Self::new()
    }
}

/// `~` and `~/…` resolved against `HOME`; anything else as typed.
fn expand_home(typed: &str) -> PathBuf {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    match typed.strip_prefix('~') {
        Some("") => home().unwrap_or_else(|| PathBuf::from(typed)),
        Some(rest) if rest.starts_with('/') => home().map_or_else(
            || PathBuf::from(typed),
            |home| home.join(rest.trim_start_matches('/')),
        ),
        Some(_) | None => Path::new(typed).to_path_buf(),
    }
}
