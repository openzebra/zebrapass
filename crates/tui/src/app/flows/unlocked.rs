//! The open vault: owns the session (through [`Vault`]), the summary cache,
//! and every view. Dropping this state is what "lock" means.

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent};
use session::WrapDirectory;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::Dialog;
use crate::app::flows::editor::EditorState;
use crate::app::flows::factors::{Anim, FactorsState};
use crate::app::flows::generator::{GenEvent, GeneratorState};
use crate::app::flows::history::HistoryState;
use crate::app::flows::home::{visible, Detail, Home};
use crate::app::flows::panels::SettingsState;
use crate::app::keymap::Scope;
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::secure::health::HealthReport;
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::VaultRef;
use crate::vault::ops::{Op, Outcome};
use crate::vault::records::{build_cache, Summary};
use crate::vault::sync::{ImportReport, SignedPreview};
use crate::vault::Vault;

/// Public facts about the open vault, kept while a job holds the vault.
#[derive(Clone, Debug)]
pub struct VaultInfo {
    /// Display name.
    pub label: String,
    /// Vault id.
    pub vault_id: [u8; 16],
    /// Account client id.
    pub client_id: [u8; 64],
    /// Device id this session stamps into frames.
    pub origin: [u8; 16],
    /// Directory generation.
    pub generation: u64,
    /// Wrap directory.
    pub directory: WrapDirectory,
}

impl From<&Vault> for VaultInfo {
    fn from(vault: &Vault) -> Self {
        Self {
            label: vault.label(),
            vault_id: *vault.session.vault_id(),
            client_id: vault.meta.client_id,
            origin: vault.session.origin_device(),
            generation: vault.session.generation(),
            directory: vault.directory.clone(),
        }
    }
}

/// Active view.
#[derive(Debug)]
pub enum View {
    /// List and detail.
    Home,
    /// Record editor.
    Editor(Box<EditorState>),
    /// Constellation.
    Factors(FactorsState),
    /// Devices.
    Devices(usize),
    /// Sync.
    Sync(usize),
    /// Health.
    Health(usize),
    /// History.
    History(Box<HistoryState>),
    /// Settings.
    Settings(SettingsState),
}

/// Unlocked state.
#[derive(Debug)]
pub struct Unlocked {
    /// The vault; `None` while a job holds it.
    pub vault: Option<Box<Vault>>,
    /// Public facts for drawing.
    pub info: VaultInfo,
    /// Vaults for the unlock screen after lock.
    pub vaults: Vec<VaultRef>,
    /// Which of them this is.
    pub current: usize,
    /// Record summaries (wiped on drop).
    pub cache: Box<[Summary]>,
    /// Active view.
    pub view: View,
    /// Home state (kept across views).
    pub home: Home,
    /// Modal dialog.
    pub dialog: Option<Box<Dialog>>,
    /// Generator overlay.
    pub generator: Option<Box<GeneratorState>>,
    /// Last health report.
    pub health: Option<Box<HealthReport>>,
    /// Records changed since the last export.
    pub pending_sync: BTreeSet<u32>,
    /// Last exported record's signed fields.
    pub last_export: Option<SignedPreview>,
    /// Last import results.
    pub import: Option<Box<ImportReport>>,
}

impl Unlocked {
    /// Open state for `vault`.
    #[must_use]
    pub fn new(vault: Box<Vault>, vaults: Vec<VaultRef>, current: usize) -> Self {
        let cache = build_cache(&vault.session).unwrap_or_default();
        let info = VaultInfo::from(&*vault);
        let mut state = Self {
            vault: Some(vault),
            info,
            vaults,
            current,
            cache,
            view: View::Home,
            home: Home::default(),
            dialog: None,
            generator: None,
            health: None,
            pending_sync: BTreeSet::new(),
            last_export: None,
            import: None,
        };
        state.load_detail();
        state
    }

    /// Keymap scope of the focus.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        if self.dialog.is_some() {
            return Scope::Dialog;
        }
        if self.generator.is_some() {
            return Scope::Generator;
        }
        match &self.view {
            View::Home if self.home.searching => Scope::Search,
            View::Home => Scope::Home,
            View::Editor(_) => Scope::Editor,
            View::Factors(_) => Scope::Factors,
            View::Devices(_) => Scope::Devices,
            View::Sync(_) => Scope::Sync,
            View::Health(_) => Scope::Health,
            View::History(_) => Scope::History,
            View::Settings(_) => Scope::Settings,
        }
    }

    /// Indexes of the visible records.
    #[must_use]
    pub fn visible(&self) -> Vec<usize> {
        visible(
            &self.cache,
            &self.home.filter,
            self.home.query.value(),
            self.health.as_deref(),
        )
    }

    /// The selected summary.
    #[must_use]
    pub fn selected(&self) -> Option<&Summary> {
        self.visible()
            .get(self.home.selected)
            .and_then(|index| self.cache.get(*index))
    }

    /// Open the selected record into the detail pane (decrypts on demand).
    pub fn load_detail(&mut self) {
        let count = self.visible().len();
        self.home.selected = self.home.selected.min(count.saturating_sub(1));
        let Some((id, revision, timestamp)) =
            self.selected().map(|s| (s.id, s.revision, s.timestamp_ms))
        else {
            self.home.detail = None;
            return;
        };
        if self
            .home
            .detail
            .as_ref()
            .is_some_and(|detail| detail.id == id && detail.revision == revision)
        {
            return;
        }
        self.home.detail = self
            .vault
            .as_ref()
            .and_then(|vault| session::open_record(&vault.session, id).ok())
            .map(|doc| Box::new(Detail::new(id, revision, timestamp, doc)));
    }

    /// Hand the vault to the worker for `op`.
    pub fn run(&mut self, op: Op, task: Task, ctx: &mut Ctx) {
        match self.vault.take() {
            Some(vault) => ctx.start(Job::Vault(vault, op), task),
            None => ctx.toast(Tone::Info, "Still working on the last change."),
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if self.vault.is_none() {
            return Nav::Stay;
        }
        if self.dialog.is_some() {
            return crate::app::flows::dialog::on_key(self, event, ctx);
        }
        if let Some(generator) = self.generator.as_mut() {
            match generator.on_key(event, ctx) {
                GenEvent::Stay => {}
                GenEvent::Close => self.generator = None,
                GenEvent::Use(value) => {
                    self.generator = None;
                    if let View::Editor(editor) = &mut self.view {
                        editor.fill_generated(&value);
                    }
                }
            }
            return Nav::Stay;
        }
        match &mut self.view {
            View::Home => crate::app::flows::home_keys::on_key(self, event, ctx),
            View::Editor(_) => crate::app::flows::editor_keys::on_key(self, event, ctx),
            View::Factors(_) | View::Devices(_) => {
                crate::app::flows::factors::on_key(self, event, ctx)
            }
            View::Sync(_) | View::Health(_) | View::Settings(_) => {
                crate::app::flows::panels::on_key(self, event, ctx)
            }
            View::History(_) => crate::app::flows::history::on_key(self, event, ctx),
        }
    }

    /// A key was released (key-release terminals only).
    pub fn on_release(&mut self, event: &KeyEvent, ctx: &mut Ctx) {
        let hold_key = matches!(event.code, KeyCode::Char(' ') | KeyCode::Enter);
        if !hold_key {
            return;
        }
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.release(ctx);
        }
        if let Some(detail) = self.home.detail.as_mut() {
            if event.code == KeyCode::Char(' ') && detail.reveal.hide() {
                ctx.redraw();
            }
        }
    }

    /// Paste into whatever has focus.
    pub fn on_paste(&mut self, text: &str) {
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.on_paste(text);
        } else if let View::Editor(editor) = &mut self.view {
            editor.on_paste(text);
        } else if self.home.searching {
            self.home.query.insert_str(text);
        }
    }

    /// Timers: reveals and hold-to-confirm.
    pub fn on_tick(&mut self, ctx: &mut Ctx) -> Nav {
        let mut hid = false;
        if let Some(detail) = self.home.detail.as_mut() {
            hid |= detail.reveal.tick(ctx.now);
        }
        if let View::Editor(editor) = &mut self.view {
            hid |= editor.reveal.tick(ctx.now);
        }
        if hid {
            ctx.redraw();
        }
        if let Some(dialog) = self.dialog.as_mut() {
            if dialog.tick(ctx) {
                return crate::app::flows::dialog::submit(self, ctx);
            }
        }
        Nav::Stay
    }

    /// A job handed the vault back.
    pub fn on_result(&mut self, vault: Box<Vault>, result: Result<Outcome, String>, ctx: &mut Ctx) {
        self.info = VaultInfo::from(&*vault);
        self.vault = Some(vault);
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(message) => {
                ctx.toast(Tone::Danger, message);
                return;
            }
        };
        match outcome {
            Outcome::Saved(id) => {
                self.pending_sync.insert(id);
                self.view = View::Home;
                self.refresh();
                self.select(id);
                ctx.toast(Tone::Success, "Saved.");
            }
            Outcome::Deleted(id) => {
                self.pending_sync.insert(id);
                self.refresh();
                ctx.toast(
                    Tone::Success,
                    "Record deleted. It stays in history until cleared.",
                );
            }
            Outcome::Restored(id, revision) => {
                self.pending_sync.insert(id);
                self.view = View::Home;
                self.refresh();
                self.select(id);
                ctx.toast(Tone::Success, format!("Restored as revision {revision}."));
            }
            Outcome::HistoryCleared => {
                self.refresh();
                ctx.toast(Tone::Success, "History cleared.");
            }
            Outcome::Renamed => ctx.toast(Tone::Success, "Renamed on this device."),
            Outcome::FactorAdded(kind) => {
                self.animate(Anim::Add, ctx);
                ctx.toast(Tone::Success, format!("Added {}.", kind.noun()));
            }
            Outcome::FactorRemoved => {
                ctx.toast(Tone::Success, "Wrap removed. The vault key did not change.");
            }
            Outcome::Rotated {
                revoked,
                password_changed,
            } => {
                self.refresh();
                self.animate(if revoked { Anim::Revoke } else { Anim::Rotate }, ctx);
                let what = match (revoked, password_changed) {
                    (true, _) => "Revoked. New vault key",
                    (false, true) => "Password changed. New vault key",
                    (false, false) => "New vault key",
                };
                ctx.toast(
                    Tone::Success,
                    format!("{what} · generation {}.", self.info.generation),
                );
            }
            Outcome::RecoveryDropped => {
                ctx.toast(Tone::Warn, "Recovery wrap dropped from this copy.");
            }
            Outcome::Health(report) => {
                self.health = Some(report);
                self.view = View::Health(0);
            }
            Outcome::Exported(report) => {
                self.last_export = report.preview;
                self.pending_sync.clear();
                ctx.toast(
                    Tone::Success,
                    format!(
                        "Exported {} signed frame(s) to {}.",
                        report.count,
                        report.path.display()
                    ),
                );
            }
            Outcome::Imported(report) => {
                let accepted = report
                    .outcomes
                    .iter()
                    .filter(|(_, outcome)| outcome.is_ok())
                    .count();
                let total = report.outcomes.len();
                self.import = Some(report);
                self.refresh();
                let tone = if accepted == total {
                    Tone::Success
                } else {
                    Tone::Warn
                };
                ctx.toast(tone, format!("Imported {accepted} of {total} frame(s)."));
            }
        }
    }

    const fn animate(&mut self, anim: Anim, ctx: &Ctx) {
        if let View::Factors(factors) = &mut self.view {
            factors.anim = Some((anim, ctx.now));
        }
    }

    /// Rebuild the cache and the detail after a write.
    pub fn refresh(&mut self) {
        if let Some(vault) = self.vault.as_ref() {
            self.cache = build_cache(&vault.session).unwrap_or_default();
        }
        self.home.detail = None;
        self.load_detail();
    }

    /// Select record `id` if it is visible.
    pub fn select(&mut self, id: u32) {
        if let Some(position) = self.visible().iter().position(|index| {
            self.cache
                .get(*index)
                .is_some_and(|summary| summary.id == id)
        }) {
            self.home.selected = position;
            self.load_detail();
        }
    }
}
