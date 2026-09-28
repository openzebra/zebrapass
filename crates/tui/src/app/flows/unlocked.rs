//! The open vault: owns the session (through [`Vault`]), the summary cache,
//! and every view. Dropping this state is what "lock" means.

use crossterm::event::{KeyCode, KeyEvent};
use local::{device_key_info, DeviceKeyInfo, Prefs};
use session::WrapDirectory;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::Dialog;
use crate::app::flows::editor::EditorState;
use crate::app::flows::factors::{Anim, FactorsState};
use crate::app::flows::generator::{GenEvent, GeneratorState};
use crate::app::flows::history::HistoryState;
use crate::app::flows::home::{visible, Detail, Home};
use crate::app::flows::settings::SettingsModal;
use crate::app::keymap::Scope;
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::secure::health::HealthReport;
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::VaultRef;
use crate::vault::ops::{Op, Outcome};
use crate::vault::records::{build_cache, Summary};
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
    /// Public header of this device's key file, when it has one.
    pub device: Option<DeviceKeyInfo>,
    /// Saved preferences; `None` until this device saves some.
    pub prefs: Option<Prefs>,
}

impl VaultInfo {
    /// The device wrap this machine holds a key file for.
    #[must_use]
    pub fn owned_device(&self) -> Option<[u8; 16]> {
        self.device.map(|device| device.id)
    }
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
            device: device_key_info(&vault.paths.device_key).ok(),
            prefs: vault.meta.prefs.clone(),
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
    Sync,
    /// Health.
    Health(usize),
    /// History.
    History(Box<HistoryState>),
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
    /// Settings modal over the view.
    pub settings: Option<Box<SettingsModal>>,
    /// Last health report.
    pub health: Option<Box<HealthReport>>,
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
            settings: None,
            health: None,
        };
        state.load_detail();
        state
    }

    /// Keymap scope of the focus.
    #[must_use]
    pub fn scope(&self) -> Scope {
        if self.dialog.is_some() {
            return Scope::Dialog;
        }
        if self.generator.is_some() {
            return Scope::Generator;
        }
        if let Some(settings) = self.settings.as_deref() {
            return settings.scope();
        }
        match &self.view {
            View::Home if self.home.searching => Scope::Search,
            View::Home => Scope::Home,
            View::Editor(_) => Scope::Editor,
            View::Factors(_) => Scope::Factors,
            View::Devices(_) => Scope::Devices,
            View::Sync => Scope::Sync,
            View::Health(_) => Scope::Health,
            View::History(_) => Scope::History,
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
        if self.settings.is_some() {
            return crate::app::flows::settings::on_key(self, event, ctx);
        }
        match &mut self.view {
            View::Home => crate::app::flows::home_keys::on_key(self, event, ctx),
            View::Editor(_) => crate::app::flows::editor_keys::on_key(self, event, ctx),
            View::Factors(_) | View::Devices(_) => {
                crate::app::flows::factors::on_key(self, event, ctx)
            }
            View::Sync | View::Health(_) => crate::app::flows::panels::on_key(self, event, ctx),
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
        } else if let Some(settings) = self.settings.as_deref_mut() {
            crate::app::flows::settings::on_paste(settings, text);
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
            hid |= detail.reveal.tick(ctx.now, ctx.reveal_after);
        }
        if let View::Editor(editor) = &mut self.view {
            hid |= editor.reveal.tick(ctx.now, ctx.reveal_after);
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
                self.view = View::Home;
                self.refresh();
                self.select(id);
                ctx.toast(Tone::Success, "Saved.");
            }
            Outcome::Deleted(_) => {
                self.refresh();
                ctx.toast(
                    Tone::Success,
                    "Record deleted. It stays in history until cleared.",
                );
            }
            Outcome::Restored(id, revision) => {
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
            Outcome::PrefsSaved => {
                if let Some(prefs) = self.info.prefs.as_ref() {
                    ctx.apply_prefs(prefs);
                    if let Some(settings) = self.settings.as_deref_mut() {
                        settings.saved = prefs.clone();
                    }
                }
                ctx.toast(
                    Tone::Success,
                    "Settings saved for this vault on this device.",
                );
            }
            Outcome::FactorAdded(kind) => {
                self.animate(Anim::Add, ctx);
                ctx.toast(Tone::Success, format!("Added {}.", kind.noun()));
            }
            Outcome::FactorRemoved => {
                ctx.toast(Tone::Success, "Wrap removed. The vault key did not change.");
            }
            Outcome::PasswordChanged => {
                ctx.toast(Tone::Success, "Password changed.");
            }
            Outcome::PinChanged => {
                ctx.toast(
                    Tone::Success,
                    "Device PIN changed. The vault did not change.",
                );
            }
            Outcome::Rotated(revoked) => {
                self.refresh();
                self.animate(if revoked { Anim::Revoke } else { Anim::Rotate }, ctx);
                let what = if revoked {
                    "Revoked. New vault key"
                } else {
                    "New vault key"
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
