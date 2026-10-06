//! Application state and update logic. Elm-style: events become actions,
//! actions mutate state, `view` draws state. `view` does no IO.

pub mod action;
pub mod ctx;
pub mod event;
pub mod flows;
pub mod idle;
pub mod keymap;
pub mod p2p;
pub mod prefs;
pub mod screen;
pub mod worker;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::Frame;
use zeroize::Zeroizing;

use crate::app::action::Action;
use crate::app::ctx::{Caps, Ctx};
use crate::app::flows::create::CreateState;
use crate::app::flows::gate::{initial_screen, AlertState, LockReason, LockedState};
use crate::app::flows::import::{ImportState, Target};
use crate::app::flows::palette::{Overlay, PaletteEvent, PaletteState};
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::{Nav, Screen};
use crate::app::worker::JobResult;
use crate::cli::{Config, Flags};
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::discover;
use crate::vault::error::UnlockError;

/// The whole application.
#[derive(Debug)]
pub struct App {
    /// Current screen.
    pub screen: Screen,
    /// Palette or help, above the screen.
    pub overlay: Option<Overlay>,
    /// Shared services.
    pub ctx: Ctx,
    quit: bool,
}

/// Actions the app handles itself, whatever the screen.
const fn app_level(action: Action) -> bool {
    matches!(
        action,
        Action::Help
            | Action::Palette
            | Action::Quit
            | Action::Lock
            | Action::CycleTheme
            | Action::ToggleAnimation
            | Action::ToggleAscii
            | Action::CreateVault
            | Action::RestoreVault
    )
}

impl App {
    /// Start on the first screen for `config`.
    ///
    /// # Errors
    ///
    /// When the worker thread cannot start.
    pub fn new(config: &Config, base: PathBuf, caps: Caps) -> std::io::Result<Self> {
        let mut ctx = Ctx::new(config, base, caps, Instant::now())?;
        let screen = initial_screen(&mut ctx);
        Ok(Self {
            screen,
            overlay: None,
            ctx,
            quit: false,
        })
    }

    /// Whether the app wants to exit.
    #[must_use]
    pub const fn should_quit(&self) -> bool {
        self.quit
    }

    /// Escape sequences (clipboard) to write to the terminal.
    pub fn take_outbox(&mut self) -> Vec<Zeroizing<Vec<u8>>> {
        self.ctx.clipboard.take_outbox()
    }

    /// Whether the terminal must be cleared before the next frame.
    pub const fn take_full_redraw(&mut self) -> bool {
        std::mem::replace(&mut self.ctx.full_redraw, false)
    }

    /// Terminal resized.
    pub const fn on_resize(&mut self, columns: u16, rows: u16) {
        self.ctx.size = (columns, rows);
    }

    /// Terminal lost focus.
    pub fn on_focus_lost(&mut self) {
        if self.ctx.flags.has(Flags::FOCUS_LOCK) {
            self.lock(LockReason::Focus);
        }
    }

    /// A key event.
    pub fn on_key(&mut self, event: &KeyEvent) {
        if self.ctx.flags.has(Flags::TRACE) {
            eprintln!("key {:?} {:?}", event.kind, key_kind(event.code));
        }
        if event.kind == KeyEventKind::Release {
            self.on_release(event);
            return;
        }
        self.ctx.idle.touch(self.ctx.now);
        if let Some(pending) = self.ctx.pending {
            match resolve(Scope::Busy, event) {
                Some(Action::Back) if pending.task.cancellable() => {
                    self.ctx.pending = None;
                    self.ctx.toast(
                        Tone::Info,
                        "Cancelled. The result is discarded when it arrives.",
                    );
                }
                Some(Action::Quit) => self.quit(),
                _ => {}
            }
            return;
        }
        if let Some(overlay) = self.overlay.as_mut() {
            match overlay {
                Overlay::Palette(palette) => match palette.on_key(event) {
                    PaletteEvent::Stay => {}
                    PaletteEvent::Close => self.overlay = None,
                    PaletteEvent::Run(action) => {
                        self.overlay = None;
                        self.on_action(action);
                    }
                },
                Overlay::Help(scroll) => match resolve(Scope::Help, event) {
                    Some(Action::Up) => *scroll = scroll.saturating_sub(1),
                    Some(Action::Down) => *scroll = scroll.saturating_add(1),
                    Some(Action::PageUp) => *scroll = scroll.saturating_sub(10),
                    Some(Action::PageDown) => *scroll = scroll.saturating_add(10),
                    Some(Action::Back) => self.overlay = None,
                    Some(Action::Quit) => self.quit(),
                    _ => {}
                },
            }
            return;
        }
        if let Screen::Locked(locked) = &mut self.screen {
            if resolve(Scope::Global, event) == Some(Action::Quit) {
                self.quit();
            } else {
                let nav = locked.resume();
                self.apply(nav);
            }
            return;
        }
        let scope = self.screen.scope();
        if let Some(action) = resolve(scope, event).filter(|action| app_level(*action)) {
            self.on_action(action);
            return;
        }
        let nav = match &mut self.screen {
            Screen::Welcome(state) => resolve(Scope::Welcome, event)
                .map_or(Nav::Stay, |action| state.on_action(action, &mut self.ctx)),
            Screen::Create(state) => state.on_key(event, &mut self.ctx),
            Screen::Restore(state) => state.on_key(event, &mut self.ctx),
            Screen::Import(state) => {
                let source = state.source();
                let event = state.on_key(event, &mut self.ctx);
                flows::import::new_vault_nav(event, source, &mut self.ctx)
            }
            Screen::Unlock(state) => state.on_key(event, &mut self.ctx),
            Screen::Unlocked(state) => state.on_key(event, &mut self.ctx),
            Screen::Alert(state) => resolve(Scope::Alert, event)
                .map_or(Nav::Stay, |action| state.on_action(action, &mut self.ctx)),
            Screen::Locked(_) => Nav::Stay,
        };
        self.apply(nav);
    }

    fn on_release(&mut self, event: &KeyEvent) {
        match &mut self.screen {
            Screen::Create(state) => state.on_release(event, &mut self.ctx),
            Screen::Unlocked(state) => state.on_release(event, &mut self.ctx),
            Screen::Welcome(_)
            | Screen::Restore(_)
            | Screen::Import(_)
            | Screen::Unlock(_)
            | Screen::Alert(_)
            | Screen::Locked(_) => {}
        }
    }

    /// Pasted text (bracketed paste). The caller wipes its copy afterwards.
    pub fn on_paste(&mut self, text: &str) {
        self.ctx.idle.touch(self.ctx.now);
        if self.ctx.busy() {
            return;
        }
        if let Some(Overlay::Palette(palette)) = self.overlay.as_mut() {
            palette.query.insert_str(text);
            return;
        }
        match &mut self.screen {
            Screen::Create(state) => state.on_paste(text),
            Screen::Restore(state) => state.on_paste(text),
            Screen::Import(state) => state.on_paste(text),
            Screen::Unlock(state) => state.on_paste(text),
            Screen::Unlocked(state) => state.on_paste(text, &mut self.ctx),
            Screen::Welcome(_) | Screen::Alert(_) | Screen::Locked(_) => {}
        }
    }

    /// Run an action, from a key or the palette.
    pub fn on_action(&mut self, action: Action) {
        match action {
            Action::Help => self.overlay = Some(Overlay::Help(0)),
            Action::Palette => self.overlay = Some(Overlay::Palette(PaletteState::default())),
            Action::Quit => self.quit(),
            Action::Lock => self.lock(LockReason::Manual),
            Action::CycleTheme => self.ctx.cycle_theme(),
            Action::ToggleAnimation => self.ctx.toggle_flag(Flags::ANIM),
            Action::ToggleAscii => self.ctx.toggle_flag(Flags::ASCII),
            Action::CreateVault => {
                self.close_vault();
                self.screen = Screen::Create(Box::new(CreateState::new(&mut self.ctx)));
            }
            Action::RestoreVault => {
                if let Screen::Alert(state) = &mut self.screen {
                    let nav = state.on_action(action, &mut self.ctx);
                    self.apply(nav);
                    return;
                }
                self.close_vault();
                self.screen = Screen::Import(Box::new(ImportState::new(Target::NewVault)));
            }
            other => {
                let nav = match &mut self.screen {
                    Screen::Unlocked(state) if state.vault.is_some() => {
                        flows::home_keys::on_action(state, other, &mut self.ctx)
                    }
                    Screen::Welcome(state) => state.on_action(other, &mut self.ctx),
                    Screen::Unlock(state) => state.on_action(other, &mut self.ctx),
                    Screen::Create(state) => state.on_action(other, &mut self.ctx),
                    Screen::Alert(state) => state.on_action(other, &mut self.ctx),
                    Screen::Unlocked(_)
                    | Screen::Restore(_)
                    | Screen::Import(_)
                    | Screen::Locked(_) => {
                        self.ctx.toast(Tone::Info, "Not available on this screen.");
                        Nav::Stay
                    }
                };
                self.apply(nav);
            }
        }
    }

    fn apply(&mut self, nav: Nav) {
        match nav {
            Nav::Stay => {}
            Nav::To(screen) => {
                self.screen = screen;
                self.ctx.redraw();
            }
            Nav::Lock => self.lock(LockReason::Manual),
            Nav::Quit => self.quit(),
        }
    }

    /// Drop every secret the current screen holds (session, caches, typed
    /// input, phrases) and show the locked overlay.
    pub fn lock(&mut self, reason: LockReason) {
        let (vaults, current) = match &mut self.screen {
            Screen::Unlocked(state) => (std::mem::take(&mut state.vaults), state.current),
            Screen::Unlock(state) => (std::mem::take(&mut state.vaults), state.current),
            Screen::Welcome(_) | Screen::Alert(_) | Screen::Locked(_) => return,
            Screen::Create(_) | Screen::Restore(_) | Screen::Import(_) => {
                (discover(&self.ctx.base), 0)
            }
        };
        self.overlay = None;
        self.ctx.pending = None;
        self.screen = Screen::Locked(Box::new(LockedState {
            reason,
            vaults,
            current,
        }));
        self.ctx.clipboard.clear_if_armed();
        self.ctx.redraw();
    }

    fn close_vault(&mut self) {
        if matches!(self.screen, Screen::Unlocked(_)) {
            self.lock(LockReason::Manual);
        }
    }

    /// Lock, clear the clipboard, and exit.
    pub fn quit(&mut self) {
        self.lock(LockReason::Manual);
        self.ctx.clipboard.clear_if_armed();
        self.quit = true;
    }

    /// Advance timers and collect worker results.
    pub fn on_tick(&mut self, now: Instant) {
        self.ctx.now = now;
        self.ctx.tick = self.ctx.tick.wrapping_add(1);
        while let Some((ticket, result)) = self.ctx.worker.try_recv() {
            self.on_job(ticket, result);
        }
        self.ctx.toasts.tick(now);
        self.ctx.clipboard.tick(now);
        let unlocked = matches!(&self.screen, Screen::Unlocked(state) if state.vault.is_some());
        if unlocked && !self.ctx.busy() && self.ctx.idle.expired(now) {
            let after = self.ctx.idle.after();
            self.lock(LockReason::Idle(after));
            return;
        }
        let nav = match &mut self.screen {
            Screen::Unlocked(state) => state.on_tick(&mut self.ctx),
            Screen::Unlock(state) => {
                if state.reveal.tick(now, self.ctx.reveal_after) {
                    self.ctx.redraw();
                }
                Nav::Stay
            }
            Screen::Create(state) => {
                let after = self.ctx.reveal_after;
                if state.ceremony.reveal.tick(now, after) || state.enroll.reveal.tick(now, after) {
                    self.ctx.redraw();
                }
                Nav::Stay
            }
            Screen::Restore(state) => {
                let after = self.ctx.reveal_after;
                if state.reveal.tick(now, after) || state.enroll.reveal.tick(now, after) {
                    self.ctx.redraw();
                }
                Nav::Stay
            }
            Screen::Import(state) => {
                if state.reveal.tick(now, self.ctx.reveal_after) {
                    self.ctx.redraw();
                }
                Nav::Stay
            }
            Screen::Welcome(_) | Screen::Alert(_) | Screen::Locked(_) => Nav::Stay,
        };
        self.apply(nav);
    }

    /// Wait up to `timeout` for one worker result (tests and headless use).
    pub fn wait_for_job(&mut self, timeout: Duration) -> bool {
        match self.ctx.worker.recv_timeout(timeout) {
            Some((ticket, result)) => {
                self.on_job(ticket, result);
                true
            }
            None => false,
        }
    }

    fn on_job(&mut self, ticket: u64, result: JobResult) {
        if let JobResult::Bench(time) = result {
            self.ctx.kdf_fast = time;
            return;
        }
        let waited = self
            .ctx
            .pending
            .is_some_and(|pending| pending.ticket == ticket);
        if waited {
            self.ctx.pending = None;
        }
        match (result, &mut self.screen) {
            (JobResult::Vault(vault, outcome), Screen::Unlocked(state))
                if state.vault.is_none() =>
            {
                state.on_result(vault, outcome, &mut self.ctx);
            }
            (JobResult::Opened(outcome), Screen::Unlock(state)) if waited => match outcome {
                Ok(vault) => {
                    if let Some(prefs) = vault.meta.prefs.as_ref() {
                        self.ctx.apply_prefs(prefs);
                    }
                    let vaults = std::mem::take(&mut state.vaults);
                    let current = state.current;
                    self.screen = Screen::Unlocked(Box::new(Unlocked::new(vault, vaults, current)));
                    self.ctx.idle.touch(self.ctx.now);
                    self.ctx.redraw();
                }
                Err(
                    error @ (UnlockError::Rollback { .. }
                    | UnlockError::Conflict { .. }
                    | UnlockError::MetaMissing),
                ) => {
                    if let Some(vault) = state.vault().cloned() {
                        self.screen = Screen::Alert(Box::new(AlertState::new(error, vault)));
                        self.ctx.redraw();
                    }
                }
                Err(error) => state.failed(error, self.ctx.now),
            },
            (JobResult::ImportParsed(outcome), Screen::Import(state)) if waited => {
                state.parsed(outcome, &mut self.ctx);
            }
            (JobResult::ImportParsed(outcome), Screen::Unlocked(state)) if waited => {
                if let View::Import(import) = &mut state.view {
                    import.parsed(outcome, &mut self.ctx);
                }
            }
            (JobResult::Created(outcome), Screen::Create(state)) if waited => match outcome {
                Ok(vault) => {
                    let message = state.imported.map_or_else(
                        || String::from(
                            "Vault created. Your recovery phrase is the only way back in: keep it safe.",
                        ),
                        |(count, source)| format!(
                            "Vault created with {count} records from {source}. Delete the export \
                             file now: it holds your passwords in plain text.",
                        ),
                    );
                    self.opened(vault, &message);
                }
                Err(message) => state.failed(&message, &mut self.ctx),
            },
            (JobResult::Restored(outcome), Screen::Restore(state)) if waited => match outcome {
                Ok(vault) => self.opened(vault, "Vault restored on this device."),
                Err(UnlockError::Io) => {
                    state.failed("Couldn't write the restored vault on this device.");
                }
                Err(_) => state.failed("Couldn't unlock that vault file with this phrase."),
            },
            // Anything else was cancelled or outlived its screen: dropping it
            // here wipes whatever it carries.
            (_, _) => {}
        }
    }

    fn opened(&mut self, vault: Box<crate::vault::Vault>, message: &str) {
        let vaults = discover(&self.ctx.base);
        let current = vaults
            .iter()
            .position(|known| known.vault_id.as_ref() == Some(vault.session.vault_id()))
            .unwrap_or(0);
        if let Some(prefs) = vault.meta.prefs.as_ref() {
            self.ctx.apply_prefs(prefs);
        }
        self.screen = Screen::Unlocked(Box::new(Unlocked::new(vault, vaults, current)));
        self.ctx.idle.touch(self.ctx.now);
        self.ctx.toast(Tone::Success, message.to_owned());
        self.ctx.redraw();
    }

    /// Draw the current state. Pure: no IO, no state change.
    pub fn view(&self, frame: &mut Frame<'_>) {
        crate::ui::screens::draw(frame, self);
    }
}

/// Key kind for `--trace-events`: never the character itself.
const fn key_kind(code: KeyCode) -> &'static str {
    match code {
        KeyCode::Char(_) => "char",
        KeyCode::Enter => "enter",
        KeyCode::Esc => "esc",
        KeyCode::Tab | KeyCode::BackTab => "tab",
        KeyCode::Backspace | KeyCode::Delete => "delete",
        KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => "arrow",
        _ => "other",
    }
}
