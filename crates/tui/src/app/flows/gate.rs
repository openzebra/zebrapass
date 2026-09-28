//! Small screens around the lock: welcome, security alert, locked overlay,
//! and the choice of which screen to start on.

use std::time::Duration;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::create::CreateState;
use crate::app::flows::restore::RestoreState;
use crate::app::flows::unlock::UnlockState;
use crate::app::screen::{Nav, Screen};
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::{discover, from_file, VaultRef};
use crate::vault::error::UnlockError;

/// The first screen: the explicit vault, the first known vault, or welcome.
#[must_use]
pub fn initial_screen(ctx: &mut Ctx) -> Screen {
    let vaults = ctx
        .vault_file
        .as_deref()
        .map_or_else(|| discover(&ctx.base), |file| vec![from_file(file)]);
    if vaults.is_empty() {
        Screen::Welcome(WelcomeState::default())
    } else {
        Screen::Unlock(Box::new(UnlockState::new(vaults, 0)))
    }
}

/// First-run choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WelcomeState {
    /// `false`: create, `true`: restore.
    pub restore: bool,
}

impl WelcomeState {
    /// Handle an action.
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Left | Action::Right => {
                self.restore = !self.restore;
                Nav::Stay
            }
            Action::Confirm if self.restore => {
                Nav::To(Screen::Restore(Box::new(RestoreState::new(None, ctx))))
            }
            Action::Confirm => Nav::To(Screen::Create(Box::new(CreateState::new(ctx)))),
            _ => Nav::Stay,
        }
    }
}

/// Security alert about the vault file.
#[derive(Debug)]
pub struct AlertState {
    /// What was detected: rollback, conflict, or a missing cursor.
    pub kind: UnlockError,
    /// The vault it concerns.
    pub vault: VaultRef,
    /// Focused button: 0 location, 1 restore, 2 quit.
    pub choice: u8,
    /// The file path is shown.
    pub show_location: bool,
}

impl AlertState {
    /// Alert for `kind` on `vault`.
    #[must_use]
    pub const fn new(kind: UnlockError, vault: VaultRef) -> Self {
        Self {
            kind,
            vault,
            choice: 0,
            show_location: false,
        }
    }

    /// Handle an action. There is deliberately no "open anyway".
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Left => self.choice = self.choice.saturating_sub(1),
            Action::Right => self.choice = (self.choice + 1).min(2),
            Action::ShowLocation => self.show_location = true,
            Action::RestoreVault => return self.restore(ctx),
            Action::Confirm => {
                return match self.choice {
                    0 => {
                        self.show_location = true;
                        Nav::Stay
                    }
                    1 => self.restore(ctx),
                    _ => Nav::Quit,
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn restore(&self, ctx: &mut Ctx) -> Nav {
        ctx.toast(
            Tone::Warn,
            "Restoring from the phrase replaces this device's rollback record.",
        );
        Nav::To(Screen::Restore(Box::new(RestoreState::new(
            Some(self.vault.paths.vault_file.clone()),
            ctx,
        ))))
    }
}

/// Why the vault locked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    /// Inactivity.
    Idle(Duration),
    /// The user asked.
    Manual,
    /// The terminal lost focus.
    Focus,
    /// Ctrl-Z.
    Suspend,
}

/// Locked overlay: keys are gone; any key goes to the unlock screen.
#[derive(Debug)]
pub struct LockedState {
    /// Why.
    pub reason: LockReason,
    /// Vaults for the unlock screen.
    pub vaults: Vec<VaultRef>,
    /// The vault that was open.
    pub current: usize,
}

impl LockedState {
    /// Any key: back to unlock.
    pub fn resume(&mut self) -> Nav {
        let vaults = std::mem::take(&mut self.vaults);
        if vaults.is_empty() {
            return Nav::To(Screen::Welcome(WelcomeState::default()));
        }
        Nav::To(Screen::Unlock(Box::new(UnlockState::new(
            vaults,
            self.current,
        ))))
    }
}
