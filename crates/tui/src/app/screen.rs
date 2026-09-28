//! The screen state machine. Each variant owns its state; variants that
//! hold secrets or large state are boxed to keep the enum small.
//!
//! `Unlocked` is the only variant that owns a session. Replacing it (lock,
//! quit) drops the session, the vault file, and every cache with it.

use crate::app::flows::create::CreateState;
use crate::app::flows::gate::{AlertState, LockedState, WelcomeState};
use crate::app::flows::restore::RestoreState;
use crate::app::flows::unlock::UnlockState;
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;

/// Current screen.
#[derive(Debug)]
pub enum Screen {
    /// No vault yet.
    Welcome(WelcomeState),
    /// New vault wizard.
    Create(Box<CreateState>),
    /// Restore from phrase.
    Restore(Box<RestoreState>),
    /// Unlock a vault.
    Unlock(Box<UnlockState>),
    /// The open vault.
    Unlocked(Box<Unlocked>),
    /// Security alert.
    Alert(Box<AlertState>),
    /// Locked overlay.
    Locked(Box<LockedState>),
}

impl Screen {
    /// Keymap scope of the screen's current focus.
    #[must_use]
    pub fn scope(&self) -> Scope {
        match self {
            Self::Welcome(_) => Scope::Welcome,
            Self::Create(state) => state.scope(),
            Self::Restore(state) => state.scope(),
            Self::Unlock(_) => Scope::Unlock,
            Self::Unlocked(state) => state.scope(),
            Self::Alert(_) => Scope::Alert,
            Self::Locked(_) => Scope::Locked,
        }
    }

    /// Short name, for tests and traces.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Welcome(_) => "welcome",
            Self::Create(_) => "create",
            Self::Restore(_) => "restore",
            Self::Unlock(_) => "unlock",
            Self::Unlocked(_) => "unlocked",
            Self::Alert(_) => "alert",
            Self::Locked(_) => "locked",
        }
    }
}

/// What a flow asks the app to do next.
#[derive(Debug)]
pub enum Nav {
    /// Nothing.
    Stay,
    /// Switch screens.
    To(Screen),
    /// Lock the vault.
    Lock,
    /// Quit (locks first).
    Quit,
}
