//! The one key table. The event handler resolves keys through it, the hint
//! bars and the help screen are generated from it, so the documentation
//! cannot drift from the bindings.

use std::borrow::Cow;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::action::Action;

/// Where a binding applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Everywhere, after the screen's own scope.
    Global,
    /// First-run choice.
    Welcome,
    /// New vault: name, cost, cipher.
    Setup,
    /// Showing the recovery phrase.
    Ceremony,
    /// Proving the phrase was saved.
    Verify,
    /// Typing a phrase.
    Restore,
    /// Choosing how to restore or what to import.
    Import,
    /// Typing the export file path.
    ImportFile,
    /// Reviewing what will be imported.
    ImportPreview,
    /// Choosing this device's factor.
    Enroll,
    /// Unlock screen.
    Unlock,
    /// A long operation is running.
    Busy,
    /// Security alert.
    Alert,
    /// Locked overlay.
    Locked,
    /// Vault home.
    Home,
    /// Typing a search.
    Search,
    /// Record editor.
    Editor,
    /// Password generator.
    Generator,
    /// Factors (constellation).
    Factors,
    /// Devices.
    Devices,
    /// Sync.
    Sync,
    /// Health.
    Health,
    /// History.
    History,
    /// Settings.
    Settings,
    /// Editing a text setting.
    SettingsEdit,
    /// A dialog.
    Dialog,
    /// Command palette.
    Palette,
    /// Help screen.
    Help,
}

impl Scope {
    /// Help-screen heading.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Global => "Everywhere",
            Self::Welcome => "Welcome",
            Self::Setup => "New vault",
            Self::Ceremony => "Recovery phrase",
            Self::Verify => "Verify phrase",
            Self::Restore => "Restore",
            Self::Import => "Restore or import",
            Self::ImportFile => "Import file",
            Self::ImportPreview => "Import preview",
            Self::Enroll => "Unlock factor",
            Self::Unlock => "Unlock",
            Self::Busy => "Working",
            Self::Alert => "Security alert",
            Self::Locked => "Locked",
            Self::Home => "Vault",
            Self::Search => "Search",
            Self::Editor => "Editor",
            Self::Generator => "Generator",
            Self::Factors => "Factors",
            Self::Devices => "Devices",
            Self::Sync => "Sync",
            Self::Health => "Health",
            Self::History => "History",
            Self::Settings => "Settings",
            Self::SettingsEdit => "Settings text",
            Self::Dialog => "Dialogs",
            Self::Palette => "Command palette",
            Self::Help => "Help",
        }
    }
}

/// A key chord: a code plus whether Ctrl is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    /// Key code; letters are case-sensitive.
    pub code: KeyCode,
    /// Ctrl held.
    pub ctrl: bool,
}

const fn ch(ch: char) -> Key {
    Key {
        code: KeyCode::Char(ch),
        ctrl: false,
    }
}

const fn ctrl(ch: char) -> Key {
    Key {
        code: KeyCode::Char(ch),
        ctrl: true,
    }
}

const fn key(code: KeyCode) -> Key {
    Key { code, ctrl: false }
}

/// One binding.
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    /// Scope.
    pub scope: Scope,
    /// Chord.
    pub key: Key,
    /// Action.
    pub action: Action,
    /// Short label for the hint bar; empty keeps it off the bar.
    pub hint: &'static str,
}

macro_rules! bindings {
    ($( $scope:ident : $key:expr => $action:ident $(, $hint:literal)? ; )*) => {
        &[ $( Binding {
            scope: Scope::$scope,
            key: $key,
            action: Action::$action,
            hint: bindings!(@hint $($hint)?),
        } ),* ]
    };
    (@hint $hint:literal) => { $hint };
    (@hint) => { "" };
}

mod table;

pub use table::KEYMAP;

impl Key {
    fn matches(self, event: &KeyEvent) -> bool {
        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
        if event.modifiers.contains(KeyModifiers::ALT) || ctrl != self.ctrl {
            return false;
        }
        match (self.code, event.code) {
            (KeyCode::Char(want), KeyCode::Char(got)) if self.ctrl => {
                want.eq_ignore_ascii_case(&got)
            }
            (want, got) => want == got,
        }
    }
}

/// The action `event` means in `scope`, falling back to `Global`.
#[must_use]
pub fn resolve(scope: Scope, event: &KeyEvent) -> Option<Action> {
    let find = |wanted: Scope| {
        KEYMAP
            .iter()
            .find(|binding| binding.scope == wanted && binding.key.matches(event))
            .map(|binding| binding.action)
    };
    find(scope).or_else(|| find(Scope::Global))
}

/// Bindings with a hint label in `scope`, in table order.
pub fn hints(scope: Scope) -> impl Iterator<Item = &'static Binding> {
    KEYMAP
        .iter()
        .filter(move |binding| binding.scope == scope && !binding.hint.is_empty())
}

/// All bindings of `scope`.
pub fn in_scope(scope: Scope) -> impl Iterator<Item = &'static Binding> {
    KEYMAP.iter().filter(move |binding| binding.scope == scope)
}

/// Every scope, in help-screen order.
pub const SCOPES: [Scope; 28] = [
    Scope::Global,
    Scope::Home,
    Scope::Search,
    Scope::Editor,
    Scope::Generator,
    Scope::Factors,
    Scope::Devices,
    Scope::Sync,
    Scope::Health,
    Scope::History,
    Scope::Settings,
    Scope::SettingsEdit,
    Scope::Dialog,
    Scope::Palette,
    Scope::Unlock,
    Scope::Welcome,
    Scope::Setup,
    Scope::Ceremony,
    Scope::Verify,
    Scope::Import,
    Scope::ImportFile,
    Scope::ImportPreview,
    Scope::Restore,
    Scope::Enroll,
    Scope::Busy,
    Scope::Alert,
    Scope::Locked,
    Scope::Help,
];

/// Display label of a chord, e.g. `Ctrl-K`, `Enter`, `Space`.
#[must_use]
pub fn label(key: Key, ascii: bool) -> Cow<'static, str> {
    let base: Cow<'static, str> = match key.code {
        KeyCode::Char(' ') => "Space".into(),
        KeyCode::Char(ch) if key.ctrl => ch.to_ascii_uppercase().to_string().into(),
        KeyCode::Char(ch) => ch.to_string().into(),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::BackTab => "Shift-Tab".into(),
        KeyCode::Backspace => {
            if ascii {
                "Bksp".into()
            } else {
                "⌫".into()
            }
        }
        KeyCode::Delete => "Del".into(),
        KeyCode::Up => {
            if ascii {
                "Up".into()
            } else {
                "↑".into()
            }
        }
        KeyCode::Down => {
            if ascii {
                "Down".into()
            } else {
                "↓".into()
            }
        }
        KeyCode::Left => {
            if ascii {
                "Left".into()
            } else {
                "←".into()
            }
        }
        KeyCode::Right => {
            if ascii {
                "Right".into()
            } else {
                "→".into()
            }
        }
        KeyCode::PageUp => "PgUp".into(),
        KeyCode::PageDown => "PgDn".into(),
        KeyCode::Home => "Home".into(),
        KeyCode::End => "End".into(),
        _ => "?".into(),
    };
    if key.ctrl {
        format!("Ctrl-{base}").into()
    } else {
        base
    }
}
