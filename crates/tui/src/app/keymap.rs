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

/// Every binding. The first match in a scope wins; `Global` is searched
/// after the screen's own scope.
pub const KEYMAP: &[Binding] = bindings! {
    Global: ctrl('k') => Palette, "palette";
    Global: ctrl('c') => Quit;
    Global: ctrl('q') => Quit;
    Global: ctrl('z') => Lock;

    Welcome: key(KeyCode::Left) => Left, "choose";
    Welcome: key(KeyCode::Right) => Right;
    Welcome: key(KeyCode::Tab) => Right;
    Welcome: key(KeyCode::Enter) => Confirm, "select";
    Welcome: ch('?') => Help, "help";
    Welcome: ch('q') => Quit, "quit";

    Setup: key(KeyCode::Tab) => NextField, "next field";
    Setup: key(KeyCode::BackTab) => PrevField;
    Setup: key(KeyCode::Up) => Up, "choose";
    Setup: key(KeyCode::Down) => Down;
    Setup: key(KeyCode::Enter) => Confirm, "continue";
    Setup: key(KeyCode::Esc) => Back, "back";

    Ceremony: ch(' ') => Reveal, "reveal row";
    Ceremony: key(KeyCode::Up) => Up, "row";
    Ceremony: key(KeyCode::Down) => Down;
    Ceremony: ch('x') => ToggleWritten, "written";
    Ceremony: key(KeyCode::Enter) => Confirm, "continue";
    Ceremony: key(KeyCode::Esc) => Back, "cancel vault";

    Verify: key(KeyCode::Up) => Up, "pick";
    Verify: key(KeyCode::Down) => Down;
    Verify: key(KeyCode::Left) => Left, "card";
    Verify: key(KeyCode::Right) => Right;
    Verify: key(KeyCode::Enter) => Confirm, "confirm";
    Verify: key(KeyCode::Esc) => Back, "back to phrase";

    Restore: key(KeyCode::Tab) => AcceptSuggestion, "accept";
    Restore: ch(' ') => NextWord, "next word";
    Restore: ctrl('r') => RevealWord, "reveal last";
    Restore: ctrl('h') => HideWord, "hide current";
    Restore: key(KeyCode::Down) => NextField, "field";
    Restore: key(KeyCode::Up) => PrevField;
    Restore: key(KeyCode::Enter) => Confirm, "restore";
    Restore: key(KeyCode::Esc) => Back, "back";

    Enroll: key(KeyCode::Left) => Left, "factor";
    Enroll: key(KeyCode::Right) => Right;
    Enroll: key(KeyCode::Tab) => NextField, "field";
    Enroll: key(KeyCode::BackTab) => PrevField;
    Enroll: ctrl('g') => GeneratePassphrase, "generate";
    Enroll: ctrl('r') => RevealField, "reveal";
    Enroll: key(KeyCode::Enter) => Confirm, "enroll";
    Enroll: key(KeyCode::Esc) => Back, "back";

    Unlock: key(KeyCode::Enter) => Confirm, "unlock";
    Unlock: key(KeyCode::Tab) => SwitchFactor, "factor";
    Unlock: ctrl('p') => UseRecovery, "recovery phrase";
    Unlock: ctrl('v') => SwitchVault, "vault";
    Unlock: ctrl('r') => RevealField, "reveal";
    Unlock: ctrl('n') => CreateVault, "new vault";
    Unlock: ctrl('o') => RestoreVault, "restore";
    Unlock: key(KeyCode::Up) => Up;
    Unlock: key(KeyCode::Down) => Down;
    Unlock: key(KeyCode::Esc) => Back, "clear";
    Unlock: ctrl('q') => Quit, "quit";

    Busy: key(KeyCode::Esc) => Back, "cancel";

    Alert: key(KeyCode::Left) => Left, "choose";
    Alert: key(KeyCode::Right) => Right;
    Alert: key(KeyCode::Enter) => Confirm, "select";
    Alert: ch('l') => ShowLocation, "file location";
    Alert: ch('r') => RestoreVault, "restore from phrase";
    Alert: ch('q') => Quit, "quit";

    Locked: key(KeyCode::Enter) => Confirm, "unlock";

    Home: ch('/') => Search, "search";
    Home: key(KeyCode::Up) => Up, "move";
    Home: key(KeyCode::Down) => Down;
    Home: ch('k') => Up;
    Home: ch('j') => Down;
    Home: key(KeyCode::PageUp) => PageUp;
    Home: key(KeyCode::PageDown) => PageDown;
    Home: key(KeyCode::Home) => Top;
    Home: key(KeyCode::End) => Bottom;
    Home: key(KeyCode::Enter) => Confirm, "open";
    Home: key(KeyCode::Tab) => NextField, "pane";
    Home: key(KeyCode::BackTab) => PrevField;
    Home: key(KeyCode::Left) => PrevField;
    Home: key(KeyCode::Right) => NextField;
    Home: ch('c') => CopyPassword, "copy pw";
    Home: ch('u') => CopyUsername, "user";
    Home: ch('e') => CopyEmail;
    Home: ch('t') => CopyTotp;
    Home: ch('o') => ShowUrl;
    Home: ch(' ') => Reveal, "reveal";
    Home: ch('n') => NewRecord, "new";
    Home: ch('E') => EditRecord, "edit";
    Home: ch('d') => DeleteRecord, "delete";
    Home: ch('*') => ToggleFavorite;
    Home: ch('g') => OpenGenerator, "gen";
    Home: ch('h') => OpenHistory;
    Home: ch('F') => OpenFactors;
    Home: ch('D') => OpenDevices;
    Home: ch('S') => OpenSync;
    Home: ch('H') => OpenHealth;
    Home: ch(',') => OpenSettings;
    Home: ch('L') => Lock, "lock";
    Home: ch('?') => Help, "help";
    Home: ch('q') => Quit;
    Home: key(KeyCode::Esc) => Back;

    Search: key(KeyCode::Esc) => Back, "clear";
    Search: key(KeyCode::Enter) => Confirm, "done";
    Search: key(KeyCode::Up) => Up, "move";
    Search: key(KeyCode::Down) => Down;

    Editor: key(KeyCode::Tab) => NextField, "next";
    Editor: key(KeyCode::BackTab) => PrevField, "prev";
    Editor: key(KeyCode::Down) => NextField;
    Editor: key(KeyCode::Up) => PrevField;
    Editor: ctrl('s') => Save, "save";
    Editor: ctrl('r') => RevealField, "reveal";
    Editor: ctrl('g') => GenerateInto, "generate";
    Editor: ctrl('n') => AddField, "add field";
    Editor: ctrl('d') => RemoveField, "remove field";
    Editor: key(KeyCode::Esc) => Back, "discard";

    Generator: key(KeyCode::Left) => Left, "length";
    Generator: key(KeyCode::Right) => Right;
    Generator: ch('1') => ToggleLower, "sets";
    Generator: ch('2') => ToggleUpper;
    Generator: ch('3') => ToggleDigits;
    Generator: ch('4') => ToggleSymbols;
    Generator: ch('5') => ToggleLookalike;
    Generator: key(KeyCode::Tab) => NextMode, "mode";
    Generator: ch('r') => Reroll, "reroll";
    Generator: ch('c') => CopyGenerated, "copy";
    Generator: key(KeyCode::Enter) => Confirm, "use";
    Generator: key(KeyCode::Esc) => Back, "close";

    Factors: key(KeyCode::Up) => Up, "select";
    Factors: key(KeyCode::Down) => Down;
    Factors: key(KeyCode::Enter) => Confirm, "act";
    Factors: ch('a') => AddFactor, "add";
    Factors: ch('r') => RevokeFactor, "revoke+rotate";
    Factors: key(KeyCode::Backspace) => RemoveFactor, "remove";
    Factors: key(KeyCode::Delete) => RemoveFactor;
    Factors: ch('?') => Help;
    Factors: key(KeyCode::Esc) => Back, "back";

    Devices: key(KeyCode::Up) => Up, "select";
    Devices: key(KeyCode::Down) => Down;
    Devices: key(KeyCode::Enter) => Confirm, "details";
    Devices: ch('r') => RevokeFactor, "revoke";
    Devices: ch('n') => EnrollDevice, "enroll new device";
    Devices: ch('?') => Help;
    Devices: key(KeyCode::Esc) => Back, "back";

    Sync: ch('x') => ExportFrames, "export";
    Sync: ch('X') => ExportAll, "export all";
    Sync: ch('i') => ImportFrames, "import";
    Sync: key(KeyCode::Up) => Up;
    Sync: key(KeyCode::Down) => Down;
    Sync: ch('?') => Help;
    Sync: key(KeyCode::Esc) => Back, "back";

    Health: key(KeyCode::Up) => Up;
    Health: key(KeyCode::Down) => Down;
    Health: key(KeyCode::Enter) => Confirm, "review";
    Health: ch('g') => Regenerate, "regenerate";
    Health: ch('?') => Help;
    Health: key(KeyCode::Esc) => Back, "back";

    History: key(KeyCode::Up) => Up;
    History: key(KeyCode::Down) => Down;
    History: key(KeyCode::Enter) => Confirm, "view (masked)";
    History: ch('R') => RestoreRevision, "restore revision";
    History: ch('?') => Help;
    History: key(KeyCode::Esc) => Back, "back";

    Settings: key(KeyCode::Up) => Up, "select";
    Settings: key(KeyCode::Down) => Down;
    Settings: key(KeyCode::Left) => Left, "adjust";
    Settings: key(KeyCode::Right) => Right;
    Settings: key(KeyCode::Enter) => Confirm, "change";
    Settings: ch('?') => Help;
    Settings: key(KeyCode::Esc) => Back, "back";

    Dialog: key(KeyCode::Enter) => Confirm, "confirm";
    Dialog: key(KeyCode::Esc) => Back, "cancel";
    Dialog: key(KeyCode::Tab) => NextField, "field";
    Dialog: key(KeyCode::BackTab) => PrevField;
    Dialog: key(KeyCode::Down) => NextField;
    Dialog: key(KeyCode::Up) => PrevField;
    Dialog: key(KeyCode::Left) => Left;
    Dialog: key(KeyCode::Right) => Right;
    Dialog: ch(' ') => NextWord;
    Dialog: ctrl('r') => RevealField, "reveal";

    Palette: key(KeyCode::Up) => Up, "move";
    Palette: key(KeyCode::Down) => Down;
    Palette: key(KeyCode::Enter) => Confirm, "run";
    Palette: key(KeyCode::Esc) => Back, "close";

    Help: key(KeyCode::Up) => Up, "scroll";
    Help: key(KeyCode::Down) => Down;
    Help: key(KeyCode::PageUp) => PageUp;
    Help: key(KeyCode::PageDown) => PageDown;
    Help: key(KeyCode::Esc) => Back, "close";
    Help: ch('?') => Back;
    Help: ch('q') => Back;
};

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
pub const SCOPES: [Scope; 24] = [
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
    Scope::Dialog,
    Scope::Palette,
    Scope::Unlock,
    Scope::Welcome,
    Scope::Setup,
    Scope::Ceremony,
    Scope::Verify,
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
