//! The binding table itself, kept apart from the lookup code.

use crossterm::event::KeyCode;

use super::{ch, ctrl, key, Binding, Scope};
use crate::app::action::Action;

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

    Ceremony: key(KeyCode::Tab) => NextField, "focus";
    Ceremony: key(KeyCode::BackTab) => PrevField;
    Ceremony: ch(' ') => Reveal, "reveal / tick";
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
    Verify: key(KeyCode::Tab) => NextField, "skip button";
    Verify: key(KeyCode::BackTab) => PrevField;
    Verify: ch('s') => Skip, "skip";

    Import: key(KeyCode::Up) => Up, "choose";
    Import: key(KeyCode::Down) => Down;
    Import: key(KeyCode::Enter) => Confirm, "next";
    Import: key(KeyCode::Esc) => Back, "back";

    ImportFile: key(KeyCode::Enter) => Confirm, "read file";
    ImportFile: key(KeyCode::Esc) => Back, "back";

    ImportPreview: key(KeyCode::Up) => Up, "move";
    ImportPreview: key(KeyCode::Down) => Down;
    ImportPreview: key(KeyCode::PageUp) => PageUp;
    ImportPreview: key(KeyCode::PageDown) => PageDown;
    ImportPreview: key(KeyCode::Home) => Top;
    ImportPreview: key(KeyCode::End) => Bottom;
    ImportPreview: ch(' ') => ToggleInclude, "include";
    ImportPreview: ch('a') => ToggleAll, "all";
    ImportPreview: key(KeyCode::Enter) => Confirm, "create vault";
    ImportPreview: key(KeyCode::Esc) => Back, "back";

    Restore: key(KeyCode::Tab) => AcceptSuggestion, "accept / next field";
    Restore: key(KeyCode::BackTab) => PrevField;
    Restore: ch(' ') => NextWord, "next word";
    Restore: ctrl('r') => RevealWord, "reveal last";
    Restore: ctrl('e') => HideWord, "hide current";
    Restore: key(KeyCode::Down) => NextField, "field";
    Restore: key(KeyCode::Up) => PrevField;
    Restore: key(KeyCode::Enter) => Confirm, "continue";
    Restore: key(KeyCode::Esc) => Back, "back";

    Enroll: key(KeyCode::Left) => Left, "factor";
    Enroll: key(KeyCode::Right) => Right;
    Enroll: key(KeyCode::Up) => Up, "field";
    Enroll: key(KeyCode::Down) => Down;
    Enroll: key(KeyCode::Tab) => NextField;
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
    Home: ch(',') => OpenSettings, "settings";
    Home: ch('L') => Lock, "lock";
    Home: ch('?') => Help, "help";
    Home: ch('q') => Quit, "quit";
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
    Settings: key(KeyCode::Tab) => NextField, "section";
    Settings: key(KeyCode::BackTab) => PrevField;
    Settings: key(KeyCode::Enter) => Confirm, "change";
    Settings: ctrl('s') => Save, "apply";
    Settings: ch('/') => Search, "search";
    Settings: ch('r') => ResetSetting, "reset";
    Settings: ch('R') => ResetSection;
    Settings: ch('?') => Help;
    Settings: key(KeyCode::Esc) => Back, "close";

    SettingsEdit: key(KeyCode::Enter) => Confirm, "keep";
    SettingsEdit: key(KeyCode::Esc) => Back, "cancel";

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
