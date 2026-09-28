//! The settings table: every row, the section it lives in, what it says
//! about itself, and how it changes a draft of the preferences.

use local::{Prefs, SyncMode, CLIP_CLEAR_S, LOCK_AFTER_S, REVEAL_HIDE_S};

use crate::app::prefs::theme_of;
use crate::ui::theme::ThemeName;

/// A group of rows on the rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// Locking and revealing.
    Security,
    /// This device's factor.
    Device,
    /// The sync server (not built yet).
    Sync,
    /// Clipboard hygiene.
    Clipboard,
    /// Look and motion.
    Appearance,
    /// Facts about the vault.
    Vault,
    /// Irreversible actions.
    Danger,
    /// Version, paths, primitives.
    About,
}

impl Section {
    /// Sections in rail order.
    pub const ALL: [Self; 8] = [
        Self::Security,
        Self::Device,
        Self::Sync,
        Self::Clipboard,
        Self::Appearance,
        Self::Vault,
        Self::Danger,
        Self::About,
    ];

    /// Rail label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::Device => "This device",
            Self::Sync => "Sync",
            Self::Clipboard => "Clipboard",
            Self::Appearance => "Appearance",
            Self::Vault => "Vault",
            Self::Danger => "Danger zone",
            Self::About => "About",
        }
    }
}

/// One setting or fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// Auto-lock delay.
    AutoLock,
    /// Lock on focus loss.
    FocusLock,
    /// Reveal auto-hide delay.
    RevealHide,
    /// Password wrap cost; opens the password form.
    PasswordCost,
    /// Opens the factors view.
    Factors,
    /// Whether this device is enrolled; enrolls it.
    DeviceStatus,
    /// Fingerprint of this device's wrap.
    DeviceFingerprint,
    /// Device PIN cost; changes the PIN.
    DevicePin,
    /// Why there is no Secure Enclave here.
    SecureEnclave,
    /// Off, manual, or automatic sync.
    SyncMode,
    /// Sync server origin.
    ServerOrigin,
    /// Pinned server key.
    ServerPin,
    /// Account client id fingerprint.
    ClientId,
    /// Device certificate state.
    DeviceCert,
    /// Try the server.
    TestConnection,
    /// Clipboard clear delay.
    ClipClear,
    /// Lock always clears the clipboard.
    ClipOnLock,
    /// Color theme.
    Theme,
    /// Animations.
    Animation,
    /// ASCII glyphs.
    Ascii,
    /// Vault name; opens the rename form.
    Name,
    /// Record cipher.
    Cipher,
    /// Wrap directory generation.
    Generation,
    /// Record count.
    Records,
    /// Import records from another manager.
    Import,
    /// Vault file path.
    FilePath,
    /// Rotate the vault key.
    RotateKey,
    /// Revoke this device and rotate.
    ForgetDevice,
    /// Drop old revisions.
    ClearHistory,
    /// Build version.
    Version,
    /// Data directory.
    DataDir,
    /// Primitives in use.
    Primitives,
    /// The top security advice.
    Posture,
}

/// Every row with its section, in display order.
pub const ROWS: [(Section, Row); 33] = [
    (Section::Security, Row::AutoLock),
    (Section::Security, Row::FocusLock),
    (Section::Security, Row::RevealHide),
    (Section::Security, Row::PasswordCost),
    (Section::Security, Row::Factors),
    (Section::Device, Row::DeviceStatus),
    (Section::Device, Row::DeviceFingerprint),
    (Section::Device, Row::DevicePin),
    (Section::Device, Row::SecureEnclave),
    (Section::Sync, Row::SyncMode),
    (Section::Sync, Row::ServerOrigin),
    (Section::Sync, Row::ServerPin),
    (Section::Sync, Row::ClientId),
    (Section::Sync, Row::DeviceCert),
    (Section::Sync, Row::TestConnection),
    (Section::Clipboard, Row::ClipClear),
    (Section::Clipboard, Row::ClipOnLock),
    (Section::Appearance, Row::Theme),
    (Section::Appearance, Row::Animation),
    (Section::Appearance, Row::Ascii),
    (Section::Vault, Row::Name),
    (Section::Vault, Row::Cipher),
    (Section::Vault, Row::Generation),
    (Section::Vault, Row::Records),
    (Section::Vault, Row::Import),
    (Section::Vault, Row::FilePath),
    (Section::Danger, Row::RotateKey),
    (Section::Danger, Row::ForgetDevice),
    (Section::Danger, Row::ClearHistory),
    (Section::About, Row::Version),
    (Section::About, Row::DataDir),
    (Section::About, Row::Primitives),
    (Section::About, Row::Posture),
];

/// Auto-lock steps in seconds.
const LOCK_STEPS: [u16; 8] = [30, 60, 120, 300, 600, 900, 1800, 3600];

impl Row {
    /// Row label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AutoLock => "Auto-lock after",
            Self::FocusLock => "Lock on focus loss",
            Self::RevealHide => "Hide revealed secrets after",
            Self::PasswordCost => "Password",
            Self::Factors => "Unlock factors",
            Self::DeviceStatus => "This device",
            Self::DeviceFingerprint => "Device fingerprint",
            Self::DevicePin => "Device PIN",
            Self::SecureEnclave => "Secure Enclave",
            Self::SyncMode => "Sync",
            Self::ServerOrigin => "Server",
            Self::ServerPin => "Pinned server key",
            Self::ClientId => "Client id",
            Self::DeviceCert => "Device certificate",
            Self::TestConnection => "Test connection",
            Self::ClipClear => "Clear clipboard after",
            Self::ClipOnLock => "Clear clipboard on lock",
            Self::Theme => "Theme",
            Self::Animation => "Animations",
            Self::Ascii => "ASCII glyphs",
            Self::Name => "Name on this device",
            Self::Cipher => "Record cipher",
            Self::Generation => "Key generation",
            Self::Records => "Records",
            Self::Import => "Import records",
            Self::FilePath => "File",
            Self::RotateKey => "Rotate the vault key",
            Self::ForgetDevice => "Revoke this device",
            Self::ClearHistory => "Clear history",
            Self::Version => "Version",
            Self::DataDir => "Data directory",
            Self::Primitives => "Primitives",
            Self::Posture => "Next step",
        }
    }

    /// Why the row matters, shown under the list.
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::AutoLock => "Locks the vault and wipes its keys from memory after this much inactivity. Shorter is safer on a shared machine.",
            Self::FocusLock => "Locks the moment the terminal loses focus: switching windows is enough.",
            Self::RevealHide => "A revealed password hides itself again after this long, and the screen is repainted.",
            Self::PasswordCost => "Argon2id cost of the password wrap. Enter changes the password (or adds one).",
            Self::Factors => "Every way this vault can be opened, drawn as a constellation. Enter opens it.",
            Self::DeviceStatus => "P-256 + ML-KEM keys sealed in a file next to the vault under a PIN. They never leave this disk.",
            Self::DeviceFingerprint => "Compare this with the device list on another machine to know which wrap is which.",
            Self::DevicePin => "Argon2id stretches the PIN before it can open the key file. Enter changes the PIN; the vault is untouched.",
            Self::SecureEnclave => "Apple only lets signed apps use the Secure Enclave. A terminal app cannot, so the PIN file takes its place.",
            Self::SyncMode => "Saved now, used once the sync server exists. Every upload is signed with ML-DSA.",
            Self::ServerOrigin => "https://host[:port] only. Enter edits it; the client id is bound to the origin at first sync.",
            Self::ServerPin => "The server's key is pinned on first contact; a different key later is refused. r clears the pin.",
            Self::ClientId => "A one-way HKDF of the recovery seed. It names the account without revealing anything.",
            Self::DeviceCert => "The account key certifies each device's ML-DSA key so the server can check uploads.",
            Self::TestConnection => "Checks the server origin and its pinned key. Nothing is ever sent without a signature.",
            Self::ClipClear => "Copied secrets are wiped from the clipboard after this long.",
            Self::ClipOnLock => "Locking always clears a secret this app copied. This one is not optional.",
            Self::Theme => "Previewed live. Saved per vault; --no-color and NO_COLOR always win.",
            Self::Animation => "Reduced motion freezes every animation.",
            Self::Ascii => "Replaces Unicode symbols with plain ASCII for limited terminals.",
            Self::Name => "Stored on this device only, inside the encrypted local metadata.",
            Self::Cipher => "Each record is sealed on its own: AEGIS-256 inside Kuznyechik-CTR + HMAC, one key per layer.",
            Self::Generation => "Grows with every change to the wrap directory; an older file is refused as a rollback.",
            Self::Records => "Live records. Old revisions stay until history is cleared.",
            Self::Import => "Bitwarden, KeePass (.kdbx or XML), Enpass, or CSV. Records already here are skipped.",
            Self::FilePath => "Back this file up. Without the recovery phrase it is useless to anyone.",
            Self::RotateKey => "Draws a new vault key, re-seals every record, and re-wraps every factor. Needs the phrase.",
            Self::ForgetDevice => "Removes this device's wrap, rotates the vault key, and deletes the key file.",
            Self::ClearHistory => "Drops superseded revisions. The live record of each entry stays.",
            Self::Version => "This build and its features.",
            Self::DataDir => "Where every vault on this machine lives.",
            Self::Primitives => "Nothing here is hand-rolled: vetted implementations only.",
            Self::Posture => "The single change that would raise the posture score the most.",
        }
    }

    /// The section `self` belongs to.
    #[must_use]
    pub fn section(self) -> Section {
        ROWS.iter()
            .find(|(_, row)| *row == self)
            .map_or(Section::About, |(section, _)| *section)
    }

    /// Whether Left/Right or Enter change a draft value.
    #[must_use]
    pub const fn adjustable(self) -> bool {
        matches!(
            self,
            Self::AutoLock
                | Self::FocusLock
                | Self::RevealHide
                | Self::SyncMode
                | Self::ClipClear
                | Self::Theme
                | Self::Animation
                | Self::Ascii
        )
    }

    /// Move the draft value one step (`forward` or back).
    pub fn adjust(self, draft: &mut Prefs, forward: bool) {
        match self {
            Self::AutoLock => draft.lock_after_s = step(&LOCK_STEPS, draft.lock_after_s, forward),
            Self::FocusLock => draft.focus_lock = !draft.focus_lock,
            Self::RevealHide => {
                draft.reveal_hide_s = nudge(draft.reveal_hide_s, 1, forward, &REVEAL_HIDE_S);
            }
            Self::SyncMode => draft.sync_mode = cycle(&SyncMode::ALL, draft.sync_mode, forward),
            Self::ClipClear => {
                draft.clip_clear_s = nudge(draft.clip_clear_s, 5, forward, &CLIP_CLEAR_S);
            }
            Self::Theme => {
                let next = cycle(&ThemeName::ALL, theme_of(draft.theme), forward);
                draft.theme = u8::from(next);
            }
            Self::Animation => draft.anim = !draft.anim,
            Self::Ascii => draft.ascii = !draft.ascii,
            _ => {}
        }
    }

    /// Put the draft value back to its default.
    pub fn reset(self, draft: &mut Prefs) {
        let defaults = Prefs::default();
        match self {
            Self::AutoLock => draft.lock_after_s = defaults.lock_after_s,
            Self::FocusLock => draft.focus_lock = defaults.focus_lock,
            Self::RevealHide => draft.reveal_hide_s = defaults.reveal_hide_s,
            Self::SyncMode => draft.sync_mode = defaults.sync_mode,
            Self::ServerOrigin => draft.server_origin = defaults.server_origin,
            Self::ServerPin => draft.server_key_pin = defaults.server_key_pin,
            Self::ClipClear => draft.clip_clear_s = defaults.clip_clear_s,
            Self::Theme => draft.theme = defaults.theme,
            Self::Animation => draft.anim = defaults.anim,
            Self::Ascii => draft.ascii = defaults.ascii,
            _ => {}
        }
    }

    /// Whether the draft differs from `saved` in this row.
    #[must_use]
    pub fn changed(self, draft: &Prefs, saved: &Prefs) -> bool {
        match self {
            Self::AutoLock => draft.lock_after_s != saved.lock_after_s,
            Self::FocusLock => draft.focus_lock != saved.focus_lock,
            Self::RevealHide => draft.reveal_hide_s != saved.reveal_hide_s,
            Self::SyncMode => draft.sync_mode != saved.sync_mode,
            Self::ServerOrigin => draft.server_origin != saved.server_origin,
            Self::ServerPin => draft.server_key_pin != saved.server_key_pin,
            Self::ClipClear => draft.clip_clear_s != saved.clip_clear_s,
            Self::Theme => draft.theme != saved.theme,
            Self::Animation => draft.anim != saved.anim,
            Self::Ascii => draft.ascii != saved.ascii,
            _ => false,
        }
    }
}

/// Rows of `section`.
pub fn in_section(section: Section) -> impl Iterator<Item = Row> {
    ROWS.iter()
        .filter(move |(owner, _)| *owner == section)
        .map(|(_, row)| *row)
}

/// Rows whose label or explanation contains `query`, ignoring case.
pub fn matching(query: &str) -> impl Iterator<Item = Row> + '_ {
    let query = query.trim().to_ascii_lowercase();
    ROWS.iter().map(|(_, row)| *row).filter(move |row| {
        row.label().to_ascii_lowercase().contains(&query)
            || row.why().to_ascii_lowercase().contains(&query)
    })
}

/// Rows that differ between `draft` and `saved`.
pub fn changes<'a>(draft: &'a Prefs, saved: &'a Prefs) -> impl Iterator<Item = Row> + 'a {
    ROWS.iter()
        .map(|(_, row)| *row)
        .filter(move |row| row.changed(draft, saved))
}

fn step(steps: &[u16], value: u16, forward: bool) -> u16 {
    let clamped = value.clamp(*LOCK_AFTER_S.start(), *LOCK_AFTER_S.end());
    let next = if forward {
        steps.iter().find(|candidate| **candidate > clamped)
    } else {
        steps.iter().rev().find(|candidate| **candidate < clamped)
    };
    next.copied().unwrap_or(clamped)
}

fn nudge(value: u8, by: u8, forward: bool, range: &std::ops::RangeInclusive<u8>) -> u8 {
    let moved = if forward {
        value.saturating_add(by)
    } else {
        value.saturating_sub(by)
    };
    moved.clamp(*range.start(), *range.end())
}

fn cycle<T: Copy + PartialEq>(all: &[T], current: T, forward: bool) -> T {
    let len = all.len().max(1);
    let at = all.iter().position(|item| *item == current).unwrap_or(0);
    let next = if forward { at + 1 } else { at + len - 1 } % len;
    all.get(next).copied().unwrap_or(current)
}

#[cfg(test)]
mod tests {
    use local::Prefs;

    use super::{changes, in_section, matching, Row, Section, ROWS};

    #[test]
    fn every_section_has_rows_and_every_row_one_section() {
        for section in Section::ALL {
            assert!(in_section(section).count() > 0, "{section:?}");
        }
        for (section, row) in ROWS {
            assert_eq!(row.section(), section);
        }
    }

    #[test]
    fn adjust_walks_steps_and_stays_in_bounds() {
        let mut draft = Prefs::default();
        Row::AutoLock.adjust(&mut draft, true);
        assert_eq!(draft.lock_after_s, 600);
        for _ in 0..20 {
            Row::AutoLock.adjust(&mut draft, false);
        }
        assert_eq!(draft.lock_after_s, 30);
        for _ in 0..40 {
            Row::ClipClear.adjust(&mut draft, true);
        }
        assert_eq!(draft.clip_clear_s, 90);
        Row::Theme.adjust(&mut draft, false);
        assert_eq!(draft.theme, 2);
        assert_eq!(
            changes(&draft, &Prefs::default()).collect::<Vec<_>>(),
            [Row::AutoLock, Row::ClipClear, Row::Theme]
        );
        Row::ClipClear.reset(&mut draft);
        assert!(!Row::ClipClear.changed(&draft, &Prefs::default()));
    }

    #[test]
    fn search_matches_labels_and_explanations() {
        assert!(matching("PIN").any(|row| row == Row::DevicePin));
        assert!(matching("enclave").any(|row| row == Row::SecureEnclave));
        assert_eq!(matching("zzzz-nothing").count(), 0);
    }
}
