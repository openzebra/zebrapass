//! The settings table: every row, the section it lives in, what it says
//! about itself, and how it changes a draft of the preferences.

use local::{BACKUP_KEEP_MAX, CLIP_CLEAR_S, LOCK_AFTER_S, Prefs, REVEAL_HIDE_S};

use crate::app::prefs::theme_of;
use crate::ui::theme::ThemeName;

/// A group of rows on the rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// Locking and revealing.
    Security,
    /// This device's factor.
    Device,
    /// Peer-to-peer and HTTPS/WSS sync state of this vault.
    Sync,
    /// Local and encrypted remote backups.
    Backup,
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
    pub const ALL: [Self; 9] = [
        Self::Security,
        Self::Device,
        Self::Sync,
        Self::Clipboard,
        Self::Appearance,
        Self::Vault,
        Self::Danger,
        Self::About,
        Self::Backup,
    ];

    /// Tab label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Security => "SEC",
            Self::Device => "DEV",
            Self::Sync => "NET",
            Self::Backup => "BKUP",
            Self::Clipboard => "CLIP",
            Self::Appearance => "UI",
            Self::Vault => "VAULT",
            Self::Danger => "OPS",
            Self::About => "SYS",
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
    /// Whether the node runs and where it listens.
    SyncStatus,
    /// When and how the last check-in ended.
    LastCheckIn,
    /// Peers known and reachable.
    SyncPeers,
    /// Whether `zsync` cloud/mesh & live P2P relay sync is enabled.
    ServerSync,
    /// Custom self-hosted `zsync` server endpoints.
    SyncServers,
    /// Addresses of the account's other devices, typed by the owner.
    SyncDevices,
    /// Saved relays and whether this node holds a slot.
    SyncRelays,
    /// The address this device offers other members.
    SyncAdvertised,
    /// Whether the node announces itself on the local network.
    SyncBeacon,
    /// Check in with the peers and sync servers now.
    SyncNow,
    /// Export an encrypted `.zpbackup` file now.
    BackupExport,
    /// Folder for automatic rolling `.zpbackup` snapshots.
    BackupDir,
    /// Number of automatic rolling snapshots retained (`0` = off).
    BackupKeep,
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
}

/// Every row with its section, in display order.
pub const ROWS: [(Section, Row); 39] = [
    (Section::Security, Row::AutoLock),
    (Section::Security, Row::FocusLock),
    (Section::Security, Row::RevealHide),
    (Section::Security, Row::PasswordCost),
    (Section::Security, Row::Factors),
    (Section::Device, Row::DeviceStatus),
    (Section::Device, Row::DeviceFingerprint),
    (Section::Device, Row::DevicePin),
    (Section::Device, Row::SecureEnclave),
    (Section::Sync, Row::SyncStatus),
    (Section::Sync, Row::LastCheckIn),
    (Section::Sync, Row::SyncPeers),
    (Section::Sync, Row::SyncDevices),
    (Section::Sync, Row::SyncRelays),
    (Section::Sync, Row::SyncAdvertised),
    (Section::Sync, Row::SyncBeacon),
    (Section::Sync, Row::SyncNow),
    (Section::Sync, Row::ServerSync),
    (Section::Sync, Row::SyncServers),
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
    (Section::Backup, Row::BackupExport),
    (Section::Backup, Row::BackupDir),
    (Section::Backup, Row::BackupKeep),
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
            Self::SyncStatus => "Status",
            Self::LastCheckIn => "Last check-in",
            Self::SyncPeers => "Peers",
            Self::ServerSync => "Server sync",
            Self::SyncServers => "Sync servers",
            Self::SyncDevices => "Device addresses",
            Self::SyncRelays => "Relays",
            Self::SyncAdvertised => "Advertised address",
            Self::SyncBeacon => "Beacon",
            Self::SyncNow => "Sync now",
            Self::BackupExport => "Export encrypted backup",
            Self::BackupDir => "Auto-backup folder",
            Self::BackupKeep => "Retained snapshots",
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
                | Self::ServerSync
                | Self::BackupKeep
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
            Self::ServerSync => draft.server_sync = !draft.server_sync,
            Self::BackupKeep => {
                draft.backup_keep = nudge(draft.backup_keep, 1, forward, &(0..=BACKUP_KEEP_MAX));
            }
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
            Self::ServerSync => draft.server_sync = defaults.server_sync,
            Self::SyncServers => draft.sync_servers = defaults.sync_servers,
            Self::BackupDir => draft.backup_dir = defaults.backup_dir,
            Self::BackupKeep => draft.backup_keep = defaults.backup_keep,
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
            Self::ServerSync => draft.server_sync != saved.server_sync,
            Self::SyncServers => draft.sync_servers != saved.sync_servers,
            Self::BackupDir => draft.backup_dir != saved.backup_dir,
            Self::BackupKeep => draft.backup_keep != saved.backup_keep,
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
