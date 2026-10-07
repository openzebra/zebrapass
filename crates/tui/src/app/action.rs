//! Every user intent as a closed enum. Keys map to actions through the
//! keymap table; the command palette lists a subset. No string is ever
//! dispatched at runtime.

macro_rules! actions {
    ($( #[doc = $doc:literal] $name:ident ),+ $(,)?) => {
        /// A user intent.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Action {
            $( #[doc = $doc] $name ),+
        }

        impl Action {
            /// Every action, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$name ),+ ];

            /// Help text: the variant's doc comment, so it cannot drift.
            #[must_use]
            pub fn describe(self) -> &'static str {
                match self {
                    $( Self::$name => $doc.trim() ),+
                }
            }
        }
    };
}

actions! {
    /// Move up.
    Up,
    /// Move down.
    Down,
    /// Move left / previous choice.
    Left,
    /// Move right / next choice.
    Right,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// First item.
    Top,
    /// Last item.
    Bottom,
    /// Next field or pane.
    NextField,
    /// Previous field or pane.
    PrevField,
    /// Open / select / confirm.
    Confirm,
    /// Back / clear / cancel.
    Back,
    /// Skip the phrase check.
    Skip,
    /// Open the command palette.
    Palette,
    /// Show the key cheat sheet.
    Help,
    /// Quit (locks first).
    Quit,
    /// Lock now.
    Lock,
    /// Focus search.
    Search,
    /// Copy the password.
    CopyPassword,
    /// Copy the username.
    CopyUsername,
    /// Copy the email.
    CopyEmail,
    /// Copy the TOTP code.
    CopyTotp,
    /// Print the URL (never launched).
    ShowUrl,
    /// Reveal the focused secret (hold, or toggle with auto-hide).
    Reveal,
    /// New record.
    NewRecord,
    /// Edit the record.
    EditRecord,
    /// Delete the record.
    DeleteRecord,
    /// Mark or unmark favorite.
    ToggleFavorite,
    /// Password generator.
    OpenGenerator,
    /// Record history.
    OpenHistory,
    /// Factors (constellation).
    OpenFactors,
    /// Devices and trust.
    OpenDevices,
    /// Sync.
    OpenSync,
    /// Vault health.
    OpenHealth,
    /// Settings.
    OpenSettings,
    /// Reset the selected setting to its default.
    ResetSetting,
    /// Reset every setting of the section.
    ResetSection,
    /// Save the editor, or apply staged settings.
    Save,
    /// Reveal the focused input for a few seconds.
    RevealField,
    /// Generate into the focused field.
    GenerateInto,
    /// Add a custom field.
    AddField,
    /// Remove the focused custom field.
    RemoveField,
    /// New random value.
    Reroll,
    /// Copy the generated value.
    CopyGenerated,
    /// Next generator mode.
    NextMode,
    /// Toggle a-z.
    ToggleLower,
    /// Toggle A-Z.
    ToggleUpper,
    /// Toggle 0-9.
    ToggleDigits,
    /// Toggle symbols.
    ToggleSymbols,
    /// Toggle avoiding look-alike characters.
    ToggleLookalike,
    /// Tick "I wrote it down".
    ToggleWritten,
    /// Accept the autocomplete suggestion.
    AcceptSuggestion,
    /// Finish the current word.
    NextWord,
    /// Reveal the last finished word.
    RevealWord,
    /// Hide or show the word being typed.
    HideWord,
    /// Fill a generated passphrase.
    GeneratePassphrase,
    /// Next unlock factor.
    SwitchFactor,
    /// Unlock with the recovery phrase.
    UseRecovery,
    /// Choose another vault.
    SwitchVault,
    /// Add a factor.
    AddFactor,
    /// Revoke a factor and rotate the vault key.
    RevokeFactor,
    /// Remove a factor's wrap (no rotation).
    RemoveFactor,
    /// Enroll another device.
    EnrollDevice,
    /// Regenerate the selected record's password.
    Regenerate,
    /// Restore the selected revision.
    RestoreRevision,
    /// Show the vault file location.
    ShowLocation,
    /// Rotate the vault key.
    RotateVaultKey,
    /// Change the vault password.
    ChangePassword,
    /// Drop the recovery wrap from this copy.
    DropRecovery,
    /// Drop superseded revisions.
    ClearHistory,
    /// Next color theme.
    CycleTheme,
    /// Animations on/off.
    ToggleAnimation,
    /// ASCII glyphs on/off.
    ToggleAscii,
    /// Create a new vault.
    CreateVault,
    /// Restore a vault, or import one from another manager.
    RestoreVault,
    /// Change how CSV columns are read.
    EditColumns,
    /// Include or exclude the selected item.
    ToggleInclude,
    /// Include or exclude every item.
    ToggleAll,
    /// Make a shared vault.
    ShareNew,
    /// Add a person to the selected shared vault.
    ShareAdd,
    /// Join a shared vault from an invitation.
    ShareJoin,
    /// Fetch a waiting shared vault again, now.
    ShareRetry,
    /// Cycle where this device's node listens.
    ShareListen,
    /// Remove a person from the selected shared vault.
    ShareRemove,
    /// Change what a person may do in the selected shared vault.
    ShareRole,
    /// Leave the selected shared vault, or forget it.
    ShareLeave,
    /// Replace the key of the selected shared vault.
    ShareRekey,
}

/// Where a palette entry is listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// Vault key and factors.
    Factors,
    /// Records.
    Records,
    /// Devices and sync.
    Devices,
    /// Look and feel.
    View,
    /// Session.
    Session,
}

impl Section {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Factors => "Factors",
            Self::Records => "Records",
            Self::Devices => "Devices",
            Self::View => "View",
            Self::Session => "Session",
        }
    }
}

/// Command palette entries: `(action, label, section)`.
pub const PALETTE: &[(Action, &str, Section)] = &[
    (Action::RotateVaultKey, "Rotate vault key", Section::Factors),
    (Action::ChangePassword, "Change password", Section::Factors),
    (
        Action::OpenFactors,
        "Factors · how your vault is locked",
        Section::Factors,
    ),
    (
        Action::DropRecovery,
        "Drop recovery wrap (advanced)",
        Section::Factors,
    ),
    (
        Action::RevokeFactor,
        "Revoke device or factor…",
        Section::Devices,
    ),
    (Action::OpenDevices, "Devices and trust", Section::Devices),
    (Action::OpenSync, "Sync", Section::Devices),
    (
        Action::EnrollDevice,
        "Enroll a new device",
        Section::Devices,
    ),
    (Action::NewRecord, "New record", Section::Records),
    (
        Action::OpenGenerator,
        "Password generator",
        Section::Records,
    ),
    (Action::OpenHealth, "Vault health", Section::Records),
    (Action::ClearHistory, "Clear history", Section::Records),
    (Action::Search, "Search records", Section::Records),
    (Action::CycleTheme, "Next theme", Section::View),
    (Action::ToggleAnimation, "Toggle animations", Section::View),
    (Action::ToggleAscii, "Toggle ASCII glyphs", Section::View),
    (Action::OpenSettings, "Settings", Section::View),
    (Action::Help, "Keyboard shortcuts", Section::View),
    (Action::CreateVault, "Create a new vault", Section::Session),
    (
        Action::RestoreVault,
        "Restore or import a vault",
        Section::Session,
    ),
    (Action::Lock, "Lock now", Section::Session),
    (Action::Quit, "Quit", Section::Session),
];
