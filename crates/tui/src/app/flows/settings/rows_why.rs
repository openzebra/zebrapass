//! Explanatory text shown below each row in Settings.

use super::rows::Row;

impl Row {
    /// Why the row matters, shown under the list.
    #[must_use]
    pub const fn why(self) -> &'static str {
        if let Some(text) = self.why_security_or_device() {
            return text;
        }
        if let Some(text) = self.why_sync_or_backup() {
            return text;
        }
        self.why_vault_or_about()
    }

    const fn why_security_or_device(self) -> Option<&'static str> {
        match self {
            Self::AutoLock => Some(
                "Locks the vault and wipes its keys from memory after this much inactivity. Shorter is safer on a shared machine.",
            ),
            Self::FocusLock => {
                Some("Locks the moment the terminal loses focus: switching windows is enough.")
            }
            Self::RevealHide => Some(
                "A revealed password hides itself again after this long, and the screen is repainted.",
            ),
            Self::PasswordCost => Some(
                "Argon2id cost of the password wrap. Enter changes the password (or adds one).",
            ),
            Self::Factors => Some(
                "Every way this vault can be opened, drawn as a constellation. Enter opens it.",
            ),
            Self::DeviceStatus => Some(
                "P-256 + ML-KEM keys sealed in a file next to the vault under a PIN. They never leave this disk.",
            ),
            Self::DeviceFingerprint => Some(
                "Compare this with the device list on another machine to know which wrap is which.",
            ),
            Self::DevicePin => Some(
                "Argon2id stretches the PIN before it can open the key file. Enter changes the PIN; the vault is untouched.",
            ),
            Self::SecureEnclave => Some(
                "Apple only lets signed apps use the Secure Enclave. A terminal app cannot, so the PIN file takes its place.",
            ),
            Self::ClipClear => Some("Copied secrets are wiped from the clipboard after this long."),
            Self::ClipOnLock => {
                Some("Locking always clears a secret this app copied. This one is not optional.")
            }
            _ => None,
        }
    }

    const fn why_sync_or_backup(self) -> Option<&'static str> {
        match self {
            Self::SyncStatus => Some(
                "Peer-to-peer sync of this vault. l on the Share screen is the only switch between listening, fetch only and off.",
            ),
            Self::LastCheckIn => Some(
                "The latest check-in with your peers, and how it ended. Checks repeat on their own every 15 s.",
            ),
            Self::SyncPeers => {
                Some("Other devices and members this node knows, and how many are connected now.")
            }
            Self::ServerSync => Some(
                "Zero-knowledge PQ TLS 1.3 sync & live P2P relay across [ru, eu, zh].zebra.sh or custom servers.",
            ),
            Self::SyncServers => Some(
                "Custom Zebra sync servers (host[:port], comma-separated). Leave empty to use ru.zebra.sh, eu.zebra.sh, zh.zebra.sh.",
            ),
            Self::SyncDevices => Some(
                "Addresses of your other devices, typed here when no beacon reaches them: another network, another country. Enter opens the list; a adds one.",
            ),
            Self::SyncRelays => Some(
                "Relay slots saved here. A relay only passes sealed traffic; it never holds your data.",
            ),
            Self::SyncAdvertised => Some(
                "The address this device offers other members when it sits behind a port forward. Set it on the Share screen.",
            ),
            Self::SyncBeacon => Some(
                "Whether this device announces itself to your other devices on the local network.",
            ),
            Self::SyncNow => {
                Some("Enter checks in with your peers and sync servers once, right now.")
            }
            Self::BackupExport => Some(
                "Write a quantum-safe .zpbackup bundle (personal + ready shared vaults). Device keys are never exported.",
            ),
            Self::BackupDir => Some(
                "Folder where rolling .zpbackup snapshots are written automatically after vault changes.",
            ),
            Self::BackupKeep => Some(
                "Maximum number of automatic rolling .zpbackup snapshots to retain in Auto-backup folder.",
            ),
            _ => None,
        }
    }

    const fn why_vault_or_about(self) -> &'static str {
        match self {
            Self::Theme => "Previewed live. Saved per vault; --no-color and NO_COLOR always win.",
            Self::Animation => "Reduced motion freezes every animation.",
            Self::Ascii => "Replaces Unicode symbols with plain ASCII for limited terminals.",
            Self::Name => "Stored on this device only, inside the encrypted local metadata.",
            Self::Cipher => {
                "Each record is sealed on its own: AEGIS-256 inside Kuznyechik-CTR + HMAC, one key per layer."
            }
            Self::Generation => {
                "Grows with every change to the wrap directory; an older file is refused as a rollback."
            }
            Self::Records => "Live records. Old revisions stay until history is cleared.",
            Self::Import => {
                "Bitwarden, KeePass (.kdbx or XML), Enpass, or CSV. Records already here are skipped."
            }
            Self::FilePath => {
                "Back this file up. Without the recovery phrase it is useless to anyone."
            }
            Self::RotateKey => {
                "Draws a new vault key, re-seals every record, and re-wraps every factor. Needs the phrase."
            }
            Self::ForgetDevice => {
                "Removes this device's wrap, rotates the vault key, and deletes the key file."
            }
            Self::ClearHistory => {
                "Drops superseded revisions. The live record of each entry stays."
            }
            Self::Version => "This build and its features.",
            Self::DataDir => "Where every vault on this machine lives.",
            Self::Primitives => "Nothing here is hand-rolled: vetted implementations only.",
            _ => "",
        }
    }
}
