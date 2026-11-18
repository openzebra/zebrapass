//! Form validation: turn the typed inputs into one vault op. Every check runs
//! before the vault reaches the worker; a rejected form keeps its inputs.

use std::path::PathBuf;

use local::{BACKUP_DIR_MAX_LEN, DEVICE_PIN_LEN, SYNC_PROXY_MAX_LEN};
use seed::SeedPhrase;
use session::KdfProfile;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::app::ctx::Task;
use crate::app::flows::form::{Form, FormKind};
use crate::secure::phrase_input::secret_string;
use crate::secure::secret_input::SecretInput;
use crate::secure::strength::{StrengthLabel, estimate};
use crate::ui::input::TextInput;
use crate::vault::device::PIN_PROFILE;
use crate::vault::ops::{FactorRef, Op, Rotation};

impl Form {
    /// Edit HTTPS/WSS sync server URLs (comma-separated).
    #[must_use]
    pub fn sync_servers(current: &str) -> Self {
        Self::text_form(
            FormKind::SyncServers,
            "Sync servers",
            &[
                "Enter https://host[:port]/secret-path URLs (comma-separated).",
                "Leave empty to disable server sync, then Ctrl-S in Settings.",
            ],
            current,
            1024,
        )
    }

    /// Edit outbound `socks5h://` or `http://` proxy URL.
    #[must_use]
    pub fn sync_proxy(current: &str) -> Self {
        Self::text_form(
            FormKind::SyncProxy,
            "Outbound proxy",
            &[
                "Enter socks5h://[user:pass@]host:port or http://host:port.",
                "Leave empty for direct connections, then Ctrl-S in Settings.",
            ],
            current,
            SYNC_PROXY_MAX_LEN,
        )
    }

    /// Edit automatic rolling `.zpbackup` directory.
    #[must_use]
    pub fn backup_dir(current: &str) -> Self {
        Self::text_form(
            FormKind::BackupDir,
            "Auto-backup folder",
            &[
                "Local folder for rolling encrypted .zpbackup snapshots.",
                "Leave empty to turn off rolling backups, then Ctrl-S in Settings.",
            ],
            current,
            BACKUP_DIR_MAX_LEN,
        )
    }

    /// Choose destination path for an immediate `.zpbackup` export.
    #[must_use]
    pub fn backup_export(default_path: &str) -> Self {
        Self::text_form(
            FormKind::BackupExport,
            "Export encrypted backup",
            &[
                "Packs personal + ready shared vaults in PQ Cascade (.zpbackup).",
                "Device-bound keys (device.key, sync.id) are never included.",
            ],
            default_path,
            BACKUP_DIR_MAX_LEN,
        )
    }
    fn parse_phrase(&mut self) -> Result<Box<SeedPhrase>, &'static str> {
        let phrase = self
            .phrase
            .as_mut()
            .ok_or("The recovery phrase is needed.")?;
        if !phrase.plausible() {
            return Err("Enter all the words of the recovery phrase.");
        }
        let passphrase = secret_string(
            self.passphrase
                .as_ref()
                .map_or(&[][..], SecretInput::expose),
        )
        .ok_or("The passphrase is not valid text.")?;
        let parsed = SeedPhrase::parse(&phrase.to_secret(), &passphrase)
            .map_err(|_| "That phrase is not valid. Check the words and their order.")?;
        phrase.clear();
        Ok(Box::new(parsed))
    }

    fn new_password(&mut self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let (Some(new), Some(repeat)) = (self.new.as_mut(), self.repeat.as_ref()) else {
            return Err("A new password is needed.");
        };
        if new.is_empty() {
            return Err("Choose a password.");
        }
        if !bool::from(new.expose().ct_eq(repeat.expose())) {
            return Err("The two entries do not match.");
        }
        if estimate(new.expose()).label == StrengthLabel::VeryWeak {
            return Err("Too weak. Try a few random words.");
        }
        Ok(new.take())
    }

    fn new_pin(&mut self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let (Some(new), Some(repeat)) = (self.new.as_mut(), self.repeat.as_ref()) else {
            return Err("A device PIN is needed.");
        };
        if !DEVICE_PIN_LEN.contains(&new.len()) {
            return Err("A device PIN has 6 to 128 characters.");
        }
        if !bool::from(new.expose().ct_eq(repeat.expose())) {
            return Err("The two entries do not match.");
        }
        Ok(new.take())
    }

    fn current_password(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
        match self.current.as_mut() {
            None => Ok(None),
            Some(input) if input.is_empty() => Err("Enter the current password."),
            Some(input) => Ok(Some(input.take())),
        }
    }

    /// Validate and build the op.
    ///
    /// # Errors
    ///
    /// A message for the first invalid input.
    pub fn build(&mut self) -> Result<(Op, Task), &'static str> {
        match self.kind.clone() {
            FormKind::Revoke(factor) => self.rotation(Some(factor)),
            FormKind::Rotate => self.rotation(None),
            FormKind::ChangePassword => {
                let new = self.new_password()?;
                let current = self
                    .current_password()?
                    .ok_or("Enter the current password.")?;
                Ok((Op::ChangePassword { current, new }, Task::Factor))
            }
            FormKind::AddPassword => Ok((
                Op::AddPassword(self.new_password()?, KdfProfile::Balanced),
                Task::Factor,
            )),
            FormKind::AddDevice => Ok((Op::AddDevice(self.new_pin()?, PIN_PROFILE), Task::Factor)),
            FormKind::ChangePin => {
                let new = self.new_pin()?;
                let current = self.current_password()?.ok_or("Enter the current PIN.")?;
                Ok((
                    Op::ChangePin {
                        current,
                        new,
                        profile: PIN_PROFILE,
                    },
                    Task::Factor,
                ))
            }
            FormKind::DropRecovery => {
                if self.text.as_ref().map(TextInput::value) == Some("DROP") {
                    Ok((Op::DropRecovery, Task::Factor))
                } else {
                    Err("Type DROP to confirm.")
                }
            }
            FormKind::Rename => {
                let name = self
                    .text
                    .as_ref()
                    .map_or("", |input| input.value().trim())
                    .to_owned();
                if name.is_empty() {
                    Err("Give the vault a name.")
                } else {
                    Ok((Op::Rename(name), Task::Save))
                }
            }
            FormKind::BackupExport => {
                let path = self
                    .text
                    .as_ref()
                    .map_or("", |input| input.value().trim())
                    .to_owned();
                if path.is_empty() {
                    Err("Enter a destination file path.")
                } else {
                    Ok((Op::ExportBackup(PathBuf::from(path)), Task::Save))
                }
            }
            FormKind::SyncServers | FormKind::SyncProxy | FormKind::BackupDir => {
                Err("Apply this change directly from Settings.")
            }
        }
    }

    fn rotation(&mut self, revoke: Option<FactorRef>) -> Result<(Op, Task), &'static str> {
        let current = self.current_password()?;
        let phrase = self.parse_phrase()?;
        let rotation = Rotation {
            phrase,
            current,
            revoke,
        };
        Ok((Op::Rotate(Box::new(rotation)), Task::Rotate))
    }
}
