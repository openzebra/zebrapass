//! Form validation: turn the typed inputs into one vault op. Every check runs
//! before the vault reaches the worker; a rejected form keeps its inputs.

use std::path::PathBuf;

use seed::SeedPhrase;
use session::KdfProfile;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::app::ctx::Task;
use crate::app::flows::form::{Form, FormKind};
use crate::secure::phrase_input::secret_string;
use crate::secure::secret_input::SecretInput;
use crate::secure::strength::{estimate, StrengthLabel};
use crate::ui::input::TextInput;
use crate::vault::ops::{FactorRef, Op, Rotation};

impl Form {
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

    fn current_password(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
        match self.current.as_mut() {
            None => Ok(None),
            Some(input) if input.is_empty() => Err("Enter the current password."),
            Some(input) => Ok(Some(input.take())),
        }
    }

    fn path(&self) -> Result<PathBuf, &'static str> {
        self.path
            .as_ref()
            .map(|input| input.value().trim())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .ok_or("Enter a file path.")
    }

    /// Validate and build the op.
    ///
    /// # Errors
    ///
    /// A message for the first invalid input.
    pub fn build(&mut self) -> Result<(Op, Task), &'static str> {
        match self.kind.clone() {
            FormKind::Revoke(factor) => self.rotation(Some(factor), false),
            FormKind::Rotate => self.rotation(None, false),
            FormKind::ChangePassword => self.rotation(None, true),
            FormKind::AddPassword => Ok((
                Op::AddPassword(self.new_password()?, KdfProfile::Desktop),
                Task::Factor,
            )),
            FormKind::DropRecovery => {
                if self.text.as_ref().map(TextInput::value) == Some("DROP") {
                    Ok((Op::DropRecovery, Task::Factor))
                } else {
                    Err("Type DROP to confirm.")
                }
            }
            FormKind::Export(ids) => {
                let path = self.path()?;
                Ok((Op::Export(self.parse_phrase()?, ids, path), Task::Sync))
            }
            FormKind::Import => {
                let path = self.path()?;
                Ok((Op::Import(self.parse_phrase()?, path), Task::Sync))
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
        }
    }

    fn rotation(
        &mut self,
        revoke: Option<FactorRef>,
        change: bool,
    ) -> Result<(Op, Task), &'static str> {
        let new_password = if change {
            Some(self.new_password()?)
        } else {
            None
        };
        let current = self.current_password()?;
        let phrase = self.parse_phrase()?;
        let rotation = Rotation {
            phrase,
            current,
            new_password,
            revoke,
        };
        Ok((Op::Rotate(Box::new(rotation)), Task::Rotate))
    }
}
