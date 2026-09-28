//! Forms behind dangerous operations and the ops they build.

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::{ConfirmKind, Dialog};
use crate::app::flows::editing::Hold;
use crate::app::flows::unlock::{MAX_PASSPHRASE, MAX_PASSWORD};
use crate::app::flows::unlocked::Unlocked;
use crate::secure::phrase_input::PhraseInput;
use crate::secure::reveal::{RevealGuard, RevealKey};
use crate::secure::secret_input::SecretInput;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::chip::Chips;
use crate::vault::factors::presence;
use crate::vault::limits::MAX_VAULT_NAME;
use crate::vault::ops::{FactorRef, Op};

/// What the form is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormKind {
    /// Revoke a factor and rotate the vault key.
    Revoke(FactorRef),
    /// Rotate the vault key.
    Rotate,
    /// New password (rotates the vault key).
    ChangePassword,
    /// First password factor.
    AddPassword,
    /// Drop the recovery wrap (type `DROP`).
    DropRecovery,
    /// Rename the vault on this device.
    Rename,
}

/// Focusable inputs, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormFocus {
    /// Recovery words.
    Phrase,
    /// BIP39 passphrase.
    Passphrase,
    /// Current password.
    Current,
    /// New password.
    New,
    /// Repeat.
    Repeat,
    /// Free text (name, `DROP`).
    Text,
}

const ORDER: [FormFocus; 6] = [
    FormFocus::Phrase,
    FormFocus::Passphrase,
    FormFocus::Current,
    FormFocus::New,
    FormFocus::Repeat,
    FormFocus::Text,
];

/// A form.
#[derive(Debug)]
pub struct Form {
    /// Purpose.
    pub kind: FormKind,
    /// Title.
    pub title: String,
    /// Explanation lines.
    pub body: Vec<String>,
    /// Recovery words.
    pub phrase: Option<PhraseInput>,
    /// BIP39 passphrase.
    pub passphrase: Option<SecretInput>,
    /// Current password.
    pub current: Option<SecretInput>,
    /// New password.
    pub new: Option<SecretInput>,
    /// Repeat.
    pub repeat: Option<SecretInput>,
    /// Free text.
    pub text: Option<TextInput>,
    /// Focus.
    pub focus: FormFocus,
    /// Hold-to-confirm, for dangerous forms.
    pub hold: Option<Hold>,
    /// Last validation message.
    pub error: Option<Box<str>>,
    /// Reveal of the focused secret.
    pub reveal: RevealGuard,
}

fn secret(max: usize) -> SecretInput {
    SecretInput::new(max)
}

impl Form {
    fn blank(kind: FormKind, title: &str, body: &[&str]) -> Self {
        Self {
            kind,
            title: title.to_owned(),
            body: body.iter().map(|line| (*line).to_owned()).collect(),
            phrase: None,
            passphrase: None,
            current: None,
            new: None,
            repeat: None,
            text: None,
            focus: FormFocus::Phrase,
            hold: None,
            error: None,
            reveal: RevealGuard::default(),
        }
    }

    fn with_phrase(mut self) -> Self {
        self.phrase = Some(PhraseInput::default());
        self.passphrase = Some(secret(MAX_PASSPHRASE));
        self
    }

    fn with_current(mut self, has_password: bool) -> Self {
        if has_password {
            self.current = Some(secret(MAX_PASSWORD));
        }
        self
    }

    fn with_new(mut self) -> Self {
        self.new = Some(secret(MAX_PASSWORD));
        self.repeat = Some(secret(MAX_PASSWORD));
        self
    }

    fn held(mut self) -> Self {
        self.hold = Some(Hold::default());
        self
    }

    fn focus_first(mut self) -> Self {
        self.focus = self.order().first().copied().unwrap_or(FormFocus::Text);
        self
    }

    /// Revoke `factor`.
    #[must_use]
    pub fn revoke(factor: FactorRef, label: &str, has_password: bool) -> Self {
        Self::blank(
            FormKind::Revoke(factor),
            &format!("Revoke {label}?"),
            &[
                "1. Its wrap is removed.",
                "2. A NEW vault key is generated (rotation).",
                "3. Every remaining factor is re-wrapped.",
                "4. The old key stops working, even with old copies.",
                "The recovery phrase is needed for this rotation.",
            ],
        )
        .with_phrase()
        .with_current(has_password)
        .held()
        .focus_first()
    }

    /// Rotate the vault key.
    #[must_use]
    pub fn rotate(has_password: bool) -> Self {
        Self::blank(
            FormKind::Rotate,
            "Rotate the vault key",
            &["A new vault key re-encrypts every record and re-wraps every factor."],
        )
        .with_phrase()
        .with_current(has_password)
        .held()
        .focus_first()
    }

    /// Change the password.
    #[must_use]
    pub fn change_password() -> Self {
        Self::blank(
            FormKind::ChangePassword,
            "Change password",
            &[
                "Only the password wrap changes; the recovery phrase is not needed.",
                "Old copies of this file still open with the old password:",
                "rotate the vault key too if the old password leaked.",
            ],
        )
        .with_current(true)
        .with_new()
        .focus_first()
    }

    /// Add the first password.
    #[must_use]
    pub fn add_password() -> Self {
        Self::blank(
            FormKind::AddPassword,
            "Add a password",
            &["Argon2id stretches it into a key-encryption key."],
        )
        .with_new()
        .focus_first()
    }

    /// Drop the recovery wrap.
    #[must_use]
    pub fn drop_recovery() -> Self {
        let mut form = Self::blank(
            FormKind::DropRecovery,
            "Drop the recovery wrap from this copy?",
            &[
                "After this, the phrase no longer opens THIS file.",
                "Other copies and backups keep their recovery wrap.",
                "Type DROP, then hold Enter.",
            ],
        )
        .held();
        form.text = Some(TextInput::new(8));
        form.focus_first()
    }

    /// Rename.
    #[must_use]
    pub fn rename(current: &str) -> Self {
        let mut form = Self::blank(
            FormKind::Rename,
            "Rename vault",
            &["The name is stored on this device only."],
        );
        form.text = Some(TextInput::with_value(current, MAX_VAULT_NAME));
        form.focus_first()
    }

    /// Present inputs in order.
    #[must_use]
    pub fn order(&self) -> Vec<FormFocus> {
        ORDER
            .iter()
            .copied()
            .filter(|focus| match focus {
                FormFocus::Phrase => self.phrase.is_some(),
                FormFocus::Passphrase => self.passphrase.is_some(),
                FormFocus::Current => self.current.is_some(),
                FormFocus::New => self.new.is_some(),
                FormFocus::Repeat => self.repeat.is_some(),
                FormFocus::Text => self.text.is_some(),
            })
            .collect()
    }

    /// Move focus.
    pub fn shift(&mut self, forward: bool, ctx: &mut Ctx) {
        let order = self.order();
        let at = order
            .iter()
            .position(|focus| *focus == self.focus)
            .unwrap_or(0);
        let len = order.len().max(1);
        let next = if forward { at + 1 } else { at + len - 1 } % len;
        self.focus = order.get(next % len).copied().unwrap_or(self.focus);
        if self.reveal.hide() {
            ctx.redraw();
        }
    }

    /// Reveal key of an input.
    #[must_use]
    pub fn reveal_key(focus: FormFocus) -> RevealKey {
        RevealKey(
            30 + u32::try_from(ORDER.iter().position(|item| *item == focus).unwrap_or(0))
                .unwrap_or(0),
        )
    }

    /// Toggle reveal of the focused secret.
    pub fn toggle_reveal(&mut self, ctx: &mut Ctx) {
        if self.secret_mut(self.focus).is_some()
            && self.reveal.toggle(Self::reveal_key(self.focus), ctx.now)
        {
            ctx.redraw();
        }
    }

    /// The secret input behind `focus`.
    pub const fn secret_mut(&mut self, focus: FormFocus) -> Option<&mut SecretInput> {
        match focus {
            FormFocus::Passphrase => self.passphrase.as_mut(),
            FormFocus::Current => self.current.as_mut(),
            FormFocus::New => self.new.as_mut(),
            FormFocus::Repeat => self.repeat.as_mut(),
            FormFocus::Phrase | FormFocus::Text => None,
        }
    }

    /// The text input behind `focus`.
    pub const fn text_mut(&mut self, focus: FormFocus) -> Option<&mut TextInput> {
        match focus {
            FormFocus::Text => self.text.as_mut(),
            FormFocus::Phrase
            | FormFocus::Passphrase
            | FormFocus::Current
            | FormFocus::New
            | FormFocus::Repeat => None,
        }
    }

    /// Paste into the focused input.
    pub fn on_paste(&mut self, text: &str) {
        let focus = self.focus;
        if focus == FormFocus::Phrase {
            if let Some(phrase) = self.phrase.as_mut() {
                for ch in text.chars() {
                    if ch.is_whitespace() {
                        phrase.space();
                    } else {
                        phrase.type_char(ch);
                    }
                }
                phrase.space();
            }
        } else if let Some(input) = self.secret_mut(focus) {
            input.insert_str(text);
        } else if let Some(input) = self.text_mut(focus) {
            input.insert_str(text);
        }
    }
}

/// Carry out a confirmed yes/no dialog.
pub fn run_confirm(state: &mut Unlocked, kind: ConfirmKind, ctx: &mut Ctx) {
    match kind {
        ConfirmKind::Delete(id) => state.run(Op::Delete(id), Task::Save, ctx),
        ConfirmKind::RemoveWrap(factor) => state.run(Op::RemoveWrap(factor), Task::Factor, ctx),
        ConfirmKind::RemovePassword => state.run(Op::RemovePassword, Task::Factor, ctx),
        ConfirmKind::ClearHistory => state.run(Op::ClearHistory, Task::Save, ctx),
        ConfirmKind::RestoreRevision(id, revision) => {
            state.run(Op::RestoreRevision(id, revision), Task::Save, ctx);
        }
        ConfirmKind::Discard => crate::app::flows::editor_keys::close(state, ctx),
    }
}

/// Carry out an add-factor menu choice.
pub fn add_factor(state: &mut Unlocked, choice: usize, ctx: &mut Ctx) {
    let found = presence(&state.info.directory, &ctx.chips);
    match choice {
        0 if found.password => ctx.toast(
            Tone::Info,
            "This vault already has a password. Use Change password.",
        ),
        0 => state.dialog = Some(Box::new(Dialog::Form(Box::new(Form::add_password())))),
        1 if found.owned_devices > 0 => ctx.toast(Tone::Info, "This device is already enrolled."),
        1 => {
            if !ctx.chips.keyring().persistent() {
                ctx.toast(
                    Tone::Warn,
                    "Keychain is off: this device key lives in memory and is lost on quit.",
                );
            }
            state.run(Op::AddDevice, Task::Factor, ctx);
        }
        2 if Chips::available() => add_chip(state, ctx),
        2 => ctx.toast(
            Tone::Warn,
            "No secure chip backend in this build (Secure Enclave is not built yet).",
        ),
        // TODO(hw-key): FIDO2 PRF enrollment plugs in here; until then it fails closed.
        _ => ctx.toast(Tone::Warn, "Hardware keys are not available yet."),
    }
}

#[cfg(feature = "dev-chip")]
fn add_chip(state: &mut Unlocked, ctx: &mut Ctx) {
    ctx.toast(
        Tone::Warn,
        "Software chip (dev): its key lives in memory and is lost on quit.",
    );
    state.run(Op::AddChip, Task::Factor, ctx);
}

#[cfg(not(feature = "dev-chip"))]
const fn add_chip(_state: &mut Unlocked, _ctx: &mut Ctx) {}
