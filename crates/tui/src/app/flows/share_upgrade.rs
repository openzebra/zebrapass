//! Upgrading the sync identity of a vault whose identity was written before
//! the account gate secret existed.
//!
//! Such a device cannot serve its personal vault to the account's other
//! devices. The account's phrase brings the gate secret back: it is typed in
//! the same masked input the restore screen uses, checked against the root
//! key this identity chains to, and only then is the file rewritten, in
//! place, with the same device key and certificates.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use local::upgrade_sync_identity;
use seed::SeedPhrase;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::{edit_secret, printable};
use crate::app::flows::restore::REVEAL_LAST;
use crate::app::flows::share::Step;
use crate::app::flows::unlock::MAX_PASSPHRASE;
use crate::app::flows::unlocked::Unlocked;
use crate::secure::phrase_input::{secret_string, PhraseInput, Typed};
use crate::secure::reveal::RevealGuard;
use crate::secure::secret_input::SecretInput;
use crate::ui::widgets::toast::Tone;

/// The phrase being typed to upgrade the identity.
#[derive(Debug)]
pub struct UpgradePrompt {
    /// The words.
    pub phrase: PhraseInput,
    /// Optional 25th word.
    pub passphrase: SecretInput,
    /// Focus is on the passphrase.
    pub on_passphrase: bool,
    /// Reveal of the last finished word.
    pub reveal: RevealGuard,
    /// Last problem.
    pub error: Option<&'static str>,
}

impl UpgradePrompt {
    fn new() -> Self {
        Self {
            phrase: PhraseInput::default(),
            passphrase: SecretInput::new(MAX_PASSPHRASE),
            on_passphrase: false,
            reveal: RevealGuard::default(),
            error: None,
        }
    }

    fn wipe(&mut self) {
        self.phrase.clear();
        self.passphrase.clear();
        self.reveal.hide();
    }

    fn edit(&mut self, event: &KeyEvent, ctx: &mut Ctx) {
        if event.code == KeyCode::Tab {
            if self.on_passphrase || !self.phrase.accept_suggestion() {
                self.on_passphrase = !self.on_passphrase;
            }
        } else if event.modifiers.contains(KeyModifiers::CONTROL) {
            if event.code == KeyCode::Char('r')
                && self.phrase.count() > 0
                && self.reveal.toggle(REVEAL_LAST, ctx.now)
            {
                ctx.redraw();
            }
        } else if self.on_passphrase {
            edit_secret(&mut self.passphrase, event);
        } else if let Some(ch) = printable(event) {
            if ch == ' ' {
                self.phrase.space();
            } else if self.phrase.type_char(ch) == Typed::Rejected {
                self.error = Some("No BIP39 word starts like that.");
                return;
            }
            self.error = None;
        } else if event.code == KeyCode::Backspace {
            self.phrase.backspace();
        }
    }
}

impl Unlocked {
    /// Whether this vault's sync identity is of the old kind, which cannot
    /// serve the personal vault.
    #[must_use]
    pub fn identity_is_old(&self) -> bool {
        self.identity
            .as_deref()
            .is_some_and(|identity| identity.account_gate().is_none())
    }

    pub(super) fn begin_upgrade(&self, ctx: &mut Ctx) -> Step {
        if self.identity_is_old() {
            Step::Upgrade(Box::new(UpgradePrompt::new()))
        } else {
            ctx.toast(Tone::Info, "This device's sync identity is up to date.");
            Step::Overview
        }
    }

    pub(super) fn upgrade_step(
        &mut self,
        mut prompt: Box<UpgradePrompt>,
        action: Option<Action>,
        event: &KeyEvent,
        ctx: &mut Ctx,
    ) -> Step {
        match action {
            Some(Action::Back) => {
                prompt.wipe();
                Step::Overview
            }
            Some(Action::Confirm) => {
                if self.upgrade_with(&mut prompt, ctx) {
                    Step::Overview
                } else {
                    Step::Upgrade(prompt)
                }
            }
            _ => {
                prompt.edit(event, ctx);
                Step::Upgrade(prompt)
            }
        }
    }

    /// Check the phrase and upgrade the identity file; `true` when it is
    /// done. A wrong phrase touches nothing.
    fn upgrade_with(&mut self, prompt: &mut UpgradePrompt, ctx: &mut Ctx) -> bool {
        let Some(vault) = self.vault.as_deref() else {
            return false;
        };
        if !prompt.phrase.plausible() {
            prompt.error = Some("Enter all 12, 15, 18, 21, or 24 words.");
            return false;
        }
        let Some(passphrase) = secret_string(prompt.passphrase.expose()) else {
            prompt.error = Some("The passphrase is not valid text.");
            return false;
        };
        let Ok(phrase) = SeedPhrase::parse(&prompt.phrase.to_secret(), &passphrase) else {
            prompt.error = Some("That phrase is not valid. Check the words and their order.");
            return false;
        };
        let upgraded = vault.session.sync_identity_key().and_then(|key| {
            upgrade_sync_identity(&vault.paths.sync_identity(), &key, phrase.seed())
        });
        if upgraded.is_err() {
            prompt.error = Some("That is not the phrase of this account.");
            return false;
        }
        prompt.wipe();
        self.identity = vault
            .session
            .sync_identity_key()
            .ok()
            .and_then(|_| crate::app::p2p::load_identity(vault));
        self.restart_p2p();
        ctx.toast(
            Tone::Success,
            "Identity upgraded. This device can now serve your other devices.",
        );
        true
    }
}
