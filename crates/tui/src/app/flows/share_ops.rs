//! What each step of the share screen does to vaults, files and the node.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use local::{create_shared_vault, join_shared_vault, Introduction, SharedRef};
use memberlog::{Action as LogAction, Role};
use sharing::{account_fingerprint, vault_number, ContactCard, Invitation, Inviter, Offer, Opened};
use zeroize::Zeroizing;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::share::{Me, Step};
use crate::app::flows::unlocked::Unlocked;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::ops::Op;
use crate::vault::shared::SharedItem;

fn busy() -> anyhow::Error {
    anyhow!("Still working on the last change.")
}

impl Unlocked {
    /// A fresh contact card for this device.
    fn my_card(&self) -> Result<ContactCard> {
        let identity = self
            .identity
            .as_deref()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let publics = identity.share_publics()?;
        ContactCard::issue(
            &identity.sign_key(),
            cert,
            identity.root_vk(),
            publics.ec_pub,
            &publics.kem_ek[..],
            unix_ms(),
        )
    }

    pub(super) fn make_me(&self) -> Option<Me> {
        let card = self.my_card().ok()?;
        let text = Zeroizing::new(card.to_text().ok()?);
        Some(Me {
            text,
            print: card.fingerprint(),
        })
    }

    pub(super) fn copy_my_key(&self, ctx: &mut Ctx) {
        let Some(text) = self.make_me().map(|me| me.text) else {
            ctx.toast(Tone::Warn, "This vault has no sync identity yet.");
            return;
        };
        ctx.copy(text.as_bytes(), "share key");
    }

    fn fail(ctx: &mut Ctx, error: &anyhow::Error) {
        ctx.toast(Tone::Warn, error.to_string());
    }

    /// Write the record that points at a shared vault into the personal vault.
    fn remember(&mut self, reference: &SharedRef, ctx: &mut Ctx) {
        let doc = Box::new(reference.to_document());
        self.run(Op::Write { id: None, doc }, Task::Save, ctx);
    }

    pub(super) fn create_named(&mut self, input: TextInput, ctx: &mut Ctx) -> Step {
        let name = input.value().trim().to_owned();
        if name.is_empty() {
            return Step::Name(input);
        }
        match self.make_vault(&name, ctx) {
            Ok(()) => Step::Overview,
            Err(error) => {
                Self::fail(ctx, &error);
                Step::Name(input)
            }
        }
    }

    fn make_vault(&mut self, name: &str, ctx: &mut Ctx) -> Result<()> {
        if self.vault.is_none() {
            return Err(busy());
        }
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let (vault, reference) =
            create_shared_vault(&self.base, &identity, name, kdf::KdfProfile::Fast)?;
        let reference = Arc::new(reference);
        let item = SharedItem::created(&self.base, Arc::clone(&reference), vault, &identity);
        self.shared.push(item);
        self.ensure_p2p();
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.provider.serve(Arc::clone(&reference));
        }
        self.remember(&reference, ctx);
        Ok(())
    }

    pub(super) fn begin_add(&mut self, ctx: &mut Ctx) -> Step {
        let cursor = self.share_cursor();
        let picked = self
            .shared
            .get(cursor)
            .map(|item| (item.ready(), item.my_role));
        let message = match picked {
            None => "Make a shared vault first (n).",
            Some((false, _)) => "That vault is still syncing.",
            Some((true, role)) if role != Some(Role::Owner) => "Only owners can add people.",
            Some(_) if !self.ensure_p2p() => "This vault has no sync identity.",
            Some(_) if self.p2p.as_deref().is_none_or(|p2p| p2p.hints().is_empty()) => {
                "Listening is off. Press l, then add them."
            }
            Some(_) => return Step::PasteCard,
        };
        ctx.toast(Tone::Info, message);
        Step::Overview
    }

    pub(super) fn share_cursor(&self) -> usize {
        match &self.view {
            crate::app::flows::unlocked::View::Sync(share) => share.cursor,
            _ => 0,
        }
    }

    pub(super) fn card_pasted(text: &str, ctx: &mut Ctx) -> Step {
        ContactCard::from_text(text)
            .and_then(|card| card.verify(unix_ms()).map(|()| card))
            .map_or_else(
                |_| {
                    ctx.toast(Tone::Warn, "That is not a valid share key.");
                    Step::PasteCard
                },
                |card| Step::AddConfirm {
                    card: Box::new(card),
                    role: Role::Writer,
                },
            )
    }

    pub(super) fn finish_add(&mut self, card: Box<ContactCard>, role: Role, ctx: &mut Ctx) -> Step {
        match self.add_person(&card, role) {
            Ok((invitation, number)) => Step::AddDone {
                invitation,
                print: card.fingerprint(),
                number,
            },
            Err(error) => {
                Self::fail(ctx, &error);
                Step::AddConfirm { card, role }
            }
        }
    }

    fn add_person(
        &mut self,
        card: &ContactCard,
        role: Role,
    ) -> Result<(Zeroizing<String>, String)> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let hints = self
            .p2p
            .as_deref()
            .map(crate::app::p2p::P2p::hints)
            .unwrap_or_default();
        if hints.is_empty() {
            return Err(anyhow!("Listening is off. Press l, then add them."));
        }
        let cursor = self.share_cursor();
        let item = self
            .shared
            .get_mut(cursor)
            .ok_or_else(|| anyhow!("Pick a shared vault first."))?;
        if item.my_role != Some(Role::Owner) {
            return Err(anyhow!("Only owners can add people."));
        }
        let reference = Arc::clone(&item.reference);
        let own = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let key = identity.sign_key();
        let vault = item
            .vault_mut()
            .ok_or_else(|| anyhow!("That vault is still syncing."))?;
        let known = vault.log.members().iter().any(|member| {
            member.client_id == card.cert.client_id && member.root_vk == card.root_vk
        });
        if !known {
            let action = LogAction::Add {
                client_id: card.cert.client_id,
                root_vk: card.root_vk.clone(),
                role,
            };
            let entry = vault.log.propose(&key, own, action, unix_ms())?;
            vault.log.append(entry)?;
            vault.save_log(&reference.seed)?;
        }
        let invitation = Invitation::issue(
            &Inviter {
                sign: &key,
                cert: own,
            },
            &vault.log,
            card,
            &Offer {
                seed: &reference.seed,
                name: &reference.name,
                hints: &hints,
            },
            unix_ms(),
        )?
        .to_text()?;
        let people = vault.log.members().len();
        item.people = people;
        Ok((
            Zeroizing::new(invitation),
            vault_number(&reference.vault_id),
        ))
    }

    pub(super) fn invitation_pasted(&self, text: &str, ctx: &mut Ctx) -> Step {
        match self.open_invitation(&crate::app::flows::share_file::invitation_text(text)) {
            Ok(opened) => Step::JoinConfirm(Box::new(opened)),
            Err(error) => {
                Self::fail(ctx, &error);
                Step::PasteInvite
            }
        }
    }

    fn open_invitation(&self, text: &str) -> Result<Opened> {
        let invalid = || anyhow!("That invitation is not for this device, or did not verify.");
        let identity = self.identity.as_deref().ok_or_else(invalid)?;
        let invitation = Invitation::from_text(text).map_err(|_| invalid())?;
        let card = self.my_card().map_err(|_| invalid())?;
        let opened = invitation
            .open(
                &identity.share_keys().ec_secret()?,
                identity.share_keys().kem_seed(),
                &card,
                unix_ms(),
            )
            .map_err(|_| invalid())?;
        if self
            .shared
            .iter()
            .any(|item| &item.reference.vault_id == opened.log.vault_id())
        {
            return Err(anyhow!("You already have this vault."));
        }
        Ok(opened)
    }

    pub(super) fn finish_join_flow(&mut self, opened: Box<Opened>, ctx: &mut Ctx) -> Step {
        match self.join(*opened, ctx) {
            Ok(()) => Step::Overview,
            Err(error) => {
                Self::fail(ctx, &error);
                Step::Overview
            }
        }
    }

    fn join(&mut self, opened: Opened, ctx: &mut Ctx) -> Result<()> {
        if self.vault.is_none() {
            return Err(busy());
        }
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let Opened {
            seed,
            name,
            log,
            hints,
            head,
            inviter_id,
            inviter_vk,
            ..
        } = opened;
        let reference = Arc::new(SharedRef {
            vault_id: *log.vault_id(),
            anchor: *log.anchor(),
            seed,
            name,
            hints,
            epoch: log.epoch(),
            retired: Vec::new(),
            introduction: Some(Introduction {
                head,
                inviter_id,
                inviter_vk,
            }),
        });
        join_shared_vault(&self.base, &reference, &log)?;
        self.shared.push(SharedItem::joined(
            &self.base,
            Arc::clone(&reference),
            &identity,
        ));
        self.ensure_p2p();
        if let (Some(p2p), Some(item)) = (self.p2p.as_deref(), self.shared.last()) {
            p2p.provider.serve(Arc::clone(&item.reference));
            crate::app::p2p::fetch(p2p, item);
        }
        self.remember(&reference, ctx);
        Ok(())
    }

    pub(super) fn retry_selected(&mut self, ctx: &mut Ctx) {
        let cursor = self.share_cursor();
        let ready = self.shared.get(cursor).map(SharedItem::ready);
        match ready {
            None => ctx.toast(Tone::Info, "Nothing to sync yet."),
            Some(true) => {
                self.ensure_p2p();
                let checked = self
                    .p2p
                    .as_deref()
                    .zip(self.shared.get(cursor))
                    .map(|(p2p, item)| crate::app::p2p::fetch(p2p, item))
                    .is_some();
                if checked {
                    ctx.toast(Tone::Info, "Checking with the members.");
                } else {
                    ctx.toast(Tone::Warn, "Could not start the node.");
                }
            }
            Some(false) => {
                self.ensure_p2p();
                if self.retry(cursor) {
                    ctx.toast(Tone::Info, "Asking the members again.");
                } else {
                    ctx.toast(Tone::Warn, "Could not start the node.");
                }
            }
        }
    }

    pub(super) fn cycle_listen(&mut self, ctx: &mut Ctx) {
        let mut prefs = self.info.prefs.clone().unwrap_or_default();
        prefs.p2p_listen = prefs.p2p_listen.next();
        self.info.prefs = Some(prefs.clone());
        self.restart_p2p();
        self.run(Op::SavePrefs(Box::new(prefs)), Task::Save, ctx);
    }
}

/// The fingerprint of this account, for display.
#[must_use]
pub fn my_print(unlocked: &Unlocked) -> Option<sharing::Fingerprint> {
    let identity = unlocked.identity.as_deref()?;
    let cert = identity.devices().first()?;
    Some(account_fingerprint(&cert.client_id, identity.root_vk()))
}
