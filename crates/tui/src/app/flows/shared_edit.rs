//! Changing records of the vault the list shows: the personal vault through
//! the worker, a shared vault in place by its writers.

use local::Edit;
use record::Document;
use session::Session;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::home::Filter;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::p2p::P2p;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::Op;

impl Unlocked {
    /// The session of the vault the list shows.
    #[must_use]
    pub fn active_session(&self) -> Option<&Session> {
        match &self.home.filter {
            Filter::Shared(vault_id, _) => self
                .shared_item(vault_id)
                .and_then(crate::vault::shared::SharedItem::session),
            _ => self.vault.as_ref().map(|vault| &vault.session),
        }
    }

    /// Whether this account may add, change and delete records of the vault
    /// the list shows; says why not when it may not.
    pub fn may_edit_here(&self, ctx: &mut Ctx) -> bool {
        let Filter::Shared(vault_id, _) = &self.home.filter else {
            return true;
        };
        let writer = self
            .shared_item(vault_id)
            .and_then(|item| item.my_role.zip(Some(item.ready())))
            .is_some_and(|(role, ready)| ready && role.can_write());
        if !writer {
            ctx.toast(Tone::Info, "You can read this vault, not change it.");
        }
        writer
    }

    /// Save `doc` as record `id`, or as a new record.
    pub fn write_active(&mut self, id: Option<u32>, doc: Box<Document>, ctx: &mut Ctx) {
        match (&self.home.filter, id) {
            (Filter::Shared(..), Some(id)) => self.change_shared(Edit::Update(id, doc), ctx),
            (Filter::Shared(..), None) => self.change_shared(Edit::Create(doc), ctx),
            _ => self.run(Op::Write { id, doc }, Task::Save, ctx),
        }
    }

    /// Delete record `id`.
    pub fn delete_active(&mut self, id: u32, ctx: &mut Ctx) {
        if self.in_shared() {
            self.change_shared(Edit::Delete(id), ctx);
        } else {
            self.run(Op::Delete(id), Task::Save, ctx);
        }
    }

    fn change_shared(&mut self, edit: Edit, ctx: &mut Ctx) {
        let Filter::Shared(vault_id, _) = self.home.filter.clone() else {
            return;
        };
        let deleting = matches!(edit, Edit::Delete(_));
        self.ensure_p2p();
        let saved = self.p2p.as_deref().map(|p2p| {
            p2p.provider
                .with_vault(&vault_id, |vault, reference, identity| {
                    vault.edit(reference, identity, edit)
                })
        });
        match saved {
            Some(Ok(id)) => {
                self.reload_shared(&vault_id);
                if !deleting {
                    self.view = View::Home;
                    self.select(id);
                }
                self.check_in_now(&vault_id);
                ctx.toast(
                    Tone::Success,
                    if deleting {
                        "Record deleted."
                    } else {
                        "Saved."
                    },
                );
            }
            Some(Err(error)) => ctx.toast(Tone::Danger, format!("Not saved: {error}")),
            None => ctx.toast(Tone::Warn, "Could not start the node."),
        }
        ctx.redraw();
    }

    /// Read a shared vault again from disk: what peers sent or this device
    /// wrote is only ever on disk.
    pub fn reload_shared(&mut self, vault_id: &[u8; 16]) {
        let Some(identity) = self.identity.clone() else {
            return;
        };
        let base = self.base.clone();
        if let Some(item) = self
            .shared
            .iter_mut()
            .find(|item| &item.reference.vault_id == vault_id)
        {
            item.reload(&base, &identity);
        }
        self.home.detail = None;
        self.load_detail();
    }

    /// Trade revisions with the vault's members now.
    pub fn check_in_now(&self, vault_id: &[u8; 16]) {
        if let (Some(p2p), Some(item)) = (self.p2p.as_deref(), self.shared_item(vault_id)) {
            crate::app::p2p::check_in(p2p, item);
        }
    }

    /// The shared vaults to check in with, a while after the last time.
    pub fn check_in_due(&mut self) {
        if !self.p2p.as_deref_mut().is_some_and(P2p::check_due) {
            return;
        }
        let due: Vec<[u8; 16]> = self
            .shared
            .iter()
            .filter(|item| item.ready())
            .map(|item| item.reference.vault_id)
            .collect();
        for vault_id in &due {
            self.check_in_now(vault_id);
        }
    }
}
