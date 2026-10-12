//! Leaving a shared vault, or forgetting one.
//!
//! Leaving is a signed entry in the member log, not a deletion: the others
//! only learn of it when a device fetches the log from this one. So the
//! device keeps the vault and keeps serving it until a member has fetched
//! the log, and only then deletes its copy and the reference in the personal
//! vault. The vault's key is not replaced by a leave; an owner has to do
//! that. Until then the person still holds the old key, but they are no
//! longer a member, so the others refuse their device and what they write.

use anyhow::{anyhow, Result};
use local::purge_shared_vault;
use memberlog::Role;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::home::Filter;
use crate::app::flows::share::Step;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;

/// What confirming does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaveMode {
    /// Write the leave, stay until a member has it, then delete.
    Leave,
    /// Delete this copy now, without telling anyone.
    Forget,
}

impl Unlocked {
    pub(super) fn begin_leave(&self, ctx: &mut Ctx) -> Step {
        let cursor = self.share_cursor();
        let Some(item) = self.shared.get(cursor) else {
            ctx.toast(Tone::Info, "No shared vault is selected.");
            return Step::Overview;
        };
        let alone = item.people <= 1;
        if item.ready() && item.my_role.is_some() && !alone {
            let other_owner = self
                .people(cursor)
                .iter()
                .any(|person| person.role == Role::Owner);
            if item.my_role == Some(Role::Owner) && !other_owner {
                ctx.toast(
                    Tone::Info,
                    "You are the only owner. Make someone else an owner first (c).",
                );
                return Step::Overview;
            }
            return Step::LeaveConfirm(LeaveMode::Leave);
        }
        Step::LeaveConfirm(LeaveMode::Forget)
    }

    pub(super) fn leave_step(
        &mut self,
        mode: LeaveMode,
        action: Option<Action>,
        ctx: &mut Ctx,
    ) -> Step {
        match action {
            Some(Action::Back) => Step::Overview,
            Some(Action::Confirm) => match self.finish_leave(mode, ctx) {
                Ok(()) => Step::Overview,
                Err(error) => {
                    ctx.toast(Tone::Warn, error.to_string());
                    Step::LeaveConfirm(mode)
                }
            },
            _ => Step::LeaveConfirm(mode),
        }
    }

    fn finish_leave(&mut self, mode: LeaveMode, ctx: &mut Ctx) -> Result<()> {
        let index = self.share_cursor();
        let item = self
            .shared
            .get(index)
            .ok_or_else(|| anyhow!("No shared vault is selected."))?;
        let (vault_id, name) = (item.reference.vault_id, item.name().to_owned());
        match mode {
            LeaveMode::Forget => {
                self.forget_vault(&vault_id)?;
                ctx.toast(Tone::Success, format!("{name} is gone from this device."));
            }
            LeaveMode::Leave => {
                self.ensure_p2p();
                let provider = self
                    .p2p
                    .as_deref()
                    .map(|p2p| &p2p.provider)
                    .ok_or_else(|| anyhow!("Could not start the node."))?;
                provider.with_vault(&vault_id, |vault, reference, identity| {
                    vault.leave(reference, identity)
                })?;
                self.reload_shared(&vault_id);
                self.check_in_now(&vault_id);
                ctx.toast(
                    Tone::Success,
                    format!(
                        "You left {name}. This device stays online until a member has \
                         fetched that, then deletes its copy."
                    ),
                );
            }
        }
        Ok(())
    }

    /// Delete everything this device holds of a shared vault, reference
    /// included. The reference goes first: a crash afterwards leaves files
    /// nothing points at, never a reference to files that are gone.
    pub(super) fn forget_vault(&mut self, vault_id: &[u8; 16]) -> Result<()> {
        if !self.forget_reference(vault_id) {
            return Err(anyhow!(
                "Could not update the personal vault. Nothing changed."
            ));
        }
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.provider.unserve(vault_id);
        }
        if let Some(at) = self
            .shared
            .iter()
            .position(|item| &item.reference.vault_id == vault_id)
        {
            self.shared.remove(at);
            let last = self.shared.len().saturating_sub(1);
            if let crate::app::flows::unlocked::View::Sync(share) = &mut self.view {
                share.cursor = share.cursor.min(last);
            }
        }
        if matches!(&self.home.filter, Filter::Shared(open, _) if open == vault_id) {
            self.home.filter = Filter::All;
        }
        self.home.detail = None;
        self.load_detail();
        purge_shared_vault(&self.base, vault_id)
    }

    /// Leaves this device made that a member has now fetched.
    pub fn finish_delivered_leaves(&mut self, ctx: &mut Ctx) {
        let delivered = self
            .p2p
            .as_deref()
            .map(|p2p| p2p.provider.take_delivered())
            .unwrap_or_default();
        for vault_id in delivered {
            let name = self
                .shared_item(&vault_id)
                .map(|item| item.name().to_owned());
            if let Some(name) = name {
                match self.forget_vault(&vault_id) {
                    Ok(()) => ctx.toast(
                        Tone::Success,
                        format!("Your leave of {name} reached the members. The copy is deleted."),
                    ),
                    Err(error) => ctx.toast(Tone::Warn, error.to_string()),
                }
            }
        }
    }

    /// Delete the record that points at shared vault `vault_id`.
    pub fn forget_reference(&mut self, vault_id: &[u8; 16]) -> bool {
        let Some(vault) = self.vault.as_deref_mut() else {
            return false;
        };
        let found = session::list_records(&vault.session)
            .unwrap_or_default()
            .iter()
            .find(|row| {
                session::open_record(&vault.session, row.id)
                    .ok()
                    .and_then(|doc| local::SharedRef::from_document(&doc).ok().flatten())
                    .is_some_and(|known| &known.vault_id == vault_id)
            })
            .map(|row| row.id);
        match found {
            Some(id) => {
                session::delete_record(&mut vault.session, &mut vault.file, id).is_ok()
                    && vault.persist().is_ok()
            }
            None => true,
        }
    }
}
