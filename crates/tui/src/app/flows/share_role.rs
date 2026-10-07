//! Changing what a person may do in a shared vault.
//!
//! A role change is a signed entry in the member log, written by an owner.
//! The vault keeps its key: a person made a reader can still read what they
//! could before, and their writes are refused from now on.

use anyhow::{anyhow, Result};
use memberlog::Role;
use sharing::Fingerprint;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::share::{cycle, Step};
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;

impl Unlocked {
    pub(super) fn begin_role(&self, ctx: &mut Ctx) -> Step {
        let cursor = self.share_cursor();
        let picked = self
            .shared
            .get(cursor)
            .map(|item| (item.ready(), item.my_role));
        let message = match picked {
            None => "No shared vault is selected.",
            Some((false, _)) => "That vault is still syncing.",
            Some((true, role)) if role != Some(Role::Owner) => "Only owners can change roles.",
            Some(_) if self.people(cursor).is_empty() => "No one else is in this vault.",
            Some(_) => return Step::PickRole(0),
        };
        ctx.toast(Tone::Info, message);
        Step::Overview
    }

    pub(super) fn pick_role_step(&self, pick: usize, action: Option<Action>) -> Step {
        let count = self.people(self.share_cursor()).len();
        match action {
            Some(Action::Back) => Step::Overview,
            Some(Action::Up) => Step::PickRole(pick.saturating_sub(1)),
            Some(Action::Down) => Step::PickRole((pick + 1).min(count.saturating_sub(1))),
            Some(Action::Confirm) => self.confirm_role_person(pick),
            _ => Step::PickRole(pick),
        }
    }

    pub(super) fn role_confirm_step(
        &mut self,
        target: [u8; 64],
        print: Fingerprint,
        (from, to): (Role, Role),
        action: Option<Action>,
        ctx: &mut Ctx,
    ) -> Step {
        let to = match action {
            Some(Action::Back) => return Step::Overview,
            Some(Action::Confirm) => return self.finish_role(target, print, from, to, ctx),
            Some(Action::Left) => cycle(to, false),
            Some(Action::Right) => cycle(to, true),
            _ => to,
        };
        Step::RoleConfirm {
            target,
            print,
            from,
            to,
        }
    }

    fn confirm_role_person(&self, pick: usize) -> Step {
        self.people(self.share_cursor())
            .get(pick)
            .map_or(Step::Overview, |person| Step::RoleConfirm {
                target: person.client_id,
                print: person.print,
                from: person.role,
                to: person.role,
            })
    }

    pub(super) fn finish_role(
        &mut self,
        target: [u8; 64],
        print: Fingerprint,
        from: Role,
        to: Role,
        ctx: &mut Ctx,
    ) -> Step {
        if from == to {
            ctx.toast(Tone::Info, "Pick a different role with ← →.");
            return Step::RoleConfirm {
                target,
                print,
                from,
                to,
            };
        }
        match self.change_role(target, to) {
            Ok(()) => {
                ctx.toast(Tone::Success, "Role changed.");
                Step::Overview
            }
            Err(error) => {
                ctx.toast(Tone::Warn, error.to_string());
                Step::RoleConfirm {
                    target,
                    print,
                    from,
                    to,
                }
            }
        }
    }

    fn change_role(&mut self, target: [u8; 64], role: Role) -> Result<()> {
        let item = self
            .shared
            .get(self.share_cursor())
            .ok_or_else(|| anyhow!("No shared vault is selected."))?;
        let vault_id = item.reference.vault_id;
        self.ensure_p2p();
        let provider = self
            .p2p
            .as_deref()
            .map(|p2p| &p2p.provider)
            .ok_or_else(|| anyhow!("Could not start the node."))?;
        provider.with_vault(&vault_id, |vault, reference, identity| {
            vault.set_role(reference, identity, target, role)
        })?;
        self.reload_shared(&vault_id);
        self.check_in_now(&vault_id);
        Ok(())
    }
}
