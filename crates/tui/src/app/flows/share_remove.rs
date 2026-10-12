//! Removing a person from a shared vault.
//!
//! Removal is a key change, not only a log entry: the vault gets a new seed
//! and a new vault key, so what is written afterwards is closed to the person
//! who leaves. Everyone else receives the new seed over the authenticated
//! channel the next time their device connects.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use local::{apply_rotation, plan_rotation, Replace};
use memberlog::Role;
use sharing::{account_fingerprint, Fingerprint};

use crate::app::ctx::Ctx;
use crate::app::flows::share::Step;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::ui::widgets::toast::Tone;
use crate::vault::records::build_cache;

/// Someone else in a shared vault.
#[derive(Clone, Copy, Debug)]
pub struct Person {
    /// The account id.
    pub client_id: [u8; 64],
    /// The fingerprint two people compared when this person was added.
    pub print: Fingerprint,
    /// What they may do.
    pub role: Role,
}

impl Unlocked {
    /// The other people in shared vault number `vault`, when it is open.
    #[must_use]
    pub fn people(&self, vault: usize) -> Vec<Person> {
        let mine = self
            .identity
            .as_deref()
            .and_then(|identity| identity.devices().first())
            .map(|cert| cert.client_id);
        let Some(open) = self.shared.get(vault).and_then(|item| match &item.status {
            crate::vault::shared::Status::Ready(vault) => Some(vault),
            _ => None,
        }) else {
            return Vec::new();
        };
        open.log
            .members()
            .iter()
            .filter(|member| Some(member.client_id) != mine)
            .map(|member| Person {
                client_id: member.client_id,
                print: account_fingerprint(&member.client_id, &member.root_vk),
                role: member.role,
            })
            .collect()
    }

    fn selected_vault(&self) -> usize {
        match &self.view {
            View::Sync(share) => share.cursor,
            _ => 0,
        }
    }

    pub(super) fn begin_remove(&self, ctx: &mut Ctx) -> Step {
        let cursor = self.selected_vault();
        let picked = self
            .shared
            .get(cursor)
            .map(|item| (item.ready(), item.my_role));
        let message = match picked {
            None => "No shared vault is selected.",
            Some((false, _)) => "That vault is still syncing.",
            Some((true, role)) if role != Some(Role::Owner) => "Only owners can remove people.",
            Some(_) if self.people(cursor).is_empty() => "No one else is in this vault.",
            Some(_) => return Step::PickPerson(0),
        };
        ctx.toast(Tone::Info, message);
        Step::Overview
    }

    pub(super) fn confirm_person(&self, pick: usize) -> Step {
        self.people(self.selected_vault())
            .get(pick)
            .map_or(Step::Overview, |person| Step::RemoveConfirm {
                target: person.client_id,
                print: person.print,
                role: person.role,
            })
    }

    pub(super) fn finish_remove(
        &mut self,
        target: [u8; 64],
        print: Fingerprint,
        role: Role,
        ctx: &mut Ctx,
    ) -> Step {
        match self.remove_person(target) {
            Ok(others) => {
                let message = match others {
                    0 => String::from("Removed. No one else is in this vault."),
                    1 => String::from(
                        "Removed. One other person gets the new key when they connect.",
                    ),
                    n => format!("Removed. {n} other people get the new key when they connect."),
                };
                ctx.toast(Tone::Success, message);
                Step::Overview
            }
            Err(error) => {
                ctx.toast(Tone::Warn, error.to_string());
                Step::RemoveConfirm {
                    target,
                    print,
                    role,
                }
            }
        }
    }

    /// Rotate the vault, removing `target`; returns how many other people
    /// remain besides this account. The new seed is stored in the personal
    /// vault before anything else changes, so a crash cannot lose it.
    fn remove_person(&mut self, target: [u8; 64]) -> Result<usize> {
        self.replace_key(Replace::Remove(target))
    }

    /// Replace the vault's seed and vault key as `replace` says; returns how
    /// many other people remain besides this account.
    pub(super) fn replace_key(&mut self, replace: Replace) -> Result<usize> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| anyhow!("This vault has no sync identity."))?;
        let index = self.selected_vault();
        let item = self
            .shared
            .get(index)
            .ok_or_else(|| anyhow!("No shared vault is selected."))?;
        if item.my_role != Some(Role::Owner) {
            return Err(anyhow!("Only owners can change the key."));
        }
        let epoch = match &item.status {
            crate::vault::shared::Status::Ready(vault) => vault.log.epoch(),
            _ => return Err(anyhow!("That vault is still syncing.")),
        };
        let next = plan_rotation(&item.reference, epoch)?;
        if !self.save_reference(&next) {
            return Err(anyhow!("Could not store the new key. Nothing changed."));
        }
        let item = self
            .shared
            .get_mut(index)
            .ok_or_else(|| anyhow!("No shared vault is selected."))?;
        let (people, cache) = {
            let vault = item
                .vault_mut()
                .ok_or_else(|| anyhow!("That vault is still syncing."))?;
            apply_rotation(vault, &next, &identity, replace)?;
            (
                vault.log.members().len(),
                build_cache(&vault.session).unwrap_or_default(),
            )
        };
        let next = Arc::new(next);
        item.reference = Arc::clone(&next);
        item.people = people;
        item.leaves = 0;
        item.cache = cache;
        item.stale = false;
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.provider.serve(next);
        }
        Ok(people.saturating_sub(1))
    }
}
