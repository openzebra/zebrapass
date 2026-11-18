//! Adopting arrived shared vault snapshots and saving updated references.

use std::path::PathBuf;
use std::sync::Arc;

use p2p_net::{Joined, finish_join};

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;
use crate::vault::shared::Status;

impl Unlocked {
    pub(crate) fn arrived(
        &mut self,
        vault_id: &[u8; 16],
        log: &[u8],
        snapshot: Vec<u8>,
        rekey: Option<&[u8]>,
        ctx: &mut Ctx,
    ) {
        let Some(identity) = self.identity.clone() else {
            return;
        };
        let base: PathBuf = self.base.clone();
        let Some(index) = self
            .shared
            .iter()
            .position(|item| &item.reference.vault_id == vault_id)
        else {
            return;
        };
        let Some(item) = self.shared.get(index) else {
            return;
        };
        let (name, was_ready) = (item.name().to_owned(), item.ready());
        let joined = match self.p2p.as_ref() {
            Some(p2p) => p2p
                .provider
                .locked(|| {
                    finish_join(
                        &base,
                        &item.reference,
                        &identity,
                        log,
                        snapshot,
                        rekey,
                        item.known(),
                    )
                })
                .unwrap_or_else(|| Err(anyhow::anyhow!("shared vault unavailable"))),
            None => finish_join(
                &base,
                &item.reference,
                &identity,
                log,
                snapshot,
                rekey,
                item.known(),
            ),
        };
        match joined {
            Ok(Joined::Opened(vault)) => {
                let settled = self
                    .shared
                    .get(index)
                    .map(|item| Arc::new(item.reference.settled()));
                // A failed store keeps the introduction, which only matters
                // while the vault is pending.
                if let Some(settled) = settled.filter(|settled| self.save_reference(settled)) {
                    if let Some(p2p) = self.p2p.as_deref() {
                        p2p.provider.serve(Arc::clone(&settled));
                    }
                    if let Some(item) = self.shared.get_mut(index) {
                        item.reference = settled;
                    }
                }
                if let Some(item) = self.shared.get_mut(index) {
                    item.adopt(*vault, &identity);
                    let message = format!("{name} is synced: {} records.", item.cache.len());
                    ctx.toast(Tone::Success, message);
                }
            }
            Ok(Joined::Rekey(plan)) => self.take_new_key(index, *plan, ctx),
            Ok(Joined::Unchanged) => {
                if let Some(item) = self.shared.get_mut(index) {
                    item.waiting = None;
                }
            }
            Err(_) if was_ready => {
                let message = format!("An update for {name} did not verify and was ignored.");
                ctx.toast(Tone::Warn, message);
            }
            Err(_) => {
                if let Some(item) = self.shared.get_mut(index) {
                    item.status = Status::Unavailable;
                }
                let message = format!("{name} did not verify and was not opened.");
                ctx.toast(Tone::Danger, message);
            }
        }
        ctx.redraw();
    }

    /// An owner replaced the vault's seed and this member got it: store the
    /// new reference first, then move the files. A crash between the two
    /// leaves files that still open through the retired seed.
    pub(crate) fn take_new_key(&mut self, index: usize, plan: local::RekeyPlan, ctx: &mut Ctx) {
        let reference = Arc::new(plan.reference().settled());
        if !self.save_reference(&reference) {
            ctx.toast(Tone::Danger, "Could not store the new key. Try again.");
            return;
        }
        let Ok(vault) = plan.commit() else {
            if let Some(item) = self.shared.get_mut(index) {
                item.status = Status::Unavailable;
            }
            ctx.toast(Tone::Danger, "The vault could not be updated.");
            return;
        };
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.provider.serve(Arc::clone(&reference));
        }
        let Some(identity) = self.identity.clone() else {
            return;
        };
        if let Some(item) = self.shared.get_mut(index) {
            item.reference = reference;
            item.adopt(vault, &identity);
            let message = format!("{} has a new key from its owner.", item.name());
            ctx.toast(Tone::Success, message);
        }
    }

    /// Write `reference` over the record that points at this shared vault in
    /// the personal vault, now. Returns whether it was stored.
    pub fn save_reference(&mut self, reference: &local::SharedRef) -> bool {
        let Some(vault) = self.vault.as_deref_mut() else {
            return false;
        };
        let Some(id) = session::list_records(&vault.session)
            .unwrap_or_default()
            .iter()
            .find(|row| {
                session::open_record(&vault.session, row.id)
                    .ok()
                    .and_then(|doc| local::SharedRef::from_document(&doc).ok().flatten())
                    .is_some_and(|known| known.vault_id == reference.vault_id)
            })
            .map(|row| row.id)
        else {
            return false;
        };
        session::write_record(
            &mut vault.session,
            &mut vault.file,
            Some(id),
            &reference.to_document(),
        )
        .is_ok()
            && vault.persist().is_ok()
    }
}
