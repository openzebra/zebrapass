//! Outcome handling after a worker vault mutation finishes.

use crate::app::ctx::Ctx;
use crate::app::flows::factors::Anim;
use crate::app::flows::unlocked::{Unlocked, VaultInfo, View};
use crate::ui::widgets::toast::Tone;
use crate::vault::Vault;
use crate::vault::ops::Outcome;

impl Unlocked {
    /// A job handed the vault back.
    pub fn on_result(&mut self, vault: Box<Vault>, result: Result<Outcome, String>, ctx: &mut Ctx) {
        self.info = VaultInfo::from(&*vault);
        self.vault = Some(vault);
        self.refresh_personal();
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(message) => {
                ctx.toast(Tone::Danger, message);
                return;
            }
        };
        match outcome {
            Outcome::Saved(id) => self.on_saved(id, ctx),
            Outcome::Deleted(id) => {
                self.refresh();
                self.sync_push_personal(Some(id));
                ctx.toast(
                    Tone::Success,
                    "Record deleted. It stays in history until cleared.",
                );
            }
            Outcome::Restored(id, revision) => {
                self.view = View::Home;
                self.refresh();
                self.select(id);
                self.sync_push_personal(Some(id));
                ctx.toast(Tone::Success, format!("Restored as revision {revision}."));
            }
            Outcome::HistoryCleared => {
                self.refresh();
                self.sync_push_personal(None);
                ctx.toast(Tone::Success, "History cleared.");
            }
            Outcome::Renamed => ctx.toast(Tone::Success, "Renamed on this device."),
            Outcome::PrefsSaved => self.on_prefs_saved(ctx),
            Outcome::FactorAdded(kind) => {
                self.animate(Anim::Add, ctx);
                self.sync_push_personal(None);
                ctx.toast(Tone::Success, format!("Added {}.", kind.noun()));
            }
            Outcome::FactorRemoved => {
                self.sync_push_personal(None);
                ctx.toast(Tone::Success, "Wrap removed. The vault key did not change.");
            }
            Outcome::PasswordChanged => {
                self.sync_push_personal(None);
                ctx.toast(Tone::Success, "Password changed.");
            }
            Outcome::PinChanged => {
                ctx.toast(
                    Tone::Success,
                    "Device PIN changed. The vault did not change.",
                );
            }
            Outcome::Rotated(revoked) => self.on_rotated(revoked, ctx),
            Outcome::RecoveryDropped => {
                self.sync_push_personal(None);
                ctx.toast(Tone::Warn, "Recovery wrap dropped from this copy.");
            }
            Outcome::Imported(merged) => {
                if !merged.ids.is_empty() {
                    self.promote_if_placeholder();
                }
                self.sync_push_personal(None);
                crate::app::flows::import_vault::done(self, &merged, ctx);
            }
            Outcome::BackupExported(dest) => {
                ctx.toast(
                    Tone::Success,
                    format!("Exported backup to {}", dest.display()),
                );
            }
            Outcome::Health(report) => {
                self.health = Some(report);
                self.view = View::Health(0);
            }
        }
    }

    fn on_saved(&mut self, id: u32, ctx: &mut Ctx) {
        // A write made from the share screen is the reference to a
        // shared vault: stay there, and select nothing.
        let on_share = matches!(self.view, View::Sync(_));
        self.promote_if_placeholder();
        self.refresh();
        self.sync_push_personal(Some(id));
        if !on_share {
            self.view = View::Home;
            self.select(id);
            ctx.toast(Tone::Success, "Saved.");
        }
    }

    fn on_prefs_saved(&mut self, ctx: &mut Ctx) {
        if let Some(prefs) = self.info.prefs.as_ref() {
            ctx.apply_prefs(prefs);
            if let Some(settings) = self.settings.as_deref_mut() {
                settings.saved = prefs.clone();
            }
        }
        self.restart_zsync(ctx);
        ctx.toast(
            Tone::Success,
            "Settings saved for this vault on this device.",
        );
    }

    fn on_rotated(&mut self, revoked: bool, ctx: &mut Ctx) {
        let target = self.pending_revoke.take();
        self.refresh();
        self.sync_push_personal_rotation(target);
        self.animate(if revoked { Anim::Revoke } else { Anim::Rotate }, ctx);
        let what = if revoked {
            "Revoked. New vault key"
        } else {
            "New vault key"
        };
        ctx.toast(
            Tone::Success,
            format!("{what} · generation {}.", self.info.generation),
        );
    }

    pub(crate) const fn animate(&mut self, anim: Anim, ctx: &Ctx) {
        if let View::Factors(factors) = &mut self.view {
            factors.anim = Some((anim, ctx.now));
        }
    }
}
