//! Background job dispatch handling on [`App`].

use crate::app::App;
use crate::app::flows::gate::AlertState;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::screen::Screen;
use crate::app::worker::JobResult;
use crate::ui::widgets::toast::Tone;
use crate::vault::discover::discover;
use crate::vault::error::UnlockError;

impl App {
    pub(super) fn on_job(&mut self, ticket: u64, result: JobResult) {
        if let JobResult::Bench(time) = result {
            self.ctx.kdf_fast = time;
            return;
        }
        let waited = self
            .ctx
            .pending
            .is_some_and(|pending| pending.ticket == ticket);
        if waited {
            self.ctx.pending = None;
        }
        match (result, &mut self.screen) {
            (JobResult::Vault(vault, outcome), Screen::Unlocked(state))
                if state.vault.is_none() =>
            {
                state.on_result(vault, outcome, &mut self.ctx);
            }
            (JobResult::Opened(outcome), Screen::Unlock(state)) if waited => match outcome {
                Ok(vault) => {
                    if let Some(prefs) = vault.meta.prefs.as_ref() {
                        self.ctx.apply_prefs(prefs);
                    }
                    let vaults = std::mem::take(&mut state.vaults);
                    let (current, beacon) = (state.current, self.ctx.beacon);
                    let mut unlocked =
                        Unlocked::new(vault, vaults, current, beacon).with_held(state.held.take());
                    unlocked.start_https_sync(&self.ctx);
                    self.screen = Screen::Unlocked(Box::new(unlocked));
                    self.ctx.idle.touch(self.ctx.now);
                    self.ctx.redraw();
                }
                Err(
                    error @ (UnlockError::Rollback { .. }
                    | UnlockError::Conflict { .. }
                    | UnlockError::MetaMissing),
                ) => {
                    if let Some(vault) = state.vault().cloned() {
                        self.screen = Screen::Alert(Box::new(AlertState::new(error, vault)));
                        self.ctx.redraw();
                    }
                }
                Err(error) => state.failed(error, self.ctx.now),
            },
            (JobResult::ImportParsed(outcome), Screen::Import(state)) if waited => {
                state.parsed(outcome, &mut self.ctx);
            }
            (JobResult::ImportParsed(outcome), Screen::Unlocked(state)) if waited => {
                if let View::Import(import) = &mut state.view {
                    import.parsed(outcome, &mut self.ctx);
                }
            }
            (JobResult::Created(outcome), Screen::Create(state)) if waited => match outcome {
                Ok(vault) => {
                    let message = state.imported.map_or_else(
                        || {
                            String::from(
                                "Vault created. Your recovery phrase is the only way back in: keep it safe.",
                            )
                        },
                        |(count, source)| {
                            format!(
                                "Vault created with {count} records from {source}. Delete the export \
                                 file now: it holds your passwords in plain text.",
                            )
                        },
                    );
                    self.opened(vault, &message);
                }
                Err(message) => state.failed(&message, &mut self.ctx),
            },
            (JobResult::Restored(outcome), Screen::Restore(state)) if waited => match outcome {
                Ok(vault) => {
                    let held = state.held.take();
                    self.opened_holding(vault, "Vault restored on this device.", held);
                }
                Err(UnlockError::Io) => {
                    state.failed("Couldn't write the restored vault on this device.");
                }
                Err(
                    error @ (UnlockError::Peer(_)
                    | UnlockError::WrongVault
                    | UnlockError::Rollback { .. }
                    | UnlockError::Conflict { .. }),
                ) => state.failed(error.message()),
                Err(_) => state.failed("Couldn't unlock that vault file with this phrase."),
            },
            (JobResult::Adopted(outcome), Screen::Unlocked(state)) if waited => match outcome {
                Ok(vault) => self.opened(vault, "Your vault arrived from your other device."),
                Err(error) => state.adopt_failed(error, &mut self.ctx),
            },
            // Cancelled or outlived its screen: dropping it wipes what it carries.
            (_, _) => {}
        }
    }

    pub(super) fn opened(&mut self, mut vault: Box<crate::vault::Vault>, message: &str) {
        seed_cli_sync_prefs(&mut vault, &self.ctx);
        let vaults = discover(&self.ctx.base);
        let current = vaults
            .iter()
            .position(|known| known.vault_id.as_ref() == Some(vault.session.vault_id()))
            .unwrap_or(0);
        if let Some(prefs) = vault.meta.prefs.as_ref() {
            self.ctx.apply_prefs(prefs);
        }
        let beacon = self.ctx.beacon;
        let mut unlocked = Unlocked::new(vault, vaults, current, beacon);
        unlocked.start_https_sync(&self.ctx);
        self.screen = Screen::Unlocked(Box::new(unlocked));
        self.ctx.idle.touch(self.ctx.now);
        self.ctx.toast(Tone::Success, message.to_owned());
        self.ctx.redraw();
    }
}

pub(super) fn seed_cli_sync_prefs(vault: &mut crate::vault::Vault, ctx: &crate::app::ctx::Ctx) {
    if ctx.sync_servers.is_empty() && ctx.sync_proxy.is_none() {
        return;
    }
    let mut prefs = vault.meta.prefs.clone().unwrap_or_default();
    let need_servers = prefs.sync_servers.is_empty() && !ctx.sync_servers.is_empty();
    let need_proxy = prefs.sync_proxy.is_none() && ctx.sync_proxy.is_some();
    if !need_servers && !need_proxy {
        return;
    }
    if need_servers {
        prefs.sync_servers.clone_from(&ctx.sync_servers);
    }
    if need_proxy {
        prefs.sync_proxy.clone_from(&ctx.sync_proxy);
    }
    vault.meta.prefs = Some(prefs);
    let _ = local::save_meta(&vault.paths, &vault.meta, &vault.session);
}
