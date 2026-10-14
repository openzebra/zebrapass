//! A placeholder vault asks the network for the account's vault: when
//! another device is found, its vault is fetched and opened with the
//! password that unlocked this one.

use std::net::SocketAddr;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::Dialog;
use crate::app::flows::unlocked::Unlocked;
use crate::app::screen::Screen;
use crate::app::worker::Job;
use crate::ui::widgets::toast::Tone;
use crate::vault::adopt::{is_placeholder, unmark_placeholder, AdoptRequest, Held};
use crate::vault::error::UnlockError;
use crate::vault::Vault;

impl crate::app::App {
    /// Open `vault` and keep `held`, the password of a placeholder.
    pub(super) fn opened_holding(&mut self, vault: Box<Vault>, message: &str, held: Option<Held>) {
        self.opened(vault, message);
        if let Screen::Unlocked(unlocked) = &mut self.screen {
            let show_modal = held.is_some() && unlocked.cache.is_empty();
            unlocked.held = held;
            if show_modal {
                unlocked.dialog = Some(Box::new(Dialog::RestoreSync(0)));
            }
        }
    }
}

impl Unlocked {
    /// Keep the password the placeholder was unlocked with.
    #[must_use]
    pub fn with_held(mut self, held: Option<Held>) -> Self {
        let show_modal = held.is_some() && self.cache.is_empty();
        self.held = held;
        if show_modal {
            self.dialog = Some(Box::new(Dialog::RestoreSync(0)));
        }
        self
    }

    /// Cancel waiting for another device's vault: promote this vault to the
    /// active personal vault and start serving it.
    pub fn cancel_adopt(&mut self, ctx: &mut Ctx) {
        self.promote_if_placeholder();
        ctx.redraw();
    }

    /// Promote a placeholder vault to the active personal vault once the
    /// owner writes or imports records into it, or cancels restore sync.
    pub fn promote_if_placeholder(&mut self) {
        self.held = None;
        if matches!(self.dialog.as_deref(), Some(Dialog::RestoreSync(_))) {
            self.dialog = None;
        }
        if let Some(vault) = self.vault.as_deref() {
            if is_placeholder(&vault.paths) {
                unmark_placeholder(&vault.paths);
            }
        }
        self.refresh_personal();
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.hold_saved();
        }
    }

    /// Ask the devices found so far for the account's vault, when this vault
    /// is still an untouched placeholder and a new device was heard or the
    /// check-in timer is due.
    pub fn try_adopt(&mut self, ctx: &mut Ctx) {
        if ctx.busy() || self.held.is_none() || !self.cache.is_empty() {
            return;
        }
        let (Some(vault), Some(p2p), Some(identity), Some(held)) = (
            self.vault.as_deref(),
            self.p2p.as_deref_mut(),
            self.identity.as_ref(),
            self.held.as_ref(),
        ) else {
            return;
        };
        if !is_placeholder(&vault.paths) {
            return;
        }
        let manual: Vec<String> = self
            .devices
            .iter()
            .filter(|entry| entry.manual)
            .map(|entry| entry.address.to_string())
            .collect();
        let known = p2p.discovered.len() + manual.len();
        let due = p2p.check_due();
        if known == 0 || (known == self.adopt_seen && !due) {
            return;
        }
        self.adopt_seen = known;
        let addresses: Vec<String> = p2p
            .discovered
            .iter()
            .filter(|address| {
                address.parse::<SocketAddr>().is_ok()
                    || address.parse::<p2p_net::RelayHint>().is_ok()
            })
            .cloned()
            .chain(manual.iter().rev().cloned())
            .collect();
        if let Some(target) = addresses.last() {
            p2p.log.push_line(format!(
                "adopt // dialing {target} ({} candidates)",
                addresses.len()
            ));
        }
        let request = AdoptRequest {
            placeholder: vault.paths.clone(),
            identity: std::sync::Arc::clone(identity),
            client_id: vault.meta.client_id,
            name: vault.meta.name.clone(),
            password: held.copy(),
            addresses,
            manual,
            loopback: self.beacon.is_some_and(|config| config.loopback),
        };
        ctx.start(Job::Adopt(Box::new(request)), Task::Adopt);
        ctx.redraw();
    }

    /// The attempt failed. Not finding a device is the ordinary case and
    /// stays quiet; a vault that does not open with this password ends the
    /// attempts.
    pub fn adopt_failed(&mut self, error: UnlockError, ctx: &mut Ctx) {
        let message = match error {
            UnlockError::Peer(reason) => {
                if let Some(p2p) = self.p2p.as_deref_mut() {
                    p2p.log.push_line(format!("adopt // peer failed: {reason}"));
                }
                ctx.redraw();
                return;
            }
            UnlockError::Denied => {
                self.held = None;
                if matches!(self.dialog.as_deref(), Some(Dialog::RestoreSync(_))) {
                    self.dialog = None;
                }
                "Your other device uses a different password: bring the vault in with its \
                 file or phrase."
            }
            _ => "The vault from your other device could not be brought in.",
        };
        ctx.toast(Tone::Warn, message);
    }
}
