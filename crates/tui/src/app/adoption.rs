//! A placeholder vault asks sync servers and LAN peers for the account's
//! vault: when another copy is found, it is fetched, unlocked with the held
//! credentials, and enrolled with this device's own password or Device PIN.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::Dialog;
use crate::app::flows::unlocked::Unlocked;
use crate::app::screen::Screen;
use crate::app::worker::Job;
use crate::ui::widgets::toast::Tone;
use crate::vault::Vault;
use crate::vault::adopt::{AdoptRequest, Held, is_placeholder, unmark_placeholder};
use crate::vault::error::UnlockError;

impl crate::app::App {
    /// Open `vault` and keep `held`, the credentials of a placeholder.
    pub(super) fn opened_holding(
        &mut self,
        mut vault: Box<Vault>,
        message: &str,
        held: Option<Arc<Held>>,
    ) {
        crate::app::jobs::seed_cli_sync_prefs(&mut vault, &self.ctx);
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
    /// Keep the credentials the placeholder was unlocked with.
    #[must_use]
    pub fn with_held(mut self, held: Option<Arc<Held>>) -> Self {
        let show_modal = held.is_some() && self.cache.is_empty();
        self.held = held;
        if show_modal {
            self.dialog = Some(Box::new(Dialog::RestoreSync(0)));
        }
        self
    }

    /// Dismiss the restore-sync modal while keeping background adoption
    /// active if the user adds a manual device address or sync server.
    pub fn cancel_adopt(&mut self, ctx: &mut Ctx) {
        if matches!(self.dialog.as_deref(), Some(Dialog::RestoreSync(_))) {
            self.dialog = None;
        }
        self.refresh_personal();
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.hold_saved();
        }
        ctx.redraw();
    }

    /// Promote a placeholder vault to the active personal vault once the
    /// owner writes or imports records into it.
    pub fn promote_if_placeholder(&mut self) {
        self.held = None;
        if matches!(self.dialog.as_deref(), Some(Dialog::RestoreSync(_))) {
            self.dialog = None;
        }
        if let Some(vault) = self.vault.as_deref()
            && is_placeholder(&vault.paths)
        {
            unmark_placeholder(&vault.paths);
        }
        self.refresh_personal();
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.hold_saved();
        }
    }

    /// Ask configured sync servers and any discovered peers for the account's
    /// vault when this vault is still an untouched placeholder.
    pub fn try_adopt(&mut self, ctx: &mut Ctx) {
        if ctx.busy() || self.held.is_none() || !self.cache.is_empty() {
            return;
        }
        let (Some(vault), Some(identity), Some(held)) = (
            self.vault.as_deref(),
            self.identity.as_ref(),
            self.held.as_ref(),
        ) else {
            return;
        };
        if !is_placeholder(&vault.paths) {
            return;
        }
        let sync_servers: Vec<String> = vault
            .meta
            .prefs
            .as_ref()
            .filter(|p| !p.sync_servers.is_empty())
            .map_or_else(
                || ctx.sync_servers.iter().map(ToString::to_string).collect(),
                |p| p.sync_servers.iter().map(ToString::to_string).collect(),
            );
        let sync_proxy = vault
            .meta
            .prefs
            .as_ref()
            .and_then(|p| p.sync_proxy.as_deref())
            .or(ctx.sync_proxy.as_deref())
            .map(ToString::to_string);
        let manual: Vec<String> = self
            .devices
            .iter()
            .filter(|entry| entry.manual)
            .map(|entry| entry.address.to_string())
            .collect();
        let (known, due) = self.p2p.as_deref_mut().map_or((0, false), |p2p| {
            (
                p2p.discovered.len() + manual.len() + p2p.relays.len(),
                p2p.check_due(),
            )
        });
        let server_due = !sync_servers.is_empty()
            && self
                .adopt_last_try
                .is_none_or(|t| ctx.now.saturating_duration_since(t) >= Duration::from_secs(2));
        let peer_due = known > 0 && (known != self.adopt_seen || due);
        if !server_due && !peer_due {
            return;
        }
        self.adopt_seen = known;
        self.adopt_last_try = Some(ctx.now);
        let addresses = self.p2p.as_deref().map_or_else(Vec::new, |p2p| {
            let primary: Vec<String> = p2p
                .discovered
                .iter()
                .filter(|address| {
                    address.parse::<SocketAddr>().is_ok()
                        || local::parse_relay_hint(address).is_ok()
                })
                .cloned()
                .chain(manual.iter().rev().cloned())
                .collect();
            let chain = crate::app::p2p::personal_candidates(p2p, &manual);
            let mut list: Vec<String> = chain
                .into_iter()
                .filter(|cand| !primary.contains(cand))
                .rev()
                .collect();
            list.extend(primary);
            list
        });
        if let (Some(p2p), Some(target)) = (self.p2p.as_deref_mut(), addresses.last()) {
            p2p.log.push_line(format!(
                "adopt // dialing {target} ({} candidates)",
                addresses.len()
            ));
        }
        let request = AdoptRequest {
            placeholder: vault.paths.clone(),
            identity: Arc::clone(identity),
            client_id: vault.meta.client_id,
            name: vault.meta.name.clone(),
            held: Arc::clone(held),
            addresses,
            manual,
            loopback: self.beacon.is_some_and(|config| config.loopback),
            sync_servers,
            sync_proxy,
            extra_ca_pem: ctx.extra_ca_pem.clone(),
        };
        ctx.start(Job::Adopt(Box::new(request)), Task::Adopt);
        ctx.redraw();
    }

    /// The attempt failed. Not finding a device is the ordinary case and
    /// stays quiet; a vault that does not open with the held credentials ends
    /// the attempts.
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
