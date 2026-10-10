//! The personal vault on the peer-to-peer node: when a node is wanted for
//! it, serving it to the account's other devices, pulling what this device
//! lacks from them, and applying what they send.

use local::{load_personal_peers, Listen};
use p2p_net::{personal_view, Dialing, Policy};

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::node::P2p;
use crate::ui::widgets::toast::Tone;
use crate::vault::Vault;

/// Whether a node is wanted for this identity: there are shared vaults to
/// serve and fetch, or the personal vault can be served to the account's
/// other devices and the user has not turned listening off.
#[must_use]
pub const fn wants_node(has_gate: bool, shared: usize, listen: Listen) -> bool {
    shared > 0 || (has_gate && !matches!(listen, Listen::Off))
}

/// Ask another device of this account, at an address remembered next to the
/// vault, for the record frames this device lacks, and send it the ones it
/// lacks. Does nothing when no address is remembered.
pub fn pull_personal(p2p: &P2p, vault: &Vault) {
    let loopback = matches!(p2p.listen, Listen::Local);
    let remembered = vault
        .session
        .personal_peers_key()
        .ok()
        .and_then(|key| load_personal_peers(&vault.paths.peers_store(), &key, loopback).ok())
        .unwrap_or_default();
    let mut addresses: Vec<String> = remembered.iter().map(ToString::to_string).collect();
    for found in p2p.discovered.iter().chain(&p2p.relays) {
        if !addresses.contains(found) {
            addresses.push(found.clone());
        }
    }
    if addresses.is_empty() {
        return;
    }
    let dialing = Dialing {
        policy: Policy { loopback },
        trusted: addresses
            .iter()
            .filter_map(|text| {
                text.parse().ok().or_else(|| {
                    text.parse::<p2p_net::RelayHint>()
                        .ok()
                        .map(|hint| hint.relay)
                })
            })
            .collect(),
    };
    let (Some(view), Ok(mine)) = (
        personal_view(&p2p.identity, dialing),
        session::frontier(&vault.session),
    ) else {
        return;
    };
    p2p.service
        .pull_personal(view, addresses, mine, p2p.provider.personal_serve());
}

impl Unlocked {
    /// Hand the node the vault key as it is now, after a job may have
    /// rotated it.
    pub fn refresh_personal(&self) {
        if let (Some(p2p), Some(vault)) = (self.p2p.as_deref(), self.vault.as_deref()) {
            p2p.serve_personal(vault);
        }
    }

    /// Keep the frames another device of this account sent, each checked as
    /// a newer revision of a record sealed under this vault's key, and save
    /// the vault if any was.
    pub(crate) fn apply_pulled(&mut self, frames: &[Vec<u8>], ctx: &mut Ctx) {
        let Some(vault) = self.vault.as_deref_mut() else {
            return;
        };
        let applied = frames
            .iter()
            .filter(|frame| {
                session::accept_peer_frame(&mut vault.session, &mut vault.file, frame).is_ok()
            })
            .count();
        if applied == 0 {
            return;
        }
        if vault.persist().is_err() {
            ctx.toast(Tone::Danger, "Could not save what your other device sent.");
            return;
        }
        self.refresh();
        ctx.toast(
            Tone::Info,
            format!("{applied} updated from your other device."),
        );
        ctx.redraw();
    }
}
