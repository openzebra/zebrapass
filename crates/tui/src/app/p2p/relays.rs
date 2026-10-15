//! Where a node dials besides the addresses it was given: discovered LAN
//! peers, saved relay slots, and deterministic shared-vault relay slots.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::node::P2p;
use crate::vault::shared::SharedItem;

/// Candidate hints for reaching members of `item`: the invitation's addresses,
/// peers discovered via LAN beacons, saved relay hints, deterministic
/// shared-vault slots on saved relays, and fallback WebSocket/catalog relays.
#[must_use]
pub fn hints_for(p2p: &P2p, item: &SharedItem) -> Vec<String> {
    let loopback = matches!(p2p.listen, local::Listen::Local | local::Listen::Fetch);
    let catalog_count = if !loopback && p2p.relays.is_empty() {
        2
    } else {
        0
    };
    let mut hints = item.reference.hints.clone();
    for found in &p2p.discovered {
        if !hints.contains(found) {
            hints.push(found.clone());
        }
    }
    for seed in item.reference.seeds() {
        let expanded = p2p_net::expand_chain_hints(
            &item.reference.hints,
            &p2p.discovered,
            &p2p.relays,
            seed.expose(),
            &item.reference.vault_id,
            catalog_count,
        );
        for candidate in expanded {
            if !hints.contains(&candidate) {
                hints.push(candidate);
            }
        }
    }
    hints
}

/// Candidate hints for reaching another device of this account across the
/// 4-stage transport fallback chain.
#[must_use]
pub fn personal_candidates(p2p: &P2p, explicit: &[String], catalog_count: usize) -> Vec<String> {
    if let Some(gate) = p2p.identity.account_gate() {
        if let Ok(route) = kdf::account_route_id(gate) {
            return p2p_net::expand_chain_hints(
                explicit,
                &p2p.discovered,
                &p2p.relays,
                gate.expose(),
                &route,
                catalog_count,
            );
        }
    }
    let mut out = Vec::new();
    for addr in p2p.discovered.iter().chain(explicit).chain(&p2p.relays) {
        if !out.contains(addr) {
            out.push(addr.clone());
        }
    }
    out
}

/// Trade revisions with the members of an open shared vault, once.
pub fn check_in(p2p: &P2p, item: &SharedItem) {
    if !item.ready() {
        return;
    }
    let hints = hints_for(p2p, item);
    p2p.service
        .check_in(Arc::clone(&p2p.provider), item.reference.vault_id, hints);
}

/// The relay slots saved in `prefs`, as text.
pub fn saved_relays(prefs: Option<&local::Prefs>) -> Vec<String> {
    prefs.map_or_else(Vec::new, |prefs| {
        prefs.p2p_relays.iter().map(ToString::to_string).collect()
    })
}

/// Handle a discovered peer beacon: remember its address and relay hints,
/// persist learned personal-vault addresses, and trigger immediate sync for
/// any matching personal or shared vault.
pub fn on_discovered(
    unlocked: &mut Unlocked,
    address: SocketAddr,
    vaults: &[[u8; 16]],
    relays: &[p2p_net::RelayHint],
    ctx: &mut Ctx,
) {
    if let Some(p2p) = unlocked.p2p.as_deref_mut() {
        p2p.discover(address);
        for hint in relays {
            p2p.discover_relay(hint);
        }
    }
    if let (Some(p2p), Some(vault)) = (unlocked.p2p.as_deref(), unlocked.vault.as_deref()) {
        let is_personal = p2p
            .identity
            .account_gate()
            .and_then(|gate| kdf::account_route_id(gate).ok())
            .is_some_and(|route| vaults.contains(&route));
        if is_personal && !crate::vault::adopt::is_placeholder(&vault.paths) {
            if let Ok(key) = vault.session.personal_peers_key() {
                let store = vault.paths.peers_store();
                let _ = local::remember_personal_peer(&store, &key, &address.to_string());
                for hint in relays {
                    let _ = local::remember_personal_peer(&store, &key, &hint.to_string());
                }
            }
            crate::app::personal::pull_personal(p2p, vault);
        }
        for item in &unlocked.shared {
            if vaults.contains(&item.reference.vault_id) {
                super::fetch(p2p, item);
            }
        }
    }
    unlocked.try_adopt(ctx);
    ctx.redraw();
}
