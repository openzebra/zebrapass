//! Where a node dials besides the addresses it was given: the relay slots
//! the person saved.

use std::sync::Arc;

use crate::app::node::P2p;
use crate::vault::shared::SharedItem;

/// Trade revisions with the members of an open shared vault, once.
pub fn check_in(p2p: &P2p, item: &SharedItem) {
    if !item.ready() {
        return;
    }
    let mut hints = item.reference.hints.clone();
    for relay in &p2p.relays {
        if !hints.contains(relay) {
            hints.push(relay.clone());
        }
    }
    p2p.service
        .check_in(Arc::clone(&p2p.provider), item.reference.vault_id, hints);
}

/// The relay slots saved in `prefs`, as text.
pub fn saved_relays(prefs: Option<&local::Prefs>) -> Vec<String> {
    prefs.map_or_else(Vec::new, |prefs| {
        prefs.p2p_relays.iter().map(ToString::to_string).collect()
    })
}
