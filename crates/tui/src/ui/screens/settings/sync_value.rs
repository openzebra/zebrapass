//! The value column of the Sync section: live facts of the node, each
//! `—` when it is not known.

use local::Listen;

use crate::app::ctx::Ctx;
use crate::app::flows::settings::rows::Row;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::screens::p2p_status::{checkin_text, peers_text, summary};
use crate::ui::screens::sync::node_text;

const UNKNOWN: &str = "—";

/// Text of a Sync row's value.
pub fn sync_value(row: Row, state: &Unlocked, ctx: &Ctx) -> String {
    let p2p = state.p2p.as_deref();
    match row {
        Row::SyncStatus if p2p.is_none() && state.listen_mode() == Listen::Off => {
            String::from("off")
        }
        Row::SyncStatus => node_text(state, &ctx.theme).0,
        Row::LastCheckIn => p2p.map_or_else(
            || UNKNOWN.to_owned(),
            |p2p| {
                p2p.last_checkin
                    .map_or_else(|| String::from("waiting for first check-in"), checkin_text)
            },
        ),
        Row::SyncPeers => p2p.map_or_else(
            || UNKNOWN.to_owned(),
            |_| peers_text(&summary(state, &ctx.theme)),
        ),
        Row::SyncDevices => match state.manual_devices().count() {
            0 => String::from("none"),
            added => format!("{added} added"),
        },
        Row::SyncRelays => {
            let saved = state
                .info
                .prefs
                .as_ref()
                .map_or(0, |prefs| prefs.p2p_relays.len());
            let held = if p2p.is_some_and(|p2p| p2p.relayed.is_some()) {
                "announced"
            } else {
                "not holding"
            };
            format!("{saved} saved · {held}")
        }
        Row::SyncAdvertised => state.advertised().unwrap_or(UNKNOWN).to_owned(),
        Row::SyncBeacon => String::from(if state.listen_mode() == Listen::Beacon {
            "on"
        } else {
            "off"
        }),
        _ => String::from("Enter"),
    }
}
