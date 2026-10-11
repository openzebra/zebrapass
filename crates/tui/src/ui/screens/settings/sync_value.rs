//! The value column of the Sync section: live facts of the node, each
//! `—` when it is not known.

use local::Listen;

use crate::app::ctx::Ctx;
use crate::app::flows::settings::rows::Row;
use crate::app::flows::unlocked::Unlocked;
use crate::app::node::{CheckIn, CheckOutcome};
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
            |p2p| {
                let members: usize = state
                    .shared
                    .iter()
                    .map(|item| item.people.saturating_sub(1))
                    .sum();
                format!(
                    "{} known · {} reachable",
                    members + p2p.discovered.len(),
                    p2p.service.status().peers
                )
            },
        ),
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

fn checkin_text(checkin: CheckIn) -> String {
    let outcome = match checkin.outcome {
        CheckOutcome::Synced => "synced",
        CheckOutcome::RefusedChanges => "refused: a member's changes were refused",
        CheckOutcome::TurnedAway => "refused: turned this device away",
        CheckOutcome::Unreachable => "unreachable",
        CheckOutcome::Failed => "failed",
    };
    let secs = checkin.at.elapsed().as_secs();
    let ago = match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h", secs / 3600),
    };
    format!("{outcome} · {ago} ago")
}
