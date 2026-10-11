//! What the home screen says about peer-to-peer sync: one summary of the
//! node, read by the status strip, the traffic light and the info dialog,
//! so no fact is kept twice.

use std::net::SocketAddr;
use std::time::Instant;

use local::Listen;
use ratatui::style::Style;

use crate::app::flows::unlocked::Unlocked;
use crate::app::node::log::LastResult;
use crate::app::node::{CheckIn, CheckOutcome};
use crate::ui::screens::sync::node_text;
use crate::ui::theme::Theme;

/// Where an address came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// Typed by the owner.
    Manual,
    /// Announced by a beacon on the network.
    Beacon,
    /// Learned from a peer or an earlier session.
    Learned,
}

impl Source {
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Beacon => "beacon",
            Self::Learned => "learned",
        }
    }
}

/// The addresses this device dials or may dial, each once, with its source.
#[must_use]
pub fn peer_rows(state: &Unlocked) -> Vec<(String, Source)> {
    let p2p = state.p2p.as_deref();
    let typed = state
        .devices
        .iter()
        .filter(|entry| entry.manual)
        .map(|entry| (entry.address.to_string(), Source::Manual));
    let relays = p2p
        .into_iter()
        .flat_map(|p2p| p2p.relays.iter())
        .map(|slot| (slot.clone(), Source::Manual));
    let heard = p2p
        .into_iter()
        .flat_map(|p2p| p2p.discovered.iter())
        .map(|found| {
            let source = if found.parse::<SocketAddr>().is_ok() {
                Source::Beacon
            } else {
                Source::Learned
            };
            (found.clone(), source)
        });
    let learned = state
        .devices
        .iter()
        .filter(|entry| !entry.manual)
        .map(|entry| (entry.address.to_string(), Source::Learned));
    let mut rows: Vec<(String, Source)> = Vec::new();
    for row in typed.chain(relays).chain(heard).chain(learned) {
        if !rows.iter().any(|(address, _)| *address == row.0) {
            rows.push(row);
        }
    }
    rows
}

/// How well sync is going.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Light {
    /// Running, a peer reachable, the last check-in succeeded.
    Green,
    /// Running, but no peer reachable or the last check-in failed.
    Yellow,
    /// Sync is off for this vault, or the node is not running.
    Red,
}

impl Light {
    /// The style of the dot.
    #[must_use]
    pub const fn style(self, theme: &Theme) -> Style {
        match self {
            Self::Green => theme.accent(),
            Self::Yellow => theme.warn(),
            Self::Red => theme.danger(),
        }
    }
}

/// The node as the interface describes it.
#[derive(Debug)]
pub struct Summary {
    /// The node line.
    pub node: String,
    /// Members and addresses known.
    pub known: usize,
    /// Peers connected now.
    pub reachable: usize,
    /// The latest check-in.
    pub last: Option<CheckIn>,
    /// The traffic light.
    pub light: Light,
    /// A node exists.
    pub running: bool,
}

/// Read the node of `state`.
#[must_use]
pub fn summary(state: &Unlocked, theme: &Theme) -> Summary {
    let (node, up) = node_text(state, theme);
    let p2p = state.p2p.as_deref();
    let members: usize = state
        .shared
        .iter()
        .map(|item| item.people.saturating_sub(1))
        .sum();
    let discovered = p2p.map_or(0, |p2p| p2p.discovered.len());
    let typed = state
        .manual_devices()
        .filter(|entry| p2p.is_none_or(|p2p| !p2p.discovered.contains(&entry.address.to_string())))
        .count();
    let connected = p2p.map_or(0, |p2p| p2p.service.status().peers);
    let answered = p2p.map_or(0, |p2p| {
        peer_rows(state)
            .iter()
            .filter(|(address, _)| matches!(p2p.log.result(address), Some(LastResult::Pulled(_))))
            .count()
    });
    let reachable = connected.max(answered);
    let last = p2p.and_then(|p2p| p2p.last_checkin);
    let light = match (p2p.is_some() && up, last) {
        (false, _) => Light::Red,
        (
            true,
            Some(CheckIn {
                outcome: CheckOutcome::Synced,
                ..
            }),
        ) if reachable > 0 => Light::Green,
        (true, _) => Light::Yellow,
    };
    Summary {
        node,
        known: members + discovered + typed,
        reachable,
        last,
        light,
        running: p2p.is_some(),
    }
}

/// `N known · M reachable`.
#[must_use]
pub fn peers_text(summary: &Summary) -> String {
    format!("{} known · {} reachable", summary.known, summary.reachable)
}

/// How long ago `at` was.
#[must_use]
pub fn ago(at: Instant) -> String {
    let secs = at.elapsed().as_secs();
    match secs {
        0..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        _ => format!("{} h ago", secs / 3600),
    }
}

/// The latest check-in, as Settings → Sync says it.
#[must_use]
pub fn checkin_text(checkin: CheckIn) -> String {
    let outcome = match checkin.outcome {
        CheckOutcome::Synced => "synced",
        CheckOutcome::RefusedChanges => "refused: a member's changes were refused",
        CheckOutcome::TurnedAway => "refused: turned this device away",
        CheckOutcome::Unreachable => "unreachable",
        CheckOutcome::Failed => "failed",
    };
    format!("{outcome} · {}", ago(checkin.at))
}

/// The status strip: one line, with no wrapping of its own.
#[must_use]
pub fn strip(state: &Unlocked, theme: &Theme) -> String {
    let summary = summary(state, theme);
    if !summary.running {
        return String::from("p2p · off · sync is off for this vault");
    }
    let last = summary.last.map_or_else(
        || String::from("waiting for first check-in"),
        |checkin| match checkin.outcome {
            CheckOutcome::Synced => format!("synced {}", ago(checkin.at)),
            CheckOutcome::RefusedChanges => format!("changes refused {}", ago(checkin.at)),
            CheckOutcome::TurnedAway => format!("turned away {}", ago(checkin.at)),
            CheckOutcome::Unreachable => format!("unreachable {}", ago(checkin.at)),
            CheckOutcome::Failed => format!("failed {}", ago(checkin.at)),
        },
    );
    format!("p2p · {} · {} · {last}", summary.node, peers_text(&summary))
}

/// The listening choice, in words.
#[must_use]
pub const fn mode_word(listen: Listen) -> &'static str {
    match listen {
        Listen::Lan => "local network",
        Listen::Beacon => "local network, announced",
        Listen::Local => "this device only",
        Listen::Fetch => "fetch only",
        Listen::Off => "off",
    }
}
