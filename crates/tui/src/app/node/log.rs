//! What the node told the interface this session.
//!
//! A bounded, in-memory record of event kinds, addresses and causes. It holds
//! no record titles, plaintext or secrets, is never written anywhere, and
//! goes with the node.

use std::collections::VecDeque;
use std::time::Instant;

use p2p_net::{Event, FetchError};

/// Lines kept; the oldest give way.
pub const LOG_CAP: usize = 200;

/// Addresses whose latest result is kept.
const RESULTS_CAP: usize = 8;

/// One line of the log.
#[derive(Debug)]
pub struct LogLine {
    /// Unix milliseconds when the event arrived.
    pub at_ms: u64,
    /// What happened.
    pub text: Box<str>,
}

/// The latest word from the dialed addresses.
#[derive(Debug, Default)]
pub struct EventLog {
    lines: VecDeque<LogLine>,
    pulled: Vec<(String, Instant)>,
    failed: Option<(FetchError, Instant)>,
}

/// How the latest check-in with an address ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LastResult {
    /// The address answered and the check-in completed.
    Pulled(Instant),
    /// Nothing answered, for the reason given.
    Failed(FetchError, Instant),
}

impl EventLog {
    /// Lines, oldest first.
    #[must_use]
    pub fn lines(&self) -> impl ExactSizeIterator<Item = &LogLine> {
        self.lines.iter()
    }

    /// The latest result for `address`: its own success, unless a failure
    /// came after it; a failure covers every address of that check-in.
    #[must_use]
    pub fn result(&self, address: &str) -> Option<LastResult> {
        let pulled = self
            .pulled
            .iter()
            .find(|(known, _)| known == address)
            .map(|(_, at)| *at);
        match (pulled, self.failed) {
            (Some(at), Some((_, failed))) if failed > at => self
                .failed
                .map(|(reason, at)| LastResult::Failed(reason, at)),
            (Some(at), _) => Some(LastResult::Pulled(at)),
            (None, Some((reason, at))) => Some(LastResult::Failed(reason, at)),
            (None, None) => None,
        }
    }

    /// Record `event`.
    pub fn note(&mut self, event: &Event) {
        let text = match event {
            Event::Listening(address) => format!("listening on {address}"),
            Event::PeerConnected { .. } => String::from("peer connected"),
            Event::PeerGone { .. } => String::from("peer gone"),
            Event::Fetched { log, snapshot, .. } => format!(
                "fetched a shared vault ({} B log, {} B file)",
                log.len(),
                snapshot.len()
            ),
            Event::Synced {
                pulled,
                pushed,
                refused,
                ..
            } => format!("synced: {pulled} pulled, {pushed} pushed, {refused} refused"),
            Event::PersonalPulled { address, frames } => {
                self.pulled.retain(|(known, _)| known != address);
                self.pulled.push((address.clone(), Instant::now()));
                if self.pulled.len() > RESULTS_CAP {
                    self.pulled.remove(0);
                }
                format!("checked in with {address}: {} frames", frames.len())
            }
            Event::Observed(address) => format!("seen from outside as {address}"),
            Event::Discovered {
                address, relays, ..
            } => format!("discovered {address} ({} relay slots)", relays.len()),
            Event::Relayed(hint) => format!("holds a relay slot at {hint}"),
            Event::FetchFailed { reason, .. } => {
                self.failed = Some((*reason, Instant::now()));
                format!("fetch failed: {reason}")
            }
        };
        self.push_line(text);
    }

    /// Append a custom status line to the log.
    pub fn push_line(&mut self, text: impl Into<Box<str>>) {
        if self.lines.len() >= LOG_CAP {
            self.lines.pop_front();
        }
        self.lines.push_back(LogLine {
            at_ms: crate::vault::create::unix_ms(),
            text: text.into(),
        });
    }
}
