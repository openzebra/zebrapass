//! What one peer, or one network address, may make a node hold.
//!
//! Handshakes and established connections are counted per source address and
//! overall; an established connection that sits idle, sends too many requests
//! or keeps asking for things it is refused is closed. The numbers are for a
//! handful of devices per person: raise them for a hub, not for a laptop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The bounds a node enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Authenticated connections held at once.
    pub max_peers: usize,
    /// Handshakes one address may have in flight.
    pub per_address_handshakes: usize,
    /// Authenticated connections one address may hold.
    pub per_address_peers: usize,
    /// How long an authenticated connection may sit with no request and none
    /// being answered.
    pub idle: Duration,
    /// How long one request may take to answer, however slowly the peer
    /// reads.
    pub request: Duration,
    /// Requests refused or malformed before the connection is closed.
    pub max_failed: u32,
    /// Requests one connection may make in all.
    pub max_requests: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_peers: 64,
            per_address_handshakes: 4,
            per_address_peers: 8,
            idle: Duration::from_secs(120),
            request: Duration::from_secs(15 * 60),
            max_failed: 32,
            max_requests: 16_384,
        }
    }
}

#[derive(Default)]
struct Counts {
    handshakes: HashMap<IpAddr, usize>,
    peers: HashMap<IpAddr, usize>,
    total_peers: usize,
}

/// Who holds what right now.
pub struct Tickets {
    limits: Limits,
    counts: Mutex<Counts>,
}

fn release(map: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
    if let Some(held) = map.get_mut(&ip) {
        *held = held.saturating_sub(1);
        if *held == 0 {
            map.remove(&ip);
        }
    }
}

impl Tickets {
    /// Counters with these bounds.
    #[must_use]
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            counts: Mutex::new(Counts::default()),
        })
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// A place for one more handshake from `ip`, if it has one left.
    #[must_use]
    pub fn begin(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeSlot> {
        let mut counts = self.counts.lock().ok()?;
        let held = counts.handshakes.entry(ip).or_insert(0);
        if *held >= self.limits.per_address_handshakes {
            return None;
        }
        *held += 1;
        drop(counts);
        Some(HandshakeSlot {
            tickets: Arc::clone(self),
            ip,
        })
    }
}

/// One handshake in flight from an address; released when dropped.
pub struct HandshakeSlot {
    tickets: Arc<Tickets>,
    ip: IpAddr,
}

impl HandshakeSlot {
    /// The handshake succeeded: trade the slot for a place among the
    /// authenticated connections, if there is one.
    #[must_use]
    pub fn promote(self) -> Option<PeerSlot> {
        let tickets = Arc::clone(&self.tickets);
        let ip = self.ip;
        drop(self);
        let mut counts = tickets.counts.lock().ok()?;
        let held = counts.peers.get(&ip).copied().unwrap_or(0);
        if counts.total_peers >= tickets.limits.max_peers
            || held >= tickets.limits.per_address_peers
        {
            return None;
        }
        counts.peers.insert(ip, held + 1);
        counts.total_peers += 1;
        drop(counts);
        Some(PeerSlot { tickets, ip })
    }
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.tickets.counts.lock() {
            release(&mut counts.handshakes, self.ip);
        }
    }
}

/// One authenticated connection from an address; released when dropped.
pub struct PeerSlot {
    tickets: Arc<Tickets>,
    ip: IpAddr,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.tickets.counts.lock() {
            release(&mut counts.peers, self.ip);
            counts.total_peers = counts.total_peers.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use std::net::IpAddr;

    use super::{Limits, Tickets};

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn handshakes_are_counted_per_address_and_freed_on_drop() {
        let tickets = Tickets::new(Limits {
            per_address_handshakes: 2,
            ..Limits::default()
        });
        let a = tickets.begin(ip(1)).unwrap();
        let b = tickets.begin(ip(1)).unwrap();
        assert!(tickets.begin(ip(1)).is_none());
        assert!(
            tickets.begin(ip(2)).is_some(),
            "another address is unaffected"
        );
        drop(a);
        assert!(tickets.begin(ip(1)).is_some());
        drop(b);
    }

    #[test]
    fn peers_are_bounded_per_address_and_in_all() {
        let tickets = Tickets::new(Limits {
            per_address_handshakes: 8,
            per_address_peers: 2,
            max_peers: 3,
            ..Limits::default()
        });
        let promoted = |at: u8| {
            tickets
                .begin(ip(at))
                .and_then(super::HandshakeSlot::promote)
        };
        let one = promoted(1).unwrap();
        let _two = promoted(1).unwrap();
        assert!(promoted(1).is_none(), "per address");
        let _three = promoted(2).unwrap();
        assert!(promoted(3).is_none(), "in all");
        drop(one);
        assert!(promoted(3).is_some(), "a place frees when a peer leaves");
    }

    #[test]
    fn a_failed_promotion_does_not_leak_the_handshake_slot() {
        let tickets = Tickets::new(Limits {
            per_address_handshakes: 1,
            per_address_peers: 1,
            ..Limits::default()
        });
        let held = tickets.begin(ip(1)).and_then(super::HandshakeSlot::promote);
        assert!(held.is_some());
        assert!(tickets
            .begin(ip(1))
            .and_then(super::HandshakeSlot::promote)
            .is_none());
        assert!(
            tickets.begin(ip(1)).is_some(),
            "the handshake slot came back"
        );
    }
}
