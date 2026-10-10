//! Which addresses learned from other members this device will dial.
//!
//! A member's signature proves who published an address, not that the address
//! is a device of the vault. A member could list one that points inside
//! someone else's network, so a learned address is dialed only if it is
//! globally routable, or private and in the same network as an address this
//! device already trusts (its own, or the one its invitation came from).
//! Loopback is refused unless asked for, and addresses that are never a peer
//! (unspecified, multicast, link-local such as cloud metadata, reserved) are
//! refused always.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use local::never_dialable;
use syncwire::RelayHint;

/// How strictly learned addresses are filtered.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    /// Accept loopback addresses: for tests and single-machine setups.
    pub loopback: bool,
}

const fn v4_shared(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private() || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
}

const fn v6_shared(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00
}

fn same_network(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().get(..2) == b.octets().get(..2),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments().get(..3) == b.segments().get(..3),
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

impl Policy {
    /// Whether `address` may be dialed, given the addresses already trusted.
    #[must_use]
    pub fn allows(self, address: &SocketAddr, trusted: &[SocketAddr]) -> bool {
        let ip = address.ip().to_canonical();
        if address.port() == 0 {
            return false;
        }
        if ip.is_loopback() {
            return self.loopback;
        }
        if never_dialable(ip) {
            return false;
        }
        let shared = match ip {
            IpAddr::V4(v4) => v4_shared(v4),
            IpAddr::V6(v6) => v6_shared(v6),
        };
        !shared
            || trusted
                .iter()
                .any(|known| same_network(ip, known.ip().to_canonical()))
    }
}

/// Where this device may dial: the policy and the addresses it trusts.
#[derive(Clone, Debug, Default)]
pub struct Dialing {
    /// How strictly addresses are filtered.
    pub policy: Policy,
    /// Addresses whose private network is trusted: this device's own.
    pub trusted: Vec<SocketAddr>,
}

/// Where a hint leads: straight to a device, or to a relay and a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// An address to dial.
    Direct(SocketAddr),
    /// A relay to dial and the slot to ask it for.
    Relayed(RelayHint),
}

impl Dialing {
    /// `hint` as a place this device may go: an address, or `ip:port/slot`
    /// for a relay (which must pass the same rules as any address).
    #[must_use]
    pub fn target(&self, hint: &str) -> Option<Target> {
        if hint.contains('/') {
            let relayed: RelayHint = hint.parse().ok()?;
            self.policy
                .allows(&relayed.relay, &self.trusted)
                .then_some(Target::Relayed(relayed))
        } else {
            self.resolve(hint).map(Target::Direct)
        }
    }

    /// `hint` as an address this device may dial. Names are never resolved.
    #[must_use]
    pub fn resolve(&self, hint: &str) -> Option<SocketAddr> {
        hint.parse()
            .ok()
            .filter(|address| self.policy.allows(address, &self.trusted))
    }
}
