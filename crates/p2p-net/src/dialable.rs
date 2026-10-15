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
    let [first, second, ..] = ip.octets();
    ip.is_private() || (first == 100 && (second & 0xC0) == 64)
}

const fn v6_shared(ip: Ipv6Addr) -> bool {
    let [first, ..] = ip.segments();
    (first & 0xFE00) == 0xFC00
}

fn same_network(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(va), IpAddr::V4(vb)) => {
            let [a0, a1, ..] = va.octets();
            let [b0, b1, ..] = vb.octets();
            (a0 == 10 && b0 == 10)
                || (a0 == 172 && (16..=31).contains(&a1) && b0 == 172 && (16..=31).contains(&b1))
                || (a0 == 100 && (a1 & 0xC0) == 64 && b0 == 100 && (b1 & 0xC0) == 64)
                || (a0 == b0 && a1 == b1)
        }
        (IpAddr::V6(va), IpAddr::V6(vb)) => va.segments().get(..3) == vb.segments().get(..3),
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

/// Transport fallback stage in ascending order of preference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Stage {
    /// Direct peer on a trusted local or private network.
    Lan = 0,
    /// Direct peer on the public Internet or an overlay network.
    WanDirect = 1,
    /// User-saved or peer-advertised TCP relay slot (`ZPRY`).
    ZpryRelay = 2,
    /// WebSocket (`RFC 6455` / Nostr envelope) or catalog hostname relay slot.
    CatalogRelay = 3,
}

/// A WebSocket or hostname-backed relay target (`ws://host:port/slot` or
/// `host:port/slot`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogTarget {
    /// Hostname or IP literal of the relay.
    pub host: Box<str>,
    /// Deterministic 16-byte rendezvous slot.
    pub slot: [u8; 16],
    /// Relay TCP port.
    pub port: u16,
    /// Whether WebSocket (`RFC 6455`) framing was requested (`ws://`).
    pub websocket: bool,
}

/// Where this device may dial: the policy and the addresses it trusts.
#[derive(Clone, Debug, Default)]
pub struct Dialing {
    /// How strictly addresses are filtered.
    pub policy: Policy,
    /// Addresses whose private network is trusted: this device's own.
    pub trusted: Vec<SocketAddr>,
}

/// Where a hint leads: straight to a device, to a TCP relay and a slot, or to
/// a WebSocket/catalog relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    /// An address to dial.
    Direct(SocketAddr),
    /// A relay to dial and the slot to ask it for.
    Relayed(RelayHint),
    /// A WebSocket or hostname-backed relay and slot.
    Catalog(Box<CatalogTarget>),
}

fn parse_slot_bytes(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (dst, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let hi = match *pair.first()? {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        let lo = match *pair.get(1)? {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        *dst = (hi << 4) | lo;
    }
    Some(out)
}

impl Dialing {
    /// Classify `hint` into its fallback [`Stage`].
    #[must_use]
    pub fn stage_of(&self, hint: &str) -> Stage {
        if !hint.contains('/') {
            if let Ok(addr) = hint.parse::<SocketAddr>() {
                let ip = addr.ip().to_canonical();
                let is_lan = ip.is_loopback()
                    || match ip {
                        IpAddr::V4(v4) => v4.is_private(),
                        IpAddr::V6(v6) => v6_shared(v6),
                    };
                if is_lan {
                    return Stage::Lan;
                }
            }
            return Stage::WanDirect;
        }
        if !hint.starts_with("ws://") && hint.parse::<RelayHint>().is_ok() {
            return Stage::ZpryRelay;
        }
        Stage::CatalogRelay
    }

    /// `hint` as a place this device may go: an address, `ip:port/slot` for a
    /// TCP relay, or `ws://host:port/slot` / `ws://ip:port/slot` for a
    /// WebSocket or catalog relay.
    #[must_use]
    pub fn target(&self, hint: &str) -> Option<Target> {
        if !hint.contains('/') {
            return self.resolve(hint).map(Target::Direct);
        }
        let Some(body) = hint.strip_prefix("ws://") else {
            let relayed: RelayHint = hint.parse().ok()?;
            return self
                .policy
                .allows(&relayed.relay, &self.trusted)
                .then_some(Target::Relayed(relayed));
        };
        local::parse_personal_target(hint, self.policy.loopback).ok()?;
        let (endpoint, slot_hex) = body.split_once('/')?;
        let slot = parse_slot_bytes(slot_hex)?;
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            if !self.policy.allows(&addr, &self.trusted) {
                return None;
            }
            return Some(Target::Catalog(Box::new(CatalogTarget {
                host: addr.ip().to_string().into_boxed_str(),
                slot,
                port: addr.port(),
                websocket: true,
            })));
        }
        let (host, port_str) = endpoint.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        Some(Target::Catalog(Box::new(CatalogTarget {
            host: host.into(),
            slot,
            port,
            websocket: true,
        })))
    }

    /// The next hint of `queue` to try that is not in `done`, ordered across
    /// the 4-stage fallback chain: [`Stage::Lan`], [`Stage::WanDirect`],
    /// [`Stage::ZpryRelay`], and [`Stage::CatalogRelay`].
    #[must_use]
    pub fn next_hint<'a>(&self, queue: &'a [String], done: &[String]) -> Option<&'a String> {
        for stage in [
            Stage::Lan,
            Stage::WanDirect,
            Stage::ZpryRelay,
            Stage::CatalogRelay,
        ] {
            if let Some(found) = queue
                .iter()
                .filter(|hint| !done.contains(hint))
                .find(|hint| self.stage_of(hint) == stage)
            {
                return Some(found);
            }
        }
        None
    }

    /// `hint` as an address this device may dial. Names are never resolved.
    #[must_use]
    pub fn resolve(&self, hint: &str) -> Option<SocketAddr> {
        hint.parse()
            .ok()
            .filter(|address| self.policy.allows(address, &self.trusted))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]
mod tests {
    use super::*;

    fn dialing() -> Dialing {
        Dialing {
            policy: Policy { loopback: false },
            trusted: Vec::new(),
        }
    }

    fn relayed(text: &str) -> String {
        format!("{text}/{}", "ab".repeat(16))
    }

    #[test]
    fn a_hint_is_a_direct_address_or_a_relay_and_a_slot_and_nothing_else() {
        let dialing = dialing();
        assert_eq!(
            dialing.target("93.184.216.34:7447"),
            Some(Target::Direct("93.184.216.34:7447".parse().unwrap()))
        );
        let Some(Target::Relayed(hint)) = dialing.target(&relayed("93.184.216.34:7447")) else {
            panic!("not a relay hint")
        };
        assert_eq!(hint.slot, [0xAB; 16]);
        for refused in [
            "169.254.169.254:80".to_owned(),
            relayed("169.254.169.254:80"),
            relayed("127.0.0.1:7447"),
            relayed("10.0.0.8:7447"),
            "93.184.216.34:7447/abcd".to_owned(),
            "example.com:7447".to_owned(),
        ] {
            assert_eq!(dialing.target(&refused), None, "{refused}");
        }
    }

    #[test]
    fn every_direct_address_comes_before_any_relay_whatever_the_order_it_was_learned_in() {
        let dialing = dialing();
        let relay = relayed("93.184.216.40:7447");
        let queue = vec![
            relay.clone(),
            "93.184.216.34:7447".to_owned(),
            relayed("93.184.216.41:7447"),
            "169.254.169.254:80".to_owned(),
            "93.184.216.35:7447".to_owned(),
        ];
        let mut done = Vec::new();
        let mut order = Vec::new();
        while let Some(next) = dialing.next_hint(&queue, &done) {
            order.push(next.clone());
            done.push(next.clone());
        }
        assert_eq!(
            order,
            [
                "93.184.216.34:7447",
                "169.254.169.254:80",
                "93.184.216.35:7447",
                relay.as_str(),
                queue[2].as_str(),
            ],
            "direct ones in their order (a forbidden one fails at once), then the relays"
        );
        assert_eq!(dialing.next_hint(&[], &[]), None);
    }

    #[test]
    fn a_relayed_member_that_is_also_a_direct_peer_is_dialed_directly() {
        let dialing = dialing();
        let queue = vec![
            relayed("93.184.216.40:7447"),
            "93.184.216.34:7447".to_owned(),
        ];
        let first = dialing.next_hint(&queue, &[]).unwrap();
        assert_eq!(
            dialing.target(first),
            Some(Target::Direct("93.184.216.34:7447".parse().unwrap()))
        );
        let after = dialing
            .next_hint(&queue, std::slice::from_ref(first))
            .unwrap();
        assert!(matches!(dialing.target(after), Some(Target::Relayed(_))));
    }

    #[test]
    fn four_stage_ordering_steps_lan_wan_zpry_then_catalog() {
        let dialing = Dialing {
            policy: Policy { loopback: true },
            trusted: Vec::new(),
        };
        let ws_cat = format!("ws://relay.damus.io:443/{}", "cd".repeat(16));
        let ws_ip = format!("ws://93.184.216.40:7447/{}", "ef".repeat(16));
        let zpry = relayed("93.184.216.40:7447");
        let wan = "93.184.216.34:7447".to_owned();
        let lan = "192.168.1.42:7447".to_owned();

        let queue = vec![
            ws_cat.clone(),
            zpry.clone(),
            wan.clone(),
            ws_ip.clone(),
            lan.clone(),
        ];
        let mut done = Vec::new();
        let mut order = Vec::new();
        while let Some(next) = dialing.next_hint(&queue, &done) {
            order.push(next.clone());
            done.push(next.clone());
        }
        assert_eq!(order, vec![lan, wan, zpry, ws_cat, ws_ip]);
        assert_eq!(dialing.stage_of("192.168.1.42:7447"), Stage::Lan);
        assert_eq!(dialing.stage_of("93.184.216.34:7447"), Stage::WanDirect);
        assert_eq!(dialing.stage_of(&order[2]), Stage::ZpryRelay);
        assert_eq!(dialing.stage_of(&order[3]), Stage::CatalogRelay);
    }
}
