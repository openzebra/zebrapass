//! Addresses that are never a peer, wherever they are published or read.

use std::net::IpAddr;

/// Whether `ip` can never be a device another member could dial.
///
/// That is unspecified, multicast, broadcast, link-local (cloud metadata
/// lives there), documentation and reserved ranges. Loopback and private
/// ranges are the caller's call. Pass an address already in canonical form
/// (`IpAddr::to_canonical`).
#[must_use]
pub const fn never_dialable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_documentation()
                || first == 0
                || first >= 240
                || (first == 198 && (second & 0xFE) == 18)
        }
        IpAddr::V6(v6) => {
            let [first, second, ..] = v6.segments();
            v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xFFC0) == 0xFE80
                || (first == 0x2001 && second == 0x0DB8)
        }
    }
}

/// Validate the address this device advertises: a socket address (`ip:port`,
/// `[ipv6]:port`) with a port, that is an address another device could be
/// asked to dial. Returns it in canonical form.
///
/// # Errors
///
/// A short reason the interface can show as is.
pub fn parse_advertise(input: &str) -> Result<Box<str>, &'static str> {
    parse_peer_address(input, false)
}

/// As [`parse_advertise`], for an address this device is asked to dial.
///
/// `allow_loopback` is for an address its user typed in on purpose, such as
/// a device reached through an SSH tunnel or on this machine; an address
/// another device published is never loopback.
///
/// # Errors
///
/// A short reason the interface can show as is.
pub fn parse_peer_address(input: &str, allow_loopback: bool) -> Result<Box<str>, &'static str> {
    let address: std::net::SocketAddr = input
        .trim()
        .parse()
        .map_err(|_| "Write it as ip:port, for example 93.184.216.34:7447.")?;
    let ip = address.ip().to_canonical();
    let loopback_refused = ip.is_loopback() && !allow_loopback;
    let refused = !ip.is_loopback() && crate::never_dialable(ip);
    if address.port() == 0 || loopback_refused || refused {
        return Err("Other devices cannot reach that address.");
    }
    Ok(address.to_string().into_boxed_str())
}

/// What to do with the address a peer reports having seen this device at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Offer {
    /// A public address worth offering as the advertised one, with the
    /// node's own port.
    Public(Box<str>),
    /// The peer is on this machine: shown, never offered.
    Local(Box<str>),
    /// An address that could never be dialed, or no port to pair it with.
    Unusable,
}

/// Judge the address a peer saw this device at.
///
/// Only the address counts: the port a peer sees is that of an outgoing
/// connection, so it is replaced by `listen_port`, the one this node accepts
/// connections on. The result then passes the same rules as the advertised
/// address.
#[must_use]
pub fn offer_observed(seen: std::net::SocketAddr, listen_port: u16) -> Offer {
    let ip = seen.ip().to_canonical();
    let candidate = std::net::SocketAddr::new(ip, listen_port).to_string();
    if ip.is_loopback() && listen_port != 0 {
        return Offer::Local(candidate.into_boxed_str());
    }
    parse_advertise(&candidate).map_or(Offer::Unusable, Offer::Public)
}
