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

fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return false;
    }
    let mut has_alpha = false;
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
        if label.bytes().any(|b| b.is_ascii_lowercase()) {
            has_alpha = true;
        }
    }
    has_alpha
}

fn valid_slot_hex(slot: &str) -> bool {
    slot.len() == 32
        && slot
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_relay_target(text: &str, allow_loopback: bool) -> Result<Box<str>, &'static str> {
    const SHAPE: &str = "Write it as ip:port/slot, the way another device shows it.";
    const UNREACHABLE: &str = "Other devices cannot reach that relay.";

    let (is_ws, body) = text
        .strip_prefix("ws://")
        .map_or((false, text), |rest| (true, rest));
    let Some((endpoint, slot)) = body.split_once('/') else {
        return Err(SHAPE);
    };
    if !valid_slot_hex(slot) {
        return Err(SHAPE);
    }
    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
        if addr.to_string() != endpoint {
            return Err(SHAPE);
        }
        parse_peer_address(endpoint, allow_loopback).map_err(|_| UNREACHABLE)?;
        return Ok(text.into());
    }
    if !is_ws {
        return Err(SHAPE);
    }
    let Some((host, port_str)) = endpoint.rsplit_once(':') else {
        return Err(SHAPE);
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return Err(SHAPE);
    };
    if port == 0 || port_str != port.to_string() || !valid_hostname(host) {
        return Err(SHAPE);
    }
    if host == "localhost" || host.ends_with(".localhost") {
        if !allow_loopback {
            return Err(UNREACHABLE);
        }
        return Ok(text.into());
    }
    Ok(text.into())
}

/// Validate a relay slot a person pasted: `ip:port/slot`, `host:port/slot`,
/// or `ws://host:port/slot`.
///
/// It must be in canonical lowercase form, with a relay address that could
/// ever be a peer. Loopback is allowed because the person chose it.
///
/// # Errors
///
/// A short reason the interface can show as is.
pub fn parse_relay_hint(input: &str) -> Result<Box<str>, &'static str> {
    validate_relay_target(input.trim(), true)
}

/// Validate a personal peer target (`ip:port`, `ip:port/slot`, or
/// `ws://host:port/slot`), respecting `allow_loopback` for both direct
/// addresses and relay addresses.
///
/// # Errors
///
/// A short reason the interface can show as is.
pub fn parse_personal_target(input: &str, allow_loopback: bool) -> Result<Box<str>, &'static str> {
    let text = input.trim();
    if text.contains('/') {
        validate_relay_target(text, allow_loopback)
    } else {
        parse_peer_address(text, allow_loopback)
    }
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
