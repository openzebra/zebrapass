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
    let address: std::net::SocketAddr = input
        .trim()
        .parse()
        .map_err(|_| "Write it as ip:port, for example 93.184.216.34:7447.")?;
    let ip = address.ip().to_canonical();
    if address.port() == 0 || ip.is_loopback() || crate::never_dialable(ip) {
        return Err("Other devices cannot reach that address.");
    }
    Ok(address.to_string().into_boxed_str())
}
