//! Local network interface discovery and directed broadcast targets.
//!
//! Probes the system routing table across public, RFC 1918 (`10/8`,
//! `172.16/12`, `192.168/16`), Carrier-Grade NAT / Tailscale / `WireGuard`
//! (`100.64/10`), and multicast destinations without transmitting any packets.
//! Never appends `127.0.0.1` so `PeerRecord` hints stay valid under non-loopback
//! policies.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use local::never_dialable;

/// Probe destinations covering default routes, private LAN subnets, Tailscale /
/// `WireGuard` CGNAT space, and the local multicast group. Connecting a UDP
/// socket only queries the kernel routing table and sends no traffic.
const PROBE_TARGETS: [&str; 9] = [
    "192.0.2.1:9",
    "8.8.8.8:80",
    "1.1.1.1:80",
    "239.255.74.74:7448",
    "192.168.1.1:9",
    "192.168.0.1:9",
    "10.0.0.1:9",
    "172.16.0.1:9",
    "100.64.0.1:9",
];

/// Non-loopback, dialable local IP addresses discovered across active network
/// interfaces, best route first.
#[must_use]
pub fn local_ips() -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for probe in PROBE_TARGETS {
        let found = UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| socket.connect(probe).and_then(|()| socket.local_addr()))
            .ok()
            .map(|local| local.ip().to_canonical())
            .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !never_dialable(*ip));
        if let Some(ip) = found {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// Addresses other devices might reach this node at on `port`, best first.
///
/// Loopback is omitted whenever at least one non-loopback interface exists, so
/// `PeerRecord`s signed from `reachable_hints` are never poisoned with
/// `127.0.0.1` on real networks.
#[must_use]
pub fn reachable_hints(port: u16) -> Vec<String> {
    let mut hints: Vec<String> = local_ips()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .collect();
    if hints.is_empty() {
        hints.push(format!("127.0.0.1:{port}"));
    }
    hints
}

/// Directed `/24` subnet broadcast and limited broadcast UDP targets for `port`.
///
/// Covers all discovered local IPv4 interfaces so beacons traverse Wi-Fi
/// routers and hotspots that drop IGMP multicast (`239.255.74.74`).
#[must_use]
pub fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut targets: Vec<SocketAddr> = Vec::new();
    for ip in local_ips() {
        if let IpAddr::V4(v4) = ip {
            let [a, b, c, _] = v4.octets();
            let subnet_bcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, 255)), port);
            if !targets.contains(&subnet_bcast) {
                targets.push(subnet_bcast);
            }
        }
    }
    let limited = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port);
    if !targets.contains(&limited) {
        targets.push(limited);
    }
    targets
}
