//! Automatic NAT port mapping (NAT-PMP / `UPnP` IGD) and STUN public address
//! discovery for direct WAN connectivity.
//!
//! All network packets are strictly bounded before parsing, and any discovered
//! external IP is checked against [`local::never_dialable`] before it is
//! reported as [`Event::Observed`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::time::Duration;

use local::never_dialable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use crate::interfaces::{default_gateways, local_ips};
use crate::service::{Event, Service};

/// Standard NAT-PMP UDP gateway port (RFC 6886).
pub const NAT_PMP_PORT: u16 = 5351;
/// STUN magic cookie (RFC 5389).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const SSDP_MULTICAST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAX_STUN_PACKET: usize = 548;
const MAX_UPNP_RESPONSE: usize = 8192;
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const LEASE_SECONDS: u32 = 3600;
const REFRESH_INTERVAL: Duration = Duration::from_secs(1800);
const STUN_SERVERS: [&str; 3] = [
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
];

/// Encode a 20-byte RFC 5389 STUN Binding Request for `tx_id`.
#[must_use]
pub fn encode_stun_binding_request(tx_id: &[u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    if let Some(head) = pkt.get_mut(0..2) {
        head.copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    }
    if let Some(cookie) = pkt.get_mut(4..8) {
        cookie.copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    }
    if let Some(tx) = pkt.get_mut(8..20) {
        tx.copy_from_slice(tx_id);
    }
    pkt
}

/// Decode an RFC 5389 STUN Binding Response, verifying `expected_tx_id` in
/// constant time and extracting the `XOR-MAPPED-ADDRESS` or `MAPPED-ADDRESS`.
#[must_use]
pub fn decode_stun_binding_response(pkt: &[u8], expected_tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if pkt.len() < 20 || pkt.len() > MAX_STUN_PACKET {
        return None;
    }
    let msg_type = u16::from_be_bytes(pkt.get(0..2)?.try_into().ok()?);
    let msg_len = usize::from(u16::from_be_bytes(pkt.get(2..4)?.try_into().ok()?));
    let cookie = u32::from_be_bytes(pkt.get(4..8)?.try_into().ok()?);
    let tx_id: &[u8; 12] = pkt.get(8..20)?.try_into().ok()?;
    if msg_type != STUN_BINDING_RESPONSE
        || cookie != STUN_MAGIC_COOKIE
        || !secret::ct_eq(tx_id, expected_tx_id)
    {
        return None;
    }
    let mut attrs = pkt.get(20..20usize.checked_add(msg_len)?)?;
    let mut fallback: Option<SocketAddr> = None;
    while attrs.len() >= 4 {
        let attr_type = u16::from_be_bytes(attrs.get(0..2)?.try_into().ok()?);
        let attr_len = usize::from(u16::from_be_bytes(attrs.get(2..4)?.try_into().ok()?));
        let value = attrs.get(4..4usize.checked_add(attr_len)?)?;
        let padded = attr_len.checked_add(3)? & !3;
        attrs = attrs.get(4usize.checked_add(padded)?..).unwrap_or(&[]);
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_stun_address(value, true, expected_tx_id) {
                return Some(addr);
            }
        } else if attr_type == STUN_ATTR_MAPPED_ADDRESS && fallback.is_none() {
            fallback = parse_stun_address(value, false, expected_tx_id);
        }
    }
    fallback
}

fn parse_stun_address(value: &[u8], xor: bool, tx_id: &[u8; 12]) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let raw_port = u16::from_be_bytes(value.get(2..4)?.try_into().ok()?);
    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
    let [c0, c1, _, _] = cookie_bytes;
    let port = if xor {
        raw_port ^ u16::from_be_bytes([c0, c1])
    } else {
        raw_port
    };
    if port == 0 {
        return None;
    }
    match family {
        0x01 => {
            let mut octets: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            if xor {
                for (b, c) in octets.iter_mut().zip(cookie_bytes) {
                    *b ^= c;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            let mut octets: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            if xor {
                for (b, c) in octets.iter_mut().take(4).zip(cookie_bytes) {
                    *b ^= c;
                }
                for (b, t) in octets.iter_mut().skip(4).zip(tx_id) {
                    *b ^= *t;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

/// Encode a 2-byte NAT-PMP external IPv4 address request (`[0, 0]`).
#[must_use]
pub const fn encode_nat_pmp_external_ip_request() -> [u8; 2] {
    [0, 0]
}

/// Decode a 12-byte NAT-PMP external IPv4 address response.
#[must_use]
pub fn decode_nat_pmp_external_ip_response(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 12 {
        return None;
    }
    let result_code = u16::from_be_bytes(pkt.get(2..4)?.try_into().ok()?);
    if *pkt.first()? != 0 || *pkt.get(1)? != 128 || result_code != 0 {
        return None;
    }
    let octets: [u8; 4] = pkt.get(8..12)?.try_into().ok()?;
    let ip = Ipv4Addr::from(octets);
    (!ip.is_unspecified() && !ip.is_loopback() && !never_dialable(IpAddr::V4(ip))).then_some(ip)
}

/// Encode a 12-byte NAT-PMP TCP port mapping request for `internal_port`.
#[must_use]
pub fn encode_nat_pmp_tcp_map_request(internal_port: u16, lease_s: u32) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    if let Some(op) = pkt.get_mut(1) {
        *op = 2;
    }
    if let Some(int_p) = pkt.get_mut(4..6) {
        int_p.copy_from_slice(&internal_port.to_be_bytes());
    }
    if let Some(ext_p) = pkt.get_mut(6..8) {
        ext_p.copy_from_slice(&internal_port.to_be_bytes());
    }
    if let Some(ttl) = pkt.get_mut(8..12) {
        ttl.copy_from_slice(&lease_s.to_be_bytes());
    }
    pkt
}

/// Decode a 16-byte NAT-PMP TCP port mapping response, returning the mapped
/// external port.
#[must_use]
pub fn decode_nat_pmp_tcp_map_response(pkt: &[u8], expected_internal: u16) -> Option<u16> {
    if pkt.len() < 16 {
        return None;
    }
    let result_code = u16::from_be_bytes(pkt.get(2..4)?.try_into().ok()?);
    let internal = u16::from_be_bytes(pkt.get(8..10)?.try_into().ok()?);
    let external = u16::from_be_bytes(pkt.get(10..12)?.try_into().ok()?);
    if *pkt.first()? != 0
        || *pkt.get(1)? != 130
        || result_code != 0
        || internal != expected_internal
        || external == 0
    {
        return None;
    }
    Some(external)
}

/// Query a NAT-PMP gateway at `gateway_addr` for the external IPv4 and a TCP
/// mapping for `internal_port`.
pub async fn probe_nat_pmp_gateway(
    gateway_addr: SocketAddr,
    internal_port: u16,
) -> Option<SocketAddr> {
    let bind_addr = if gateway_addr.ip().is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.ok()?;
    socket.connect(gateway_addr).await.ok()?;
    socket
        .send(&encode_nat_pmp_external_ip_request())
        .await
        .ok()?;
    let mut buf = [0u8; 32];
    let n = timeout(PROBE_TIMEOUT, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let ext_ip = decode_nat_pmp_external_ip_response(buf.get(..n)?)?;
    socket
        .send(&encode_nat_pmp_tcp_map_request(
            internal_port,
            LEASE_SECONDS,
        ))
        .await
        .ok()?;
    let n2 = timeout(PROBE_TIMEOUT, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let ext_port = decode_nat_pmp_tcp_map_response(buf.get(..n2)?, internal_port)?;
    Some(SocketAddr::new(IpAddr::V4(ext_ip), ext_port))
}

/// Query a STUN server at `server_addr` for this node's reflexive public
/// address.
pub async fn probe_stun_server(server_addr: SocketAddr) -> Option<SocketAddr> {
    let rand_bytes = p2p_core::relay_random().ok()?;
    let tx_id: [u8; 12] = rand_bytes.get(0..12)?.try_into().ok()?;
    let bind_addr = if server_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.ok()?;
    socket
        .send_to(&encode_stun_binding_request(&tx_id), server_addr)
        .await
        .ok()?;
    let mut buf = [0u8; MAX_STUN_PACKET];
    let (n, _) = timeout(PROBE_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    decode_stun_binding_response(buf.get(..n)?, &tx_id)
}

async fn try_upnp_igd(internal_port: u16) -> Option<SocketAddr> {
    let local_v4 = local_ips().into_iter().find_map(|ip| match ip {
        IpAddr::V4(v4) if v4.is_private() => Some(v4),
        _ => None,
    })?;
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let search = concat!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\n",
        "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n"
    );
    socket
        .send_to(search.as_bytes(), SSDP_MULTICAST)
        .await
        .ok()?;
    let mut buf = [0u8; 2048];
    let (n, from) = timeout(PROBE_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let IpAddr::V4(gw_ip) = from.ip().to_canonical() else {
        return None;
    };
    if !gw_ip.is_private() {
        return None;
    }
    let text = std::str::from_utf8(buf.get(..n)?).ok()?;
    let (ctrl_addr, ctrl_path) = parse_ssdp_location(text, gw_ip)?;
    upnp_map_and_query(ctrl_addr, &ctrl_path, local_v4, internal_port).await
}

fn parse_ssdp_location(response: &str, expected_gw: Ipv4Addr) -> Option<(SocketAddr, String)> {
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("location:") {
            let url = line.get(line.len().checked_sub(rest.len())?..)?.trim();
            let without_scheme = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("HTTP://"))?;
            let (host_port, path_part) = without_scheme
                .split_once('/')
                .map_or((without_scheme, ""), |(h, p)| (h, p));
            let addr: SocketAddr = host_port.parse().ok()?;
            return (addr.ip().to_canonical() == IpAddr::V4(expected_gw))
                .then(|| (addr, format!("/{path_part}")));
        }
    }
    None
}

async fn upnp_map_and_query(
    ctrl_addr: SocketAddr,
    desc_path: &str,
    local_ip: Ipv4Addr,
    port: u16,
) -> Option<SocketAddr> {
    let desc = http_request(ctrl_addr, "GET", desc_path, None, "").await?;
    let control_url = extract_xml_tag(&desc, "controlURL")?;
    let path = if control_url.starts_with('/') {
        control_url.to_owned()
    } else {
        format!("/{control_url}")
    };
    let map_body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
         <NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>\
         <NewProtocol>TCP</NewProtocol><NewInternalPort>{port}</NewInternalPort>\
         <NewInternalClient>{local_ip}</NewInternalClient><NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>ZebraPass</NewPortMappingDescription>\
         <NewLeaseDuration>{LEASE_SECONDS}</NewLeaseDuration>\
         </u:AddPortMapping></s:Body></s:Envelope>"
    );
    let _ = http_request(
        ctrl_addr,
        "POST",
        &path,
        Some("\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""),
        &map_body,
    )
    .await;
    let ip_body = concat!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ",
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>",
        "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">",
        "</u:GetExternalIPAddress></s:Body></s:Envelope>"
    );
    let ip_resp = http_request(
        ctrl_addr,
        "POST",
        &path,
        Some("\"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\""),
        ip_body,
    )
    .await?;
    let ext_ip: Ipv4Addr = extract_xml_tag(&ip_resp, "NewExternalIPAddress")?
        .parse()
        .ok()?;
    (!ext_ip.is_unspecified() && !ext_ip.is_loopback() && !ExtFilter::rejects(IpAddr::V4(ext_ip)))
        .then_some(SocketAddr::new(IpAddr::V4(ext_ip), port))
}

struct ExtFilter;

impl ExtFilter {
    const fn rejects(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || never_dialable(ip),
            IpAddr::V6(v6) => v6.is_loopback() || never_dialable(ip),
        }
    }
}

fn extract_xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let rest = xml.get(xml.find(&open)?.checked_add(open.len())?..)?;
    Some(rest.get(..rest.find(&close)?)?.trim())
}

async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    soap_action: Option<&str>,
    body: &str,
) -> Option<String> {
    let mut stream = timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let action_header =
        soap_action.map_or_else(String::new, |act| format!("SOAPAction: {act}\r\n"));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         {action_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(PROBE_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(1024);
    let mut limited = stream.take(MAX_UPNP_RESPONSE as u64);
    timeout(PROBE_TIMEOUT, limited.read_to_end(&mut buf))
        .await
        .ok()?
        .ok()?;
    String::from_utf8(buf).ok()
}

async fn discover_wan_endpoint(internal_port: u16) -> Option<SocketAddr> {
    for gw in default_gateways() {
        let gw_addr = SocketAddr::new(IpAddr::V4(gw), NAT_PMP_PORT);
        if let Some(mapped) = probe_nat_pmp_gateway(gw_addr, internal_port).await {
            if !ExtFilter::rejects(mapped.ip()) {
                return Some(mapped);
            }
        }
    }
    if let Some(mapped) = try_upnp_igd(internal_port).await {
        return Some(mapped);
    }
    for host in STUN_SERVERS {
        let Ok(Ok(iter)) = timeout(PROBE_TIMEOUT, lookup_host(host)).await else {
            continue;
        };
        for server_addr in iter.take(2) {
            if let Some(reflexive) = probe_stun_server(server_addr).await {
                let ip = reflexive.ip().to_canonical();
                if !ExtFilter::rejects(ip) {
                    return Some(SocketAddr::new(ip, internal_port));
                }
            }
        }
    }
    None
}

async fn nat_loop(port: u16, events: Sender<Event>) {
    loop {
        if let Some(wan) = discover_wan_endpoint(port).await {
            if events.send(Event::Observed(wan)).is_err() {
                return;
            }
        }
        sleep(REFRESH_INTERVAL).await;
    }
}

impl Service {
    /// Start background NAT-PMP / `UPnP` port mapping and STUN external address
    /// discovery for the node's listening port, reporting any discovered public
    /// endpoint via [`Event::Observed`].
    pub fn start_nat_traversal(&self) -> bool {
        let (Some(runtime), Some(local)) = (self.runtime.as_ref(), self.local_addr()) else {
            return false;
        };
        if local.ip().is_loopback() {
            return false;
        }
        runtime.spawn(nat_loop(local.port(), self.sender.clone()));
        true
    }
}
