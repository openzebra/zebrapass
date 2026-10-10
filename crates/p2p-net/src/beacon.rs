//! Finding other devices of the account on the local network.
//!
//! A device sends a sealed beacon, to a multicast group, every
//! [`BeaconConfig::every`], and listens on the same group. The beacon names
//! the port the sender accepts connections on and the vaults it serves,
//! sealed under a key only devices of the account derive. It is discovery and
//! nothing more: a device that hears one only learns an address, and dialing
//! it still goes through the whole handshake. Whatever does not open, parse
//! or pass the address rules is ignored without a word.

use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::parse_peer_address;
use p2p_core::{open_beacon, seal_beacon, MAX_BEACON};
use secret::Secret;
use syncwire::{decode_beacon, encode_beacon, Beacon, MAX_BEACON_VAULTS};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::io::now_ms;
use crate::service::{Event, Service};
use crate::view::Provider;

/// The multicast group beacons go to on a local network.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 74, 74);

/// The UDP port beacons use.
pub const PORT: u16 = 7448;

/// Addresses remembered to hear each at most once in a while.
const REMEMBERED: usize = 64;

/// Where beacons go, where they are heard, and how often they are sent.
#[derive(Clone, Copy, Debug)]
pub struct BeaconConfig {
    /// Where beacons are sent.
    pub send_to: SocketAddr,
    /// Where beacons are heard.
    pub bind: SocketAddr,
    /// The multicast group to join, if `bind` is a group's port.
    pub join: Option<Ipv4Addr>,
    /// Time between beacons.
    pub every: Duration,
    /// Accept an address on this machine: for tests and single-machine
    /// setups.
    pub loopback: bool,
}

impl BeaconConfig {
    /// The multicast group of a local network.
    #[must_use]
    pub const fn lan() -> Self {
        Self {
            send_to: SocketAddr::new(std::net::IpAddr::V4(GROUP), PORT),
            bind: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT),
            join: Some(GROUP),
            every: Duration::from_secs(30),
            loopback: false,
        }
    }
}

/// What a beacon task needs to know about this device.
pub struct BeaconIdentity {
    /// Key beacons are sealed under, from the account's gate secret.
    pub key: Secret<[u8; 32]>,
    /// This device's id, so it ignores its own beacons.
    pub device_id: [u8; 16],
}

impl BeaconIdentity {
    /// The identity of this device for the account whose gate secret is
    /// `gate`.
    ///
    /// # Errors
    ///
    /// Key derivation failure.
    pub fn new(gate: &Secret<[u8; 32]>, device_id: [u8; 16]) -> Result<Self> {
        Ok(Self {
            key: kdf::p2p_beacon_key(gate)?,
            device_id,
        })
    }
}

/// Bind the socket a beacon task uses.
///
/// # Errors
///
/// The port is taken, or the group cannot be joined.
pub async fn open_socket(config: &BeaconConfig) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(config.bind).await?;
    if let Some(group) = config.join {
        socket.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED)?;
        socket.set_multicast_loop_v4(true)?;
    }
    Ok(socket)
}

async fn announce<P: Provider>(
    socket: &UdpSocket,
    provider: &Arc<P>,
    identity: &BeaconIdentity,
    port: u16,
    config: &BeaconConfig,
) {
    let served = Arc::clone(provider);
    let vaults: Vec<[u8; 16]> = tokio::task::spawn_blocking(move || {
        served
            .views()
            .iter()
            .take(MAX_BEACON_VAULTS)
            .map(|view| view.vault_id)
            .collect()
    })
    .await
    .unwrap_or_default();
    let sealed = encode_beacon(&Beacon { vaults, port })
        .and_then(|bytes| seal_beacon(&identity.key, identity.device_id, now_ms(), &bytes));
    if let Ok(wire) = sealed {
        let _ = socket.send_to(&wire, config.send_to).await;
    }
}

fn heard(
    identity: &BeaconIdentity,
    config: &BeaconConfig,
    wire: &[u8],
    from: SocketAddr,
) -> Option<Event> {
    let (sender, payload) = open_beacon(&identity.key, wire, now_ms()).ok()?;
    if sender == identity.device_id {
        return None;
    }
    let beacon = decode_beacon(payload.expose()).ok()?;
    let address = SocketAddr::new(from.ip().to_canonical(), beacon.port);
    parse_peer_address(&address.to_string(), config.loopback).ok()?;
    Some(Event::Discovered {
        address,
        vaults: beacon.vaults,
    })
}

/// Send a beacon now and every [`BeaconConfig::every`], and report each
/// address heard, until the runtime ends.
pub async fn run<P: Provider>(
    socket: UdpSocket,
    provider: Arc<P>,
    identity: BeaconIdentity,
    port: u16,
    config: BeaconConfig,
    events: Sender<Event>,
) {
    let mut buffer = vec![0u8; MAX_BEACON + 1];
    let mut known: HashMap<SocketAddr, Instant> = HashMap::with_capacity(REMEMBERED);
    let mut next = Instant::now();
    loop {
        let now = Instant::now();
        if now >= next {
            announce(&socket, &provider, &identity, port, &config).await;
            next = now + config.every;
        }
        let wait = next.saturating_duration_since(Instant::now());
        let Ok(received) = timeout(wait, socket.recv_from(&mut buffer)).await else {
            continue;
        };
        let Ok((len, from)) = received else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(wire) = buffer.get(..len).filter(|wire| wire.len() <= MAX_BEACON) else {
            continue;
        };
        let Some(Event::Discovered { address, vaults }) = heard(&identity, &config, wire, from)
        else {
            continue;
        };
        let now = Instant::now();
        known.retain(|_, at| now.duration_since(*at) < config.every);
        if known.contains_key(&address) || known.len() >= REMEMBERED {
            continue;
        }
        known.insert(address, now);
        if events.send(Event::Discovered { address, vaults }).is_err() {
            return;
        }
    }
}

impl Service {
    /// Start announcing this node on the local network and report the other
    /// devices of the account that do the same, as [`Event::Discovered`].
    ///
    /// # Errors
    ///
    /// The node is not listening, or the beacon socket could not be opened.
    pub fn start_beacon<P: Provider>(
        &self,
        provider: Arc<P>,
        identity: BeaconIdentity,
        config: BeaconConfig,
    ) -> Result<()> {
        let (Some(runtime), Some(local)) = (self.runtime.as_ref(), self.local_addr()) else {
            anyhow::bail!("the node is not listening");
        };
        let socket = runtime.block_on(open_socket(&config))?;
        runtime.spawn(run(
            socket,
            provider,
            identity,
            local.port(),
            config,
            self.sender.clone(),
        ));
        Ok(())
    }
}
