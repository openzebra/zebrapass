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
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::parse_peer_address;
use p2p_core::{open_beacon, seal_beacon, MAX_BEACON};
use secret::Secret;
use syncwire::{decode_beacon, encode_beacon, Beacon, MAX_BEACON_RELAYS, MAX_BEACON_VAULTS};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time::timeout;

use crate::io::now_ms;
use crate::service::{Event, Service, Shared};
use crate::view::Provider;

/// The multicast group beacons go to on a local network.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 74, 74);

/// The UDP port beacons use.
pub const PORT: u16 = 7448;

/// Addresses remembered to hear each at most once in a while.
const REMEMBERED: usize = 64;

/// Where beacons go, where they are heard, and how often they are sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    let _ = socket.set_broadcast(true);
    if let Some(group) = config.join {
        socket.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED)?;
        for ip in crate::interfaces::local_ips() {
            if let std::net::IpAddr::V4(iface) = ip {
                let _ = socket.join_multicast_v4(group, iface);
            }
        }
        socket.set_multicast_loop_v4(true)?;
    }
    Ok(socket)
}

async fn sealed_beacons<P: Provider>(
    provider: &Arc<P>,
    shared: &Shared,
    identity: &BeaconIdentity,
    port: u16,
) -> (Vec<Vec<u8>>, Vec<Secret<[u8; 32]>>) {
    let served = Arc::clone(provider);
    let (view_ids, extra_targets) = tokio::task::spawn_blocking(move || {
        let ids: Vec<[u8; 16]> = served
            .views()
            .iter()
            .take(MAX_BEACON_VAULTS)
            .map(|view| view.vault_id)
            .collect();
        let targets = served.beacon_targets();
        (ids, targets)
    })
    .await
    .unwrap_or_default();

    let relays: Vec<syncwire::RelayHint> = shared
        .relay_hints
        .lock()
        .map(|held| held.iter().take(MAX_BEACON_RELAYS).copied().collect())
        .unwrap_or_default();

    let mut primary_vaults = view_ids;
    let mut keys = vec![Secret::new(*identity.key.expose())];
    let mut extra_packets: Vec<Vec<u8>> = Vec::new();
    let now = now_ms();

    for (key, vault_id) in extra_targets {
        if secret::ct_eq(key.expose(), identity.key.expose()) {
            if !primary_vaults.contains(&vault_id) && primary_vaults.len() < MAX_BEACON_VAULTS {
                primary_vaults.push(vault_id);
            }
        } else {
            if !keys
                .iter()
                .any(|known| secret::ct_eq(known.expose(), key.expose()))
            {
                keys.push(Secret::new(*key.expose()));
            }
            let pkt = encode_beacon(&Beacon {
                vaults: vec![vault_id],
                relays: relays.clone(),
                port,
            })
            .and_then(|bytes| seal_beacon(&key, identity.device_id, now, &bytes));
            if let Ok(wire) = pkt {
                extra_packets.push(wire);
            }
        }
    }

    let mut packets = Vec::with_capacity(1 + extra_packets.len());
    let primary = encode_beacon(&Beacon {
        vaults: primary_vaults,
        relays,
        port,
    })
    .and_then(|bytes| seal_beacon(&identity.key, identity.device_id, now, &bytes));
    if let Ok(wire) = primary {
        packets.push(wire);
    }
    packets.extend(extra_packets);
    (packets, keys)
}

async fn announce(socket: &UdpSocket, packets: &[Vec<u8>], config: &BeaconConfig) {
    let mut destinations = vec![config.send_to];
    if config.join.is_some() {
        for target in crate::interfaces::broadcast_targets(config.send_to.port()) {
            if !destinations.contains(&target) {
                destinations.push(target);
            }
        }
    }
    for pkt in packets {
        for dest in &destinations {
            let _ = socket.send_to(pkt, *dest).await;
        }
    }
}

type HeardKey = (SocketAddr, [u8; 16], usize);

/// Opens the beacons that arrive and remembers which addresses it has
/// already reported lately.
struct Hearer {
    config: BeaconConfig,
    known: HashMap<HeardKey, Instant>,
}

impl Hearer {
    fn new(config: BeaconConfig) -> Self {
        Self {
            config,
            known: HashMap::with_capacity(REMEMBERED),
        }
    }

    /// The event for one datagram, if it is a fresh beacon of another device
    /// of the account or shared vault naming an address worth trying that was
    /// not just heard.
    fn hear(
        &mut self,
        device_id: [u8; 16],
        keys: &[Secret<[u8; 32]>],
        wire: &[u8],
        from: SocketAddr,
    ) -> Option<Event> {
        if wire.len() > MAX_BEACON {
            return None;
        }
        let now_ts = now_ms();
        let (sender, payload) = keys
            .iter()
            .find_map(|key| open_beacon(key, wire, now_ts).ok())?;
        if sender == device_id {
            return None;
        }
        let beacon = decode_beacon(payload.expose()).ok()?;
        let address = SocketAddr::new(from.ip().to_canonical(), beacon.port);
        parse_peer_address(&address.to_string(), self.config.loopback).ok()?;
        let relays: Vec<syncwire::RelayHint> = beacon
            .relays
            .into_iter()
            .filter(|hint| {
                parse_peer_address(&hint.relay.to_string(), self.config.loopback).is_ok()
            })
            .collect();
        let first_vault = beacon.vaults.first().copied().unwrap_or([0; 16]);
        let heard_key = (address, first_vault, relays.len());
        let now = Instant::now();
        self.known
            .retain(|_, at| now.duration_since(*at) < self.config.every);
        if self.known.contains_key(&heard_key) || self.known.len() >= REMEMBERED {
            return None;
        }
        self.known.insert(heard_key, now);
        Some(Event::Discovered {
            address,
            vaults: beacon.vaults,
            relays,
        })
    }
}

/// Send a beacon now and every [`BeaconConfig::every`], and report each
/// address heard, until the runtime ends.
pub async fn run<P: Provider>(
    socket: UdpSocket,
    provider: Arc<P>,
    shared: Arc<Shared>,
    identity: BeaconIdentity,
    port: u16,
    config: BeaconConfig,
    events: Sender<Event>,
) {
    let mut buffer = vec![0u8; MAX_BEACON + 1];
    let mut hearer = Hearer::new(config);
    let mut next = Instant::now();
    let mut keys = vec![Secret::new(*identity.key.expose())];
    loop {
        let now = Instant::now();
        if now >= next {
            let (packets, fresh_keys) = sealed_beacons(&provider, &shared, &identity, port).await;
            keys = fresh_keys;
            announce(&socket, &packets, &config).await;
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
        let Some(wire) = buffer.get(..len) else {
            continue;
        };
        let mut event = hearer.hear(identity.device_id, &keys, wire, from);
        if event.is_none() {
            let (_, fresh_keys) = sealed_beacons(&provider, &shared, &identity, port).await;
            keys = fresh_keys;
            event = hearer.hear(identity.device_id, &keys, wire, from);
        }
        let Some(discovered) = event else {
            continue;
        };
        let (packets, _) = sealed_beacons(&provider, &shared, &identity, port).await;
        for pkt in &packets {
            let _ = socket.send_to(pkt, from).await;
        }
        if events.send(discovered).is_err() {
            return;
        }
    }
}

async fn listen(
    socket: UdpSocket,
    identity: BeaconIdentity,
    config: BeaconConfig,
    events: Sender<Event>,
) {
    let mut buffer = vec![0u8; MAX_BEACON + 1];
    let mut hearer = Hearer::new(config);
    let keys = [identity.key];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(event) = buffer
            .get(..len)
            .and_then(|wire| hearer.hear(identity.device_id, &keys, wire, from))
        else {
            continue;
        };
        if events.send(event).is_err() {
            return;
        }
    }
}

/// Listens for beacons of one account and sends none: for a device that has
/// only the account's seed, such as one being restored. Dropping it closes
/// the socket.
pub struct BeaconListener {
    key: Secret<[u8; 32]>,
    events: Receiver<Event>,
    runtime: Option<Runtime>,
}

impl std::fmt::Debug for BeaconListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BeaconListener")
    }
}

impl BeaconListener {
    /// Start listening for the account of `seed`.
    ///
    /// # Errors
    ///
    /// Key derivation failure, or the socket could not be opened.
    pub fn start(seed: &[u8; 64], config: BeaconConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let socket = runtime.block_on(open_socket(&config))?;
        let (sender, events) = channel();
        runtime.spawn(listen(
            socket,
            BeaconIdentity {
                key: account_beacon_key(seed)?,
                device_id: [0; 16],
            },
            config,
            sender,
        ));
        Ok(Self {
            key: account_beacon_key(seed)?,
            events,
            runtime: Some(runtime),
        })
    }

    /// Whether this listener is for the account of `seed`.
    #[must_use]
    pub fn is_for(&self, seed: &[u8; 64]) -> bool {
        account_beacon_key(seed).is_ok_and(|key| secret::ct_eq(key.expose(), self.key.expose()))
    }

    /// The addresses heard since the last call.
    #[must_use]
    pub fn poll(&self) -> Vec<SocketAddr> {
        self.events
            .try_iter()
            .filter_map(|event| match event {
                Event::Discovered { address, .. } => Some(address),
                _ => None,
            })
            .collect()
    }
}

impl Drop for BeaconListener {
    fn drop(&mut self) {
        // Wait for the socket to close, so its port is free when this returns.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_millis(500));
        }
    }
}

fn account_beacon_key(seed: &[u8; 64]) -> Result<Secret<[u8; 32]>> {
    kdf::p2p_beacon_key(&kdf::account_gate_secret(seed)?)
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
            Arc::clone(&self.shared),
            identity,
            local.port(),
            config,
            self.sender.clone(),
        ));
        Ok(())
    }
}
