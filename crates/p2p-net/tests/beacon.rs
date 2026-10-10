//! Devices of one account find each other on a network by sealed beacons,
//! and a beacon grants nothing: dialing still needs the whole handshake.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    clippy::significant_drop_tightening,
    reason = "tests may unwrap and index"
)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::SyncIdentity;
use p2p_core::seal_beacon;
use p2p_net::{
    now_ms, personal_view, BeaconConfig, BeaconIdentity, Conn, Dialing, Event, FetchError, Policy,
    Provider, Relay, RelayLimits, Service, SnapshotSource, VaultView,
};
use secret::Secret;
use syncwire::{encode_beacon, Beacon, RelayHint};

const SEED: [u8; 64] = [3; 64];

fn device(seed: &[u8; 64], device: u8) -> Arc<SyncIdentity> {
    let client_id = kdf::client_id(seed).unwrap();
    Arc::new(SyncIdentity::enroll(seed, &client_id, [device; 16], u64::MAX).unwrap())
}

const fn dialing() -> Dialing {
    Dialing {
        policy: Policy { loopback: true },
        trusted: Vec::new(),
    }
}

/// A node that serves only the personal vault's handshake.
struct Node(Arc<SyncIdentity>);

impl Provider for Node {
    fn views(&self) -> Vec<VaultView> {
        personal_view(&self.0, dialing()).into_iter().collect()
    }
    fn log(&self, _: &[u8; 16]) -> Option<Vec<u8>> {
        None
    }
    fn snapshot_source(&self, _: &[u8; 16]) -> Option<SnapshotSource> {
        None
    }
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(bind: u16, send_to: u16, loopback: bool) -> BeaconConfig {
    BeaconConfig {
        send_to: SocketAddr::from(([127, 0, 0, 1], send_to)),
        bind: SocketAddr::from(([127, 0, 0, 1], bind)),
        join: None,
        every: Duration::from_millis(150),
        loopback,
    }
}

fn gate(seed: &[u8; 64]) -> Secret<[u8; 32]> {
    kdf::account_gate_secret(seed).unwrap()
}

struct Peer {
    identity: Arc<SyncIdentity>,
    provider: Arc<Node>,
    service: Service,
    tcp: SocketAddr,
}

fn start(seed: &[u8; 64], id: u8, bind: u16, send_to: u16, loopback: bool) -> Peer {
    let identity = device(seed, id);
    let provider = Arc::new(Node(Arc::clone(&identity)));
    let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let beacon = BeaconIdentity::new(&gate(seed), [id; 16]).unwrap();
    service
        .start_beacon(
            Arc::clone(&provider),
            beacon,
            config(bind, send_to, loopback),
        )
        .unwrap();
    let tcp = service.local_addr().unwrap();
    Peer {
        identity,
        provider,
        service,
        tcp,
    }
}

fn discovered_with_relays(
    service: &Service,
    within: Duration,
    wanted: impl Fn(&[RelayHint]) -> bool,
) -> Option<(SocketAddr, Vec<[u8; 16]>, Vec<RelayHint>)> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Ok(Event::Discovered {
            address,
            vaults,
            relays,
        }) = service.events().recv_timeout(Duration::from_millis(100))
        {
            if wanted(&relays) {
                return Some((address, vaults, relays));
            }
        }
    }
    None
}

fn discovered(service: &Service, within: Duration) -> Option<(SocketAddr, Vec<[u8; 16]>)> {
    discovered_with_relays(service, within, |_| true).map(|(address, vaults, _)| (address, vaults))
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn two_devices_of_an_account_find_each_other_and_still_need_the_handshake() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let a = start(&SEED, 1, pa, pb, true);
    let b = start(&SEED, 2, pb, pa, true);

    let (found, vaults) = discovered(&b.service, Duration::from_secs(20)).expect("a was heard");
    assert_eq!(found, a.tcp, "its address and the port it listens on");
    let route = kdf::account_route_id(&gate(&SEED)).unwrap();
    assert_eq!(vaults, [route]);
    let (back, _) = discovered(&a.service, Duration::from_secs(20)).expect("b was heard");
    assert_eq!(back, b.tcp);

    // The address works for a device of the account, and for no one else.
    let view = personal_view(&b.identity, dialing()).unwrap();
    let stranger = personal_view(&device(&[4; 64], 9), dialing()).unwrap();
    block_on(async {
        let conn = Conn::connect(&view, &found.to_string()).await.unwrap();
        assert_eq!(conn.peer.device_id, [1; 16]);
        assert_eq!(
            Conn::connect(&stranger, &found.to_string()).await.err(),
            Some(FetchError::Refused)
        );
    });
}

#[test]
fn a_beacon_of_another_account_is_not_even_noticed() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let b = start(&SEED, 2, pb, pa, true);
    let _other = start(&[4; 64], 7, pa, pb, true);
    assert!(discovered(&b.service, Duration::from_secs(2)).is_none());
}

#[test]
fn nothing_but_a_fresh_sealed_beacon_of_another_device_is_heard() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let b = start(&SEED, 2, pb, pa, true);
    let key = kdf::p2p_beacon_key(&gate(&SEED)).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = SocketAddr::from(([127, 0, 0, 1], pb));
    let good = encode_beacon(&Beacon {
        vaults: vec![[5; 16]],
        relays: Vec::new(),
        port: 4000,
    })
    .unwrap();
    let sealed =
        |device: u8, at: u64, payload: &[u8]| seal_beacon(&key, [device; 16], at, payload).unwrap();
    let stale = sealed(3, now_ms() - 10 * 60_000, &good);
    let future = sealed(3, now_ms() + 10 * 60_000, &good);
    let mut flipped = sealed(3, now_ms(), &good);
    flipped[100] ^= 1;
    let mut cut = sealed(3, now_ms(), &good);
    cut.truncate(cut.len() - 1);
    let own = sealed(2, now_ms(), &good);
    let mut trailing = good.clone();
    trailing.push(0);
    let no_port = sealed(
        3,
        now_ms(),
        &[
            b'Z', b'P', b'B', b'C', 0, 1, 0, 0, 1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        ],
    );
    for bad in [
        vec![],
        vec![0; 10],
        vec![0xFF; 3000],
        good.clone(),
        stale,
        future,
        flipped,
        cut,
        own,
        sealed(3, now_ms(), &trailing),
        no_port,
        sealed(3, now_ms(), b"hello"),
    ] {
        socket.send_to(&bad, to).unwrap();
    }
    assert!(
        discovered(&b.service, Duration::from_secs(2)).is_none(),
        "none of those is a beacon"
    );
    socket.send_to(&sealed(3, now_ms(), &good), to).unwrap();
    let (address, vaults) = discovered(&b.service, Duration::from_secs(10)).unwrap();
    assert_eq!(address, SocketAddr::from(([127, 0, 0, 1], 4000)));
    assert_eq!(vaults, [[5; 16]]);
    // The same announcement again is not reported again so soon.
    socket.send_to(&sealed(3, now_ms(), &good), to).unwrap();
    assert!(discovered(&b.service, Duration::from_millis(600)).is_none());
}

#[test]
fn an_address_on_this_machine_is_ignored_unless_asked_for() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let _a = start(&SEED, 1, pa, pb, true);
    let b = start(&SEED, 2, pb, pa, false);
    assert!(
        discovered(&b.service, Duration::from_secs(2)).is_none(),
        "loopback is heard only when the test opts in"
    );
}

#[test]
fn a_node_that_is_not_listening_cannot_announce() {
    let provider = Arc::new(Node(device(&SEED, 1)));
    let service = Service::start(None, Arc::clone(&provider)).unwrap();
    let beacon = BeaconIdentity::new(&gate(&SEED), [1; 16]).unwrap();
    assert!(service
        .start_beacon(provider, beacon, config(free_udp_port(), 1, true))
        .is_err());
}

#[test]
fn a_node_that_holds_a_relay_slot_announces_it_to_the_account() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let a = start(&SEED, 1, pa, pb, true);
    let b = start(&SEED, 2, pb, pa, true);
    let relay = Relay::start(
        "127.0.0.1:0",
        RelayLimits {
            difficulty_idle: 4,
            ..RelayLimits::default()
        },
    )
    .unwrap();
    assert!(a
        .service
        .hold_relay(Arc::clone(&a.provider), relay.local_addr()));
    let hint = loop {
        if let Ok(Event::Relayed(hint)) = a.service.events().recv_timeout(Duration::from_secs(30)) {
            break hint;
        }
    };
    let (address, _, relays) =
        discovered_with_relays(&b.service, Duration::from_secs(20), |held| !held.is_empty())
            .expect("the beacon names the slot");
    assert_eq!(address, a.tcp);
    assert_eq!(relays, [hint]);
}

#[test]
fn a_relay_hint_in_a_beacon_passes_the_address_rules_like_any_other_address() {
    let (pa, pb) = (free_udp_port(), free_udp_port());
    let b = start(&SEED, 2, pb, pa, false);
    let key = kdf::p2p_beacon_key(&gate(&SEED)).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let slot = [7u8; 16];
    let hint = |text: &str| RelayHint {
        relay: text.parse().unwrap(),
        slot,
    };
    let beacon = encode_beacon(&Beacon {
        vaults: vec![[5; 16]],
        relays: vec![hint("93.184.216.34:7447"), hint("169.254.169.254:7447")],
        port: 4000,
    })
    .unwrap();
    let sealed = seal_beacon(&key, [3; 16], now_ms(), &beacon).unwrap();
    // The sender is on this machine, so a node that does not opt in to
    // loopback ignores the whole beacon; one that does keeps only the hints
    // that could ever be dialed.
    socket
        .send_to(&sealed, SocketAddr::from(([127, 0, 0, 1], pb)))
        .unwrap();
    assert!(discovered(&b.service, Duration::from_secs(2)).is_none());
    let (pc, pd) = (free_udp_port(), free_udp_port());
    let c = start(&SEED, 4, pd, pc, true);
    socket
        .send_to(&sealed, SocketAddr::from(([127, 0, 0, 1], pd)))
        .unwrap();
    let (_, _, relays) =
        discovered_with_relays(&c.service, Duration::from_secs(10), |_| true).unwrap();
    assert_eq!(
        relays,
        [hint("93.184.216.34:7447")],
        "link-local is dropped"
    );
}
