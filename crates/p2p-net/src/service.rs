//! The running node: a listener, the limits that protect it, and background
//! fetches, all on a runtime of its own so the interface thread never waits
//! on the network. The interface polls [`Service::events`] and
//! [`Service::status`].

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use p2p_core::{CookieSecret, Load};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use crate::client::{fetch_paths, FetchError};
use crate::limits::{HandshakeSlot, Limits, Tickets};
use crate::server::{authenticate, first_message, serve_requests_with};
use crate::view::{Provider, VaultView};

/// Handshakes in flight before new connections are dropped unanswered.
const MAX_HANDSHAKES: usize = 32;

/// In-flight handshakes up to which no puzzle is asked.
const FREE_HANDSHAKES: usize = 6;

/// Hellos remembered to refuse a replay, and for how long.
const REPLAY_CAPACITY: usize = 4096;
const REPLAY_WINDOW: Duration = Duration::from_secs(120);

/// How long a whole handshake may take, however it is paced.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Largest vault file or log a fetch accepts.
const MAX_FETCH: usize = 512 << 20;

/// How often and how long a fetch retries.
const FETCH_RETRY: Duration = Duration::from_secs(3);
const FETCH_ATTEMPTS: usize = 40;

/// Something the interface should know about.
#[derive(Debug)]
pub enum Event {
    /// The node accepts connections here.
    Listening(SocketAddr),
    /// A member's device connected and authenticated.
    PeerConnected {
        vault_id: [u8; 16],
        device_id: [u8; 16],
        client_id: [u8; 64],
    },
    /// That connection ended.
    PeerGone { vault_id: [u8; 16] },
    /// A fetch brought back a vault's member log and file.
    Fetched {
        vault_id: [u8; 16],
        log: Vec<u8>,
        snapshot: Vec<u8>,
        /// The peer's current seed and epoch, when it offered them.
        rekey: Option<Zeroizing<Vec<u8>>>,
    },
    /// A check-in reached the members and traded revisions.
    Synced {
        vault_id: [u8; 16],
        pulled: usize,
        pushed: usize,
        refused: usize,
    },
    /// A fetch gave up, and why (the last attempt's reason).
    FetchFailed {
        vault_id: [u8; 16],
        reason: FetchError,
    },
}

/// A snapshot of the node's state, for the indicator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// Where the node listens, once it does.
    pub listening: Option<SocketAddr>,
    /// Authenticated peers connected now.
    pub peers: usize,
    /// Fetches still trying.
    pub fetching: usize,
}

pub struct Shared {
    peers: AtomicUsize,
    pub(crate) fetching: AtomicUsize,
    handshakes: AtomicUsize,
    tickets: Arc<Tickets>,
    listening: Mutex<Option<SocketAddr>>,
    replay: Mutex<Replay>,
}

#[derive(Default)]
struct Replay {
    order: VecDeque<(Instant, [u8; 32])>,
    seen: HashSet<[u8; 32]>,
}

impl Replay {
    /// Whether `hello` is new; remembers it either way.
    fn fresh(&mut self, hello: &[u8]) -> bool {
        let now = Instant::now();
        while let Some((at, key)) = self.order.front().copied() {
            if now.duration_since(at) > REPLAY_WINDOW || self.order.len() >= REPLAY_CAPACITY {
                self.order.pop_front();
                self.seen.remove(&key);
            } else {
                break;
            }
        }
        let key: [u8; 32] = Sha256::digest(hello).into();
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push_back((now, key));
        true
    }
}

fn load_for(handshakes: usize) -> Load {
    let over = handshakes.saturating_sub(FREE_HANDSHAKES);
    let difficulty = if over == 0 {
        0
    } else {
        u8::try_from(8 + over)
            .unwrap_or(u8::MAX)
            .min(p2p_core::MAX_DIFFICULTY)
    };
    Load { difficulty }
}

/// A running node.
pub struct Service {
    pub(crate) runtime: Option<Runtime>,
    pub(crate) shared: Arc<Shared>,
    events: Receiver<Event>,
    pub(crate) sender: Sender<Event>,
}

impl Service {
    /// Start serving what `provider` holds, listening on `listen`; with
    /// `None` the node only fetches and accepts no connection at all.
    ///
    /// # Errors
    ///
    /// The runtime or the listener could not start.
    pub fn start<P: Provider>(listen: Option<&str>, provider: Arc<P>) -> Result<Self> {
        Self::start_with(listen, provider, Limits::default())
    }

    /// [`Service::start`] with other bounds on what peers may hold.
    ///
    /// # Errors
    ///
    /// The runtime or the listener could not start.
    pub fn start_with<P: Provider>(
        listen: Option<&str>,
        provider: Arc<P>,
        limits: Limits,
    ) -> Result<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("zebrapass-p2p")
            .enable_all()
            .build()?;
        let (sender, events) = channel();
        let shared = Arc::new(Shared {
            peers: AtomicUsize::new(0),
            fetching: AtomicUsize::new(0),
            handshakes: AtomicUsize::new(0),
            tickets: Tickets::new(limits),
            listening: Mutex::new(None),
            replay: Mutex::new(Replay::default()),
        });
        if let Some(listen) = listen {
            let listener = runtime.block_on(TcpListener::bind(listen))?;
            let local = listener.local_addr()?;
            if let Ok(mut slot) = shared.listening.lock() {
                *slot = Some(local);
            }
            let _ = sender.send(Event::Listening(local));
            let cookies = Arc::new(CookieSecret::generate()?);
            runtime.spawn(accept_loop(
                listener,
                provider,
                cookies,
                Arc::clone(&shared),
                sender.clone(),
            ));
        }
        Ok(Self {
            runtime: Some(runtime),
            shared,
            events,
            sender,
        })
    }

    /// Where the node listens.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.shared.listening.lock().ok().and_then(|slot| *slot)
    }

    /// What the node is doing.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            listening: self.local_addr(),
            peers: self.shared.peers.load(Ordering::Relaxed),
            fetching: self.shared.fetching.load(Ordering::Relaxed),
        }
    }

    /// The events since the last poll; never blocks.
    #[must_use]
    pub const fn events(&self) -> &Receiver<Event> {
        &self.events
    }

    /// Fetch a vault's member log and file from whichever of `hints` answers,
    /// retrying for a while, and report the outcome as an event.
    pub fn fetch(&self, view: VaultView, hints: Vec<String>) {
        self.fetch_with(view, hints, FETCH_ATTEMPTS, FETCH_RETRY);
    }

    /// As [`Service::fetch`], with the number of rounds and the wait between
    /// them chosen by the caller.
    pub fn fetch_with(
        &self,
        view: VaultView,
        hints: Vec<String>,
        attempts: usize,
        retry: Duration,
    ) {
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let (shared, sender) = (Arc::clone(&self.shared), self.sender.clone());
        shared.fetching.fetch_add(1, Ordering::Relaxed);
        runtime.spawn(async move {
            let vault_id = view.vault_id;
            let mut reason = FetchError::Unreachable;
            let mut outcome = None;
            'attempts: for attempt in 0..attempts {
                if attempt > 0 {
                    tokio::time::sleep(retry).await;
                }
                for hint in &hints {
                    let got = fetch_paths(
                        &view,
                        hint,
                        &["/v1/log", "/v1/snapshot"],
                        &["/v1/rekey"],
                        MAX_FETCH,
                    )
                    .await;
                    match got {
                        Ok(fetched) => {
                            let mut bodies = fetched.bodies.into_iter();
                            if let (Some(log), Some(snapshot)) = (bodies.next(), bodies.next()) {
                                let rekey = fetched
                                    .extras
                                    .into_iter()
                                    .next()
                                    .flatten()
                                    .map(Zeroizing::new);
                                outcome = Some(Event::Fetched {
                                    vault_id,
                                    log,
                                    snapshot,
                                    rekey,
                                });
                                break 'attempts;
                            }
                            reason = FetchError::Failed;
                        }
                        Err(error) => reason = error,
                    }
                }
            }
            shared.fetching.fetch_sub(1, Ordering::Relaxed);
            let _ = sender.send(outcome.unwrap_or(Event::FetchFailed { vault_id, reason }));
        });
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn accept_loop<P: Provider>(
    listener: TcpListener,
    provider: Arc<P>,
    cookies: Arc<CookieSecret>,
    shared: Arc<Shared>,
    events: Sender<Event>,
) {
    loop {
        let Ok((tcp, from)) = listener.accept().await else {
            return;
        };
        if shared.handshakes.load(Ordering::Relaxed) >= MAX_HANDSHAKES {
            continue;
        }
        let Some(slot) = shared.tickets.begin(from.ip().to_canonical()) else {
            continue;
        };
        shared.handshakes.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(connection(
            tcp,
            slot,
            Arc::clone(&provider),
            Arc::clone(&cookies),
            Arc::clone(&shared),
            events.clone(),
        ));
    }
}

async fn connection<P: Provider>(
    mut tcp: TcpStream,
    slot: HandshakeSlot,
    provider: Arc<P>,
    cookies: Arc<CookieSecret>,
    shared: Arc<Shared>,
    events: Sender<Event>,
) {
    let load = load_for(shared.handshakes.load(Ordering::Relaxed));
    let admitted = tokio::time::timeout(
        HANDSHAKE_DEADLINE,
        admit(&mut tcp, &provider, &cookies, load, &shared),
    )
    .await
    .ok()
    .flatten();
    shared.handshakes.fetch_sub(1, Ordering::Relaxed);
    let Some((views, index, peer, channel)) = admitted else {
        return;
    };
    let Some(_place) = slot.promote() else {
        return;
    };
    let Some(view) = views.get(index) else {
        return;
    };
    let vault_id = view.vault_id;
    shared.peers.fetch_add(1, Ordering::Relaxed);
    let _ = events.send(Event::PeerConnected {
        vault_id,
        device_id: peer.device_id,
        client_id: peer.client_id,
    });
    let _ = serve_requests_with(
        tcp,
        channel,
        provider,
        vault_id,
        peer.client_id,
        shared.tickets.limits(),
    )
    .await;
    shared.peers.fetch_sub(1, Ordering::Relaxed);
    let _ = events.send(Event::PeerGone { vault_id });
}

type Admitted = (
    Vec<VaultView>,
    usize,
    session::DeviceCert,
    p2p_core::Channel,
);

async fn admit<P: Provider>(
    tcp: &mut TcpStream,
    provider: &Arc<P>,
    cookies: &CookieSecret,
    load: Load,
    shared: &Shared,
) -> Option<Admitted> {
    let first = first_message(tcp).await.ok()?;
    let fresh = shared.replay.lock().ok()?.fresh(&first);
    if !fresh {
        return None;
    }
    let views = {
        let provider = Arc::clone(provider);
        tokio::task::spawn_blocking(move || provider.views())
            .await
            .ok()?
    };
    let (index, peer, channel) = authenticate(tcp, &views, cookies, load, first).await.ok()?;
    Some((views, index, peer, channel))
}

/// Addresses other devices might reach this node at, best first: the
/// interface the system would use to go out, then the loopback. No packet is
/// sent; connecting a UDP socket only picks a route.
#[must_use]
pub fn reachable_hints(port: u16) -> Vec<String> {
    let mut hints: Vec<String> = Vec::new();
    for probe in ["192.0.2.1:9", "8.8.8.8:80"] {
        let address = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| socket.connect(probe).and_then(|()| socket.local_addr()))
            .ok()
            .map(|local| local.ip())
            .filter(|ip| !ip.is_unspecified() && !ip.is_loopback());
        if let Some(ip) = address {
            let hint = format!("{ip}:{port}");
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
    }
    hints.push(format!("127.0.0.1:{port}"));
    hints
}
