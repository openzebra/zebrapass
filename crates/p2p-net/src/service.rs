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
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use crate::client::FetchError;
use crate::client_calls::fetch;
use crate::io::now_ms;
use crate::limits::{HandshakeSlot, Limits, Tickets};
use crate::server::{authenticate, first_message, serve_requests_with};
use crate::view::{Provider, VaultView};

/// Handshakes in flight before new connections are dropped unanswered.
pub const MAX_HANDSHAKES: usize = 32;

/// In-flight handshakes up to which no puzzle is asked.
const FREE_HANDSHAKES: usize = 6;

/// Connections that arrive through a relay, handshakes and sessions together.
pub const MAX_RELAYED: usize = 16;

/// Hellos remembered to refuse a replay, and for how long.
/// Threads for work that touches the disk. Well under the peers times streams
/// a node admits, so an authenticated flood cannot starve new handshakes of
/// the threads they need.
const MAX_BLOCKING: usize = 128;
const REPLAY_CAPACITY: usize = 4096;
const REPLAY_WINDOW: Duration = Duration::from_secs(120);

/// How long a whole handshake may take, however it is paced.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

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
    /// A check-in with another device of this account brought back the sealed
    /// record frames this device lacks (possibly none), from `address`. The
    /// receiver applies them to its own open vault.
    PersonalPulled {
        address: String,
        frames: Vec<Vec<u8>>,
    },
    /// A member reported the address it sees this device at. The port is
    /// that of the connection this device made, not one it listens on.
    Observed(SocketAddr),
    /// A beacon from another device of this account named an address to try.
    /// Nothing has been dialed: it is only where that device says it listens.
    Discovered {
        address: SocketAddr,
        vaults: Vec<[u8; 16]>,
        /// Relay slots it holds, each already past the address rules.
        relays: Vec<syncwire::RelayHint>,
    },
    /// This node holds a slot on a relay: members can reach it at `hint`.
    /// Publish it with the node's other addresses.
    Relayed(syncwire::RelayHint),
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
    pub(crate) handshakes: AtomicUsize,
    pub(crate) relayed: AtomicUsize,
    pub(crate) tickets: Arc<Tickets>,
    listening: Mutex<Option<SocketAddr>>,
    /// The relay slots this node holds now, to announce.
    pub relay_hints: Mutex<Vec<syncwire::RelayHint>>,
    replay: Mutex<Replay>,
}

#[derive(Default)]
struct Replay {
    order: VecDeque<(Instant, [u8; 32])>,
    seen: HashSet<[u8; 32]>,
}

impl Replay {
    /// Whether the hello with this id has not been seen in the window.
    fn unseen(&self, key: &[u8; 32]) -> bool {
        !self.seen.contains(key)
    }

    /// Whether the hello with this id is new, remembering it if so. Entries
    /// leave only when they expire: when the cache is full of live ones the
    /// hello is refused, so flooding never frees a slot for a replay.
    fn fresh(&mut self, key: [u8; 32]) -> bool {
        let now = Instant::now();
        while let Some((at, old)) = self.order.front().copied() {
            if now.duration_since(at) <= REPLAY_WINDOW {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&old);
        }
        if self.order.len() >= REPLAY_CAPACITY || !self.seen.insert(key) {
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
            .max_blocking_threads(MAX_BLOCKING)
            .thread_name("zebrapass-p2p")
            .enable_all()
            .build()?;
        let (sender, events) = channel();
        let shared = Arc::new(Shared {
            peers: AtomicUsize::new(0),
            fetching: AtomicUsize::new(0),
            handshakes: AtomicUsize::new(0),
            relayed: AtomicUsize::new(0),
            tickets: Tickets::new(limits),
            listening: Mutex::new(None),
            relay_hints: Mutex::new(Vec::new()),
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
                    match fetch(&view, hint).await {
                        Ok(fetched) => {
                            outcome = Some(Event::Fetched {
                                vault_id,
                                log: fetched.log,
                                snapshot: fetched.snapshot,
                                rekey: fetched.rekey,
                            });
                            break 'attempts;
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

pub async fn connection<P: Provider>(
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
        &shared.tickets,
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
    let id = p2p_core::Responder::first_message_id(&first).ok()?;
    if !shared.replay.lock().ok()?.unseen(&id) {
        return None;
    }
    let views = {
        let provider = Arc::clone(provider);
        tokio::task::spawn_blocking(move || provider.views())
            .await
            .ok()?
    };
    // Only a hello that passes a vault's gate is remembered, so a stranger
    // cannot fill the cache.
    let locals: Vec<_> = views.iter().map(VaultView::local).collect();
    p2p_core::Responder::route(&locals, &first, now_ms()).ok()?;
    if !shared.replay.lock().ok()?.fresh(id) {
        return None;
    }
    let (index, peer, channel) = authenticate(tcp, &views, cookies, load, first).await.ok()?;
    Some((views, index, peer, channel))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests may unwrap")]
mod tests {
    use super::*;

    #[test]
    fn a_replayed_hello_is_refused() {
        let mut replay = Replay::default();
        assert!(replay.unseen(&[1; 32]));
        assert!(replay.fresh([1; 32]));
        assert!(!replay.unseen(&[1; 32]));
        assert!(!replay.fresh([1; 32]));
    }

    #[test]
    fn a_full_cache_refuses_new_hellos_and_never_forgets_live_ones() {
        let mut replay = Replay::default();
        for n in 0..REPLAY_CAPACITY {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
            assert!(replay.fresh(key));
        }
        assert!(!replay.fresh([0xFF; 32]));
        assert!(
            !replay.fresh([0; 32]),
            "the oldest live entry is still held"
        );
    }

    #[test]
    fn expired_entries_free_their_place() {
        let mut replay = Replay::default();
        let old = Instant::now()
            .checked_sub(REPLAY_WINDOW + Duration::from_secs(1))
            .unwrap();
        replay.order.push_back((old, [7; 32]));
        replay.seen.insert([7; 32]);
        assert!(replay.fresh([8; 32]));
        assert!(replay.unseen(&[7; 32]));
    }
}
