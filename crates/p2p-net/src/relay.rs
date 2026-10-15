//! A relay: it joins two members that cannot dial each other and copies
//! their bytes. It is not a member and knows no vault: it cannot read, alter
//! or forge what it carries (the members' handshake runs end to end through
//! it), and it keeps nothing at rest. Everything here is in memory and lives
//! as long as a connection does. Abuse is met with limits, not with
//! identity, because a relay has none to check.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use syncwire::limits::RELAY_OPEN_LEN;
use syncwire::{decode_open, Challenge, RelaySide, RelayType};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::relay_wire::{receive, send, MESSAGE_TIMEOUT};

/// What a relay holds, allows and asks for. Every number is the operator's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    /// Open connections of every kind.
    pub max_connections: usize,
    /// Open connections from one address.
    pub per_address_connections: usize,
    /// Slots held at once.
    pub max_reservations: usize,
    /// Slots one address may hold.
    pub per_address_reservations: usize,
    /// How long a slot lasts without a keepalive.
    pub reservation_ttl: Duration,
    /// Splices running at once on one slot.
    pub splices_per_slot: usize,
    /// Splices running at once.
    pub max_splices: usize,
    /// Bytes one splice may carry, both ways together.
    pub splice_bytes: u64,
    /// How long one splice may run.
    pub splice_time: Duration,
    /// How long a splice may be silent.
    pub splice_idle: Duration,
    /// Bytes per second one splice may carry.
    pub splice_rate: u64,
    /// Bytes per second the whole relay may carry.
    pub total_rate: u64,
    /// `CONNECT` requests one address may make a minute.
    pub connects_per_minute: usize,
    /// How long a pending connection waits for the member to take it.
    pub pending_timeout: Duration,
    /// Puzzle difficulty when the relay is quiet.
    pub difficulty_idle: u8,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            per_address_connections: 16,
            max_reservations: 256,
            per_address_reservations: 8,
            reservation_ttl: Duration::from_secs(10 * 60),
            splices_per_slot: 4,
            max_splices: 128,
            splice_bytes: 64 << 20,
            splice_time: Duration::from_secs(15 * 60),
            splice_idle: Duration::from_secs(120),
            splice_rate: 2 << 20,
            total_rate: 32 << 20,
            connects_per_minute: 6,
            pending_timeout: Duration::from_secs(10),
            difficulty_idle: 8,
        }
    }
}

/// Counters only: nothing that names a slot or an address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayStats {
    /// Slots held now.
    pub reservations: usize,
    /// Splices running now.
    pub splices: usize,
    /// Connections open now.
    pub connections: usize,
    /// Splices ever made.
    pub spliced: u64,
    /// Requests ever turned away.
    pub refused: u64,
    /// Requests ever answered busy.
    pub busy: u64,
}

pub enum Ctl {
    Incoming([u8; 16]),
    Ping(u64),
    Closed,
}

pub struct Reservation {
    pub control: mpsc::Sender<Ctl>,
    pub active: Arc<AtomicUsize>,
}

pub struct Pending {
    pub client: TcpStream,
    pub created: Instant,
    pub permit: OwnedSemaphorePermit,
    pub active: Arc<AtomicUsize>,
    pub guard: ConnectionGuard,
}

#[derive(Default)]
struct Counts {
    connections: usize,
    reservations: usize,
    connects: VecDeque<Instant>,
}

#[derive(Default)]
pub struct Tables {
    pub reservations: HashMap<[u8; 16], Reservation>,
    pub pending: HashMap<[u8; 16], Pending>,
    per_ip: HashMap<IpAddr, Counts>,
    connections: usize,
}

pub struct State {
    pub limits: RelayLimits,
    pub tables: Mutex<Tables>,
    pub splices: Arc<Semaphore>,
    pub spliced: AtomicU64,
    pub refused: AtomicU64,
    pub busy: AtomicU64,
    next_free: Mutex<Instant>,
    pub tap: Option<Arc<Mutex<Vec<u8>>>>,
}

/// One open connection, released when dropped.
pub struct ConnectionGuard {
    state: Arc<State>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut tables) = self.state.tables.lock() {
            tables.connections = tables.connections.saturating_sub(1);
            if let Some(counts) = tables.per_ip.get_mut(&self.ip) {
                counts.connections = counts.connections.saturating_sub(1);
            }
        }
    }
}

/// Why a request was not taken in.
pub enum Turned {
    Refused,
    Busy,
}

impl State {
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionGuard, Turned> {
        let mut tables = self.tables.lock().map_err(|_| Turned::Busy)?;
        if tables.connections >= self.limits.max_connections {
            return Err(Turned::Busy);
        }
        let counts = tables.per_ip.entry(ip).or_default();
        if counts.connections >= self.limits.per_address_connections {
            return Err(Turned::Refused);
        }
        counts.connections += 1;
        tables.connections += 1;
        drop(tables);
        Ok(ConnectionGuard {
            state: Arc::clone(self),
            ip,
        })
    }

    /// Count a reservation of `ip`, if it may hold another.
    pub fn may_reserve(&self, ip: IpAddr) -> Result<(), Turned> {
        let mut tables = self.tables.lock().map_err(|_| Turned::Busy)?;
        if tables.reservations.len() >= self.limits.max_reservations {
            return Err(Turned::Busy);
        }
        let counts = tables.per_ip.entry(ip).or_default();
        if counts.reservations >= self.limits.per_address_reservations {
            return Err(Turned::Refused);
        }
        counts.reservations += 1;
        drop(tables);
        Ok(())
    }

    pub fn release_reservation(&self, ip: IpAddr) {
        if let Ok(mut tables) = self.tables.lock() {
            if let Some(counts) = tables.per_ip.get_mut(&ip) {
                counts.reservations = counts.reservations.saturating_sub(1);
            }
        }
    }

    /// Count a connect request of `ip` in the last minute, if it may make
    /// another.
    pub fn may_connect(&self, ip: IpAddr) -> bool {
        let Ok(mut tables) = self.tables.lock() else {
            return false;
        };
        let counts = tables.per_ip.entry(ip).or_default();
        let now = Instant::now();
        while counts
            .connects
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(60))
        {
            counts.connects.pop_front();
        }
        if counts.connects.len() >= self.limits.connects_per_minute {
            return false;
        }
        counts.connects.push_back(now);
        true
    }

    /// Puzzle difficulty now: harder the busier the relay is.
    pub fn difficulty(&self) -> u8 {
        let load = self.tables.lock().map_or(0, |tables| tables.connections);
        let extra = u8::try_from(load / 64).unwrap_or(u8::MAX);
        self.limits
            .difficulty_idle
            .saturating_add(extra)
            .min(syncwire::limits::RELAY_MAX_DIFFICULTY)
    }

    /// How long to wait before passing `bytes` on, so that the whole relay
    /// stays under its rate.
    pub fn pace(&self, bytes: usize) -> Duration {
        let rate = self.limits.total_rate.max(1);
        let cost = Duration::from_micros(
            u64::try_from(bytes)
                .unwrap_or(u64::MAX)
                .saturating_mul(1_000_000)
                / rate,
        );
        let Ok(mut next) = self.next_free.lock() else {
            return Duration::ZERO;
        };
        let now = Instant::now();
        let start = (*next).max(now);
        *next = start + cost;
        start.duration_since(now)
    }

    pub fn turn(&self, turned: &Turned) -> RelayType {
        match turned {
            Turned::Refused => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                RelayType::Refused
            }
            Turned::Busy => {
                self.busy.fetch_add(1, Ordering::Relaxed);
                RelayType::Busy
            }
        }
    }
}

/// A running relay.
pub struct Relay {
    runtime: Option<Runtime>,
    state: Arc<State>,
    local: SocketAddr,
}

impl Relay {
    /// Listen on `listen` and join the members that ask.
    ///
    /// # Errors
    ///
    /// The runtime or the listener could not start.
    pub fn start(listen: &str, limits: RelayLimits) -> Result<Self> {
        Self::start_inner(listen, limits, None)
    }

    /// As [`Relay::start`], also keeping a copy of every byte that passes
    /// through a splice in `tap`: for tests of what a relay can see. A real
    /// relay never records.
    ///
    /// # Errors
    ///
    /// The runtime or the listener could not start.
    pub fn start_tapped(
        listen: &str,
        limits: RelayLimits,
        tap: Arc<Mutex<Vec<u8>>>,
    ) -> Result<Self> {
        Self::start_inner(listen, limits, Some(tap))
    }

    fn start_inner(
        listen: &str,
        limits: RelayLimits,
        tap: Option<Arc<Mutex<Vec<u8>>>>,
    ) -> Result<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("zebrapass-relay")
            .enable_all()
            .build()?;
        let listener = runtime.block_on(TcpListener::bind(listen))?;
        let local = listener.local_addr()?;
        let state = Arc::new(State {
            limits,
            tables: Mutex::new(Tables::default()),
            splices: Arc::new(Semaphore::new(limits.max_splices)),
            spliced: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            next_free: Mutex::new(Instant::now()),
            tap,
        });
        runtime.spawn(accept_loop(listener, Arc::clone(&state)));
        runtime.spawn(crate::relay_flow::janitor(Arc::clone(&state)));
        Ok(Self {
            runtime: Some(runtime),
            state,
            local,
        })
    }

    /// Where the relay listens.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the relay is doing, as counters.
    #[must_use]
    pub fn stats(&self) -> RelayStats {
        let (reservations, connections) = self.state.tables.lock().map_or((0, 0), |tables| {
            (tables.reservations.len(), tables.connections)
        });
        RelayStats {
            reservations,
            splices: self.state.limits.max_splices - self.state.splices.available_permits(),
            connections,
            spliced: self.state.spliced.load(Ordering::Relaxed),
            refused: self.state.refused.load(Ordering::Relaxed),
            busy: self.state.busy.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, from)) = listener.accept().await else {
            return;
        };
        tokio::spawn(serve(stream, from, Arc::clone(&state)));
    }
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the connection guard lives exactly as long as the connection"
)]
async fn serve(mut stream: TcpStream, from: SocketAddr, state: Arc<State>) {
    let ip = from.ip().to_canonical();
    let guard = match state.admit(ip) {
        Ok(guard) => guard,
        Err(turned) => {
            // Honest and cheap: no puzzle, no parsing, one small frame.
            let _ = send(&mut stream, RelaySide::Relay, state.turn(&turned), &[]).await;
            return;
        }
    };
    let mut prefix = [0u8; 4];
    if !matches!(
        timeout(MESSAGE_TIMEOUT, stream.read_exact(&mut prefix)).await,
        Ok(Ok(_))
    ) {
        return;
    }
    let mut open = [0u8; RELAY_OPEN_LEN];
    if &prefix == b"GET " {
        let Some(upgraded) = crate::ws_relay::upgrade_after_get(stream).await else {
            return;
        };
        stream = upgraded;
        let opened = timeout(MESSAGE_TIMEOUT, stream.read_exact(&mut open)).await;
        if !matches!(opened, Ok(Ok(_))) || decode_open(&open).is_err() {
            return;
        }
    } else {
        let mut rest = [0u8; 2];
        if !matches!(
            timeout(MESSAGE_TIMEOUT, stream.read_exact(&mut rest)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let [p0, p1, p2, p3] = prefix;
        let [v0, v1] = rest;
        open = [p0, p1, p2, p3, v0, v1];
        if decode_open(&open).is_err() {
            return;
        }
    }
    let Ok(salt) = p2p_core::relay_random() else {
        return;
    };
    let difficulty = state.difficulty();
    let challenge = Challenge {
        salt,
        window: 0,
        difficulty,
    };
    if send(
        &mut stream,
        RelaySide::Relay,
        RelayType::Challenge,
        &challenge.encode(),
    )
    .await
    .is_err()
    {
        return;
    }
    let Ok((ty, payload)) = receive(&mut stream, RelaySide::Client, MESSAGE_TIMEOUT).await else {
        return;
    };
    let request = crate::relay_flow::Request {
        stream,
        ip,
        guard,
        challenge,
        payload,
    };
    match ty {
        RelayType::Reserve => crate::relay_flow::reserve(&state, request).await,
        RelayType::Connect => crate::relay_flow::connect(&state, request).await,
        RelayType::Accept => crate::relay_flow::accept(&state, request).await,
        RelayType::Ping
        | RelayType::Challenge
        | RelayType::Reserved
        | RelayType::Incoming
        | RelayType::Splice
        | RelayType::Pong
        | RelayType::Busy
        | RelayType::Refused => drop(request),
    }
}
