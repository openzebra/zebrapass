//! What a relay does with the first request on a connection: hold a slot,
//! connect to one, or take a pending connection.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2p_core::relay_pow_ok;
use syncwire::{Challenge, Claim, RelaySide, RelayType, Reserved};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::relay::{ConnectionGuard, Ctl, Pending, Reservation, State, Turned};
use crate::relay_splice::splice;
use crate::relay_wire::{receive, send};

/// Every refusal takes at least this long, so that what was refused for
/// cannot be told by how fast the answer came.
const REFUSAL_FLOOR: Duration = Duration::from_millis(50);

/// A request that passed the first frame, with what it needs to be judged.
pub struct Request {
    pub stream: TcpStream,
    pub ip: IpAddr,
    pub guard: ConnectionGuard,
    pub challenge: Challenge,
    pub payload: Vec<u8>,
}

impl Request {
    /// The claim, when it parses and solves the puzzle of this connection.
    fn claim(&self) -> Option<Claim> {
        let claim = Claim::try_from(&self.payload[..]).ok()?;
        relay_pow_ok(
            &self.challenge.salt,
            &claim.id,
            claim.nonce,
            self.challenge.difficulty,
        )
        .then_some(claim)
    }
}

/// Answer `turned` after the floor and end the connection.
async fn turn_away(state: &State, mut stream: TcpStream, turned: Turned, began: Instant) {
    let kind = state.turn(&turned);
    sleep(REFUSAL_FLOOR.saturating_sub(began.elapsed())).await;
    let _ = send(&mut stream, RelaySide::Relay, kind, &[]).await;
}

/// Hold a slot for the member and tell it when someone asks for it.
pub async fn reserve(state: &Arc<State>, request: Request) {
    let began = Instant::now();
    if let Err(turned) = state.may_reserve(request.ip) {
        return turn_away(state, request.stream, turned, began).await;
    }
    let ip = request.ip;
    let Some(claim) = request.claim() else {
        state.release_reservation(ip);
        return turn_away(state, request.stream, Turned::Refused, began).await;
    };
    let (control, inbox) = mpsc::channel::<Ctl>(8);
    let active = Arc::default();
    let taken = state.tables.lock().is_ok_and(|mut tables| {
        let free = !tables.reservations.contains_key(&claim.id);
        if free {
            tables.reservations.insert(
                claim.id,
                Reservation {
                    control: control.clone(),
                    active,
                },
            );
        }
        free
    });
    if !taken {
        state.release_reservation(ip);
        return turn_away(state, request.stream, Turned::Refused, began).await;
    }
    let limits = state.limits;
    let granted = Reserved {
        ttl_s: u32::try_from(limits.reservation_ttl.as_secs()).unwrap_or(u32::MAX),
        max_splices: u8::try_from(limits.splices_per_slot).unwrap_or(u8::MAX),
        splice_mib: u16::try_from(limits.splice_bytes.div_ceil(1 << 20)).unwrap_or(u16::MAX),
    };
    let Request {
        mut stream, guard, ..
    } = request;
    if send(
        &mut stream,
        RelaySide::Relay,
        RelayType::Reserved,
        &granted.encode(),
    )
    .await
    .is_ok()
    {
        hold(state, stream, control, inbox).await;
    }
    if let Ok(mut tables) = state.tables.lock() {
        tables.reservations.remove(&claim.id);
    }
    state.release_reservation(ip);
    drop(guard);
}

/// The control connection of a slot: keepalives in, offers out.
async fn hold(
    state: &State,
    stream: TcpStream,
    control: mpsc::Sender<Ctl>,
    mut inbox: mpsc::Receiver<Ctl>,
) {
    let ttl = state.limits.reservation_ttl;
    let (mut read, mut write): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) =
        tokio::io::split(stream);
    let reader = tokio::spawn(async move {
        while let Ok((ty, payload)) = receive(&mut read, RelaySide::Client, ttl).await {
            let (RelayType::Ping, Ok(syncwire::Ping(ping))) =
                (ty, syncwire::Ping::try_from(&payload[..]))
            else {
                break;
            };
            if control.send(Ctl::Ping(ping)).await.is_err() {
                return;
            }
        }
        let _ = control.send(Ctl::Closed).await;
    });
    while let Ok(Some(message)) = timeout(ttl, inbox.recv()).await {
        let sent = match message {
            Ctl::Ping(token) => {
                send(
                    &mut write,
                    RelaySide::Relay,
                    RelayType::Pong,
                    &token.to_be_bytes(),
                )
                .await
            }
            Ctl::Incoming(conn_id) => {
                send(&mut write, RelaySide::Relay, RelayType::Incoming, &conn_id).await
            }
            Ctl::Closed => break,
        };
        if sent.is_err() {
            break;
        }
    }
    reader.abort();
}

/// Park the dialer until the member takes it, and ask the member to.
pub async fn connect(state: &Arc<State>, request: Request) {
    let began = Instant::now();
    if !state.may_connect(request.ip) {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    }
    let Some(claim) = request.claim() else {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    };
    let found = state.tables.lock().ok().and_then(|tables| {
        tables
            .reservations
            .get(&claim.id)
            .map(|held| (held.control.clone(), Arc::clone(&held.active)))
    });
    let Some((control, active)) = found else {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    };
    if active.load(Ordering::Relaxed) >= state.limits.splices_per_slot {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    }
    let Ok(permit) = Arc::clone(&state.splices).try_acquire_owned() else {
        return turn_away(state, request.stream, Turned::Busy, began).await;
    };
    let Ok(conn_id) = p2p_core::relay_random() else {
        return;
    };
    active.fetch_add(1, Ordering::Relaxed);
    let Request { stream, guard, .. } = request;
    let parked = Pending {
        client: stream,
        created: Instant::now(),
        permit,
        active: Arc::clone(&active),
        guard,
    };
    let inserted = state
        .tables
        .lock()
        .map(|mut tables| tables.pending.insert(conn_id, parked))
        .is_ok();
    if !inserted || control.try_send(Ctl::Incoming(conn_id)).is_err() {
        if let Ok(mut tables) = state.tables.lock() {
            tables.pending.remove(&conn_id);
        }
        active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Join the member that took a pending connection to the one waiting.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guards and the permit live exactly as long as the splice"
)]
pub async fn accept(state: &Arc<State>, request: Request) {
    let began = Instant::now();
    let Some(claim) = request.claim() else {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    };
    let parked = state
        .tables
        .lock()
        .ok()
        .and_then(|mut tables| tables.pending.remove(&claim.id));
    let Some(parked) = parked else {
        return turn_away(state, request.stream, Turned::Refused, began).await;
    };
    let Request { stream, guard, .. } = request;
    let Pending {
        client,
        permit,
        active,
        guard: client_guard,
        ..
    } = parked;
    let mut member = stream;
    let mut dialer = client;
    let both = send(&mut member, RelaySide::Relay, RelayType::Splice, &[])
        .await
        .is_ok()
        && send(&mut dialer, RelaySide::Relay, RelayType::Splice, &[])
            .await
            .is_ok();
    if both {
        state.spliced.fetch_add(1, Ordering::Relaxed);
        splice(state, dialer, member).await;
    } else {
        let _ = dialer.shutdown().await;
    }
    active.fetch_sub(1, Ordering::Relaxed);
    drop((permit, guard, client_guard));
}

/// Drop pending connections nobody took, telling the dialers no.
pub async fn janitor(state: Arc<State>) {
    loop {
        sleep(Duration::from_secs(1)).await;
        let limit = state.limits.pending_timeout;
        let expired: Vec<Pending> = state
            .tables
            .lock()
            .map(|mut tables| {
                let old: Vec<[u8; 16]> = tables
                    .pending
                    .iter()
                    .filter(|(_, parked)| parked.created.elapsed() >= limit)
                    .map(|(id, _)| *id)
                    .collect();
                old.iter()
                    .filter_map(|id| tables.pending.remove(id))
                    .collect()
            })
            .unwrap_or_default();
        for parked in expired {
            parked.active.fetch_sub(1, Ordering::Relaxed);
            let kind = state.turn(&Turned::Refused);
            let mut client = parked.client;
            let _ = send(&mut client, RelaySide::Relay, kind, &[]).await;
        }
    }
}
