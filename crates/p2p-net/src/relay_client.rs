//! Reaching a member through a relay, and holding a slot on one.
//!
//! Every connection to a relay opens the same way: the magic, the relay's
//! puzzle, a solved claim. What follows depends on the claim: `CONNECT` and
//! `ACCEPT` end in a spliced stream, which is then the plain stream of a
//! direct connection; `RESERVE` stays a control connection.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use p2p_core::relay_pow_solve;
use syncwire::{encode_open, Challenge, Claim, RelayHint, RelaySide, RelayType, Reserved};
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::client::FetchError;
use crate::dialable::{CatalogTarget, Dialing};
use crate::relay_wire::{receive, send, MESSAGE_TIMEOUT};
use crate::ws_relay::connect_ws_stream;

/// How long a relay may take to find the member and join the two.
const SPLICE_WAIT: Duration = Duration::from_secs(25);

async fn claim_on_stream(
    mut stream: TcpStream,
    ty: RelayType,
    id: [u8; 16],
) -> Result<TcpStream, FetchError> {
    stream
        .write_all(&encode_open())
        .await
        .map_err(|_| FetchError::Unreachable)?;
    let (kind, payload) = receive(&mut stream, RelaySide::Relay, MESSAGE_TIMEOUT)
        .await
        .map_err(|_| FetchError::Failed)?;
    if kind != RelayType::Challenge {
        return Err(FetchError::Failed);
    }
    let challenge = Challenge::try_from(&payload[..]).map_err(|_| FetchError::Failed)?;
    let nonce = tokio::task::spawn_blocking(move || {
        relay_pow_solve(&challenge.salt, &id, challenge.difficulty)
    })
    .await
    .ok()
    .flatten()
    .ok_or(FetchError::Failed)?;
    send(
        &mut stream,
        RelaySide::Client,
        ty,
        &Claim { id, nonce }.encode(),
    )
    .await
    .map_err(|_| FetchError::Failed)?;
    Ok(stream)
}

/// Connect to `relay`, answer its puzzle, and make `ty` claim `id`.
async fn claim(relay: SocketAddr, ty: RelayType, id: [u8; 16]) -> Result<TcpStream, FetchError> {
    let stream = timeout(MESSAGE_TIMEOUT, TcpStream::connect(relay))
        .await
        .map_err(|_| FetchError::Unreachable)?
        .map_err(|_| FetchError::Unreachable)?;
    claim_on_stream(stream, ty, id).await
}

async fn claim_ws(
    relay: SocketAddr,
    host: &str,
    ty: RelayType,
    id: [u8; 16],
) -> Result<TcpStream, FetchError> {
    let stream = connect_ws_stream(relay, host).await?;
    claim_on_stream(stream, ty, id).await
}

async fn spliced(mut stream: TcpStream, wait: Duration) -> Result<TcpStream, FetchError> {
    let (kind, _) = receive(&mut stream, RelaySide::Relay, wait)
        .await
        .map_err(|_| FetchError::Failed)?;
    if kind == RelayType::Splice {
        Ok(stream)
    } else {
        Err(FetchError::Failed)
    }
}

/// A connection to the member behind `hint`, through its relay: the stream
/// after the relay has joined the two ends.
///
/// # Errors
///
/// [`FetchError::Unreachable`] when the relay cannot be reached,
/// [`FetchError::Failed`] when it refuses, is busy, or the member does not
/// answer.
pub async fn connect(hint: &RelayHint) -> Result<TcpStream, FetchError> {
    let stream = claim(hint.relay, RelayType::Connect, hint.slot).await?;
    spliced(stream, SPLICE_WAIT).await
}

/// Connect to a WebSocket or hostname-backed catalog relay target, enforcing
/// `dialing.policy` on every resolved socket address.
///
/// # Errors
///
/// As [`connect`].
pub async fn connect_catalog(
    target: &CatalogTarget,
    dialing: &Dialing,
) -> Result<TcpStream, FetchError> {
    let addrs: Vec<SocketAddr> = if let Ok(ip) = target.host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, target.port)]
    } else {
        let host_port = format!("{}:{}", target.host, target.port);
        timeout(MESSAGE_TIMEOUT, lookup_host(host_port))
            .await
            .map_err(|_| FetchError::Unreachable)?
            .map_err(|_| FetchError::Unreachable)?
            .collect()
    };
    let mut last_err = FetchError::Unreachable;
    for addr in addrs {
        if !dialing.policy.allows(&addr, &dialing.trusted) {
            continue;
        }
        let ws_attempt = claim_ws(addr, &target.host, RelayType::Connect, target.slot).await;
        let stream = match ws_attempt {
            Ok(s) => Ok(s),
            Err(_) => claim(addr, RelayType::Connect, target.slot).await,
        };
        match stream {
            Ok(s) => match spliced(s, SPLICE_WAIT).await {
                Ok(joined) => return Ok(joined),
                Err(err) => last_err = err,
            },
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

/// Take the pending connection `conn_id` the relay offered: the stream after
/// the relay has joined it to the member that asked.
///
/// # Errors
///
/// As [`connect`].
pub async fn accept(relay: SocketAddr, conn_id: [u8; 16]) -> Result<TcpStream, FetchError> {
    let stream = claim(relay, RelayType::Accept, conn_id).await?;
    spliced(stream, MESSAGE_TIMEOUT).await
}

/// Take the pending connection `conn_id` over a WebSocket upgrade tunnel,
/// falling back to raw TCP if needed.
///
/// # Errors
///
/// As [`connect`].
pub async fn accept_ws(
    relay: SocketAddr,
    host: &str,
    conn_id: [u8; 16],
) -> Result<TcpStream, FetchError> {
    let stream = match claim_ws(relay, host, RelayType::Accept, conn_id).await {
        Ok(s) => s,
        Err(_) => claim(relay, RelayType::Accept, conn_id).await?,
    };
    spliced(stream, MESSAGE_TIMEOUT).await
}

/// Hold `slot` on `relay`: the control connection and what the relay grants.
///
/// # Errors
///
/// As [`connect`].
pub async fn reserve(
    relay: SocketAddr,
    slot: [u8; 16],
) -> Result<(TcpStream, Reserved), FetchError> {
    let mut stream = claim(relay, RelayType::Reserve, slot).await?;
    let (kind, payload) = receive(&mut stream, RelaySide::Relay, MESSAGE_TIMEOUT)
        .await
        .map_err(|_| FetchError::Failed)?;
    if kind != RelayType::Reserved {
        return Err(FetchError::Failed);
    }
    let granted = Reserved::try_from(&payload[..]).map_err(|_| FetchError::Failed)?;
    Ok((stream, granted))
}

/// Hold `slot` on `relay` over an RFC 6455 WebSocket upgrade tunnel.
///
/// # Errors
///
/// As [`connect`].
pub async fn reserve_ws(
    relay: SocketAddr,
    host: &str,
    slot: [u8; 16],
) -> Result<(TcpStream, Reserved), FetchError> {
    let mut stream = claim_ws(relay, host, RelayType::Reserve, slot).await?;
    let (kind, payload) = receive(&mut stream, RelaySide::Relay, MESSAGE_TIMEOUT)
        .await
        .map_err(|_| FetchError::Failed)?;
    if kind != RelayType::Reserved {
        return Err(FetchError::Failed);
    }
    let granted = Reserved::try_from(&payload[..]).map_err(|_| FetchError::Failed)?;
    Ok((stream, granted))
}
