//! Talking to a peer: connect, handshake as the initiator, then ask.

use std::fmt;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use p2p_core::suite::{KIND_CHALLENGE, MAX_HANDSHAKE_MSG};
use p2p_core::{Initiator, KIND_OFFSET};
use session::DeviceCert;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::io::{bridge, now_ms, read_msg, write_msg, HANDSHAKE_TIMEOUT};
use crate::view::VaultView;

const STREAM_WINDOW: u32 = 1 << 20;
const CONNECTION_WINDOW: u32 = 4 << 20;

/// Why a request did not work, as far as the client can tell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchError {
    /// Nobody answered at the address.
    Unreachable,
    /// Someone answered and turned this device away: wrong key, not a
    /// member, revoked, or an answer that failed to verify.
    Refused,
    /// Anything else, including a peer that does not hold the vault.
    Failed,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreachable => "unreachable",
            Self::Refused => "refused",
            Self::Failed => "failed",
        })
    }
}

impl std::error::Error for FetchError {}

type Outcome<T> = Result<T, FetchError>;

/// What a fetch brought back.
#[derive(Debug)]
pub struct Fetched {
    /// The peer's verified certificate.
    pub peer: DeviceCert,
    /// One body per required path, in order.
    pub bodies: Vec<Vec<u8>>,
    /// One entry per optional path: its body, or `None` when the peer does
    /// not have it.
    pub extras: Vec<Option<Vec<u8>>>,
}

async fn handshake(
    view: &VaultView,
    tcp: &mut TcpStream,
) -> Outcome<(Vec<u8>, p2p_core::Established)> {
    let gate_key = view.gate_keys.first().ok_or(FetchError::Failed)?;
    let (initiator, hello) =
        Initiator::start(gate_key, now_ms()).map_err(|_| FetchError::Failed)?;
    write_msg(tcp, &hello)
        .await
        .map_err(|_| FetchError::Unreachable)?;
    let refused = |_| FetchError::Refused;
    let mut reply = read_msg(tcp, MAX_HANDSHAKE_MSG).await.map_err(refused)?;
    if reply.get(KIND_OFFSET) == Some(&KIND_CHALLENGE) {
        let solved = initiator.solve(&reply).map_err(|_| FetchError::Failed)?;
        write_msg(tcp, &solved).await.map_err(refused)?;
        reply = read_msg(tcp, MAX_HANDSHAKE_MSG).await.map_err(refused)?;
    }
    initiator
        .finish(&view.local(), &reply, now_ms())
        .map_err(refused)
}

/// An open, authenticated HTTP/2 connection to one peer.
pub struct Conn {
    sender: h2::client::SendRequest<Bytes>,
    first: bool,
    /// The peer's verified certificate.
    pub peer: DeviceCert,
}

impl Conn {
    /// Connect to `addr` and authenticate for `view`'s vault.
    ///
    /// # Errors
    ///
    /// [`FetchError::Unreachable`] when nobody answers or the address is not
    /// one this device may dial,
    /// [`FetchError::Refused`] when the peer turns this device away or its
    /// answer does not verify, [`FetchError::Failed`] otherwise.
    pub async fn connect(view: &VaultView, addr: &str) -> Outcome<Self> {
        let addr = view.dialing.resolve(addr).ok_or(FetchError::Unreachable)?;
        let mut tcp = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| FetchError::Unreachable)?
            .map_err(|_| FetchError::Unreachable)?;
        let (finish, established) = handshake(view, &mut tcp).await?;
        write_msg(&mut tcp, &finish)
            .await
            .map_err(|_| FetchError::Refused)?;
        let io = bridge(tcp, established.channel);
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(|_| FetchError::Refused)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            sender,
            first: true,
            peer: established.peer,
        })
    }

    async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Outcome<http::Response<h2::RecvStream>> {
        // A transport error on the first request of a connection means the
        // server closed on us right after the handshake: a refusal.
        let transport = if self.first {
            FetchError::Refused
        } else {
            FetchError::Failed
        };
        self.first = false;
        let sender = self.sender.clone().ready().await.map_err(|_| transport)?;
        self.sender = sender;
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .map_err(|_| FetchError::Failed)?;
        let end = body.is_none();
        let (response, mut upload) = self
            .sender
            .send_request(request, end)
            .map_err(|_| transport)?;
        if let Some(data) = body {
            upload
                .send_data(Bytes::from(data), true)
                .map_err(|_| FetchError::Failed)?;
        }
        response.await.map_err(|_| transport)
    }

    /// `GET path`. An `optional` path a peer does not have is `Ok(None)`.
    /// No body may exceed `max_body` bytes.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a non-200 answer (other than a missing
    /// optional path), an oversized body or a broken connection.
    pub async fn get(
        &mut self,
        path: &str,
        max_body: usize,
        optional: bool,
    ) -> Outcome<Option<Vec<u8>>> {
        let response = self.request(Method::GET, path, None).await?;
        if optional && response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() != StatusCode::OK {
            return Err(FetchError::Failed);
        }
        let mut stream = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk.map_err(|_| FetchError::Failed)?;
            stream
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|_| FetchError::Failed)?;
            if body.len().saturating_add(chunk.len()) > max_body {
                return Err(FetchError::Failed);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    /// `POST path` with `body`; returns the status the peer answered.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a broken connection.
    pub async fn post(&mut self, path: &str, body: Vec<u8>) -> Outcome<StatusCode> {
        let response = self.request(Method::POST, path, Some(body)).await?;
        Ok(response.status())
    }
}

/// Connect to `addr`, authenticate for `view`'s vault, and `GET` each path.
/// No body may exceed `max_body` bytes.
///
/// # Errors
///
/// As [`Conn::connect`] and [`Conn::get`].
pub async fn fetch(
    view: &VaultView,
    addr: &str,
    paths: &[&str],
    max_body: usize,
) -> Outcome<Fetched> {
    fetch_paths(view, addr, paths, &[], max_body).await
}

/// As [`fetch`], plus `optional` paths a peer may answer with not found.
///
/// # Errors
///
/// As [`fetch`]; a missing optional path is not an error.
pub async fn fetch_paths(
    view: &VaultView,
    addr: &str,
    paths: &[&str],
    optional: &[&str],
    max_body: usize,
) -> Outcome<Fetched> {
    let mut conn = Conn::connect(view, addr).await?;
    let mut bodies = Vec::with_capacity(paths.len());
    for path in paths {
        bodies.push(
            conn.get(path, max_body, false)
                .await?
                .ok_or(FetchError::Failed)?,
        );
    }
    let mut extras = Vec::with_capacity(optional.len());
    for path in optional {
        extras.push(conn.get(path, max_body, true).await?);
    }
    Ok(Fetched {
        peer: conn.peer,
        bodies,
        extras,
    })
}
