//! Talking to a peer: connect, handshake as the initiator, then ask.

use std::fmt;

use std::collections::VecDeque;
use std::time::Duration;

use p2p_core::suite::{KIND_CHALLENGE, MAX_HANDSHAKE_MSG};
use p2p_core::{Dispatcher, Initiator, Reply, KIND_OFFSET};
use session::DeviceCert;
use syncwire::limits::PIPELINE_DEPTH;
use syncwire::{Direction, MsgType};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::io::{mux, now_ms, read_msg, write_msg, MuxReader, MuxWriter, HANDSHAKE_TIMEOUT};
use crate::view::VaultView;

/// How long a peer may take to answer one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// The member log, each entry's wire bytes concatenated.
    pub log: Vec<u8>,
    /// The vault file with its attestations.
    pub snapshot: Vec<u8>,
    /// The peer's seed and epoch, when it offers them.
    pub rekey: Option<Zeroizing<Vec<u8>>>,
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

/// An open, authenticated connection to one peer.
pub struct Conn {
    reader: MuxReader,
    writer: MuxWriter,
    dispatcher: Dispatcher,
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
        let (reader, writer) =
            mux(tcp, established.channel, Direction::Response).map_err(|_| FetchError::Failed)?;
        Ok(Self {
            reader,
            writer,
            dispatcher: Dispatcher::new(
                u64::try_from(REQUEST_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            ),
            first: true,
            peer: established.peer,
        })
    }

    /// Send `requests`, keeping up to [`PIPELINE_DEPTH`] open, and hand each
    /// reply to `sink` in the order the requests were made.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a broken connection or protocol, a peer
    /// that is too slow, or whatever `sink` returns.
    pub async fn pipeline(
        &mut self,
        mut requests: impl Iterator<Item = (MsgType, Vec<u8>)> + Send,
        mut sink: impl FnMut(Reply) -> Outcome<()> + Send,
    ) -> Outcome<()> {
        // A transport error on the first request of a connection means the
        // server closed on us right after the handshake: a refusal.
        let transport = if self.first {
            FetchError::Refused
        } else {
            FetchError::Failed
        };
        self.first = false;
        let mut order = VecDeque::with_capacity(PIPELINE_DEPTH);
        let mut arrived = Vec::with_capacity(PIPELINE_DEPTH);
        let mut next = requests.next();
        loop {
            while let Some((ty, payload)) = next.take() {
                let sent = self
                    .dispatcher
                    .request(ty, payload.len(), now_ms())
                    .map_err(|_| FetchError::Failed)?;
                let Some(header) = sent else {
                    next = Some((ty, payload));
                    break;
                };
                self.writer
                    .send(&header, &payload)
                    .await
                    .map_err(|_| transport)?;
                order.push_back(header.req_id);
                next = requests.next();
            }
            if order.is_empty() {
                return Ok(());
            }
            let message = timeout(REQUEST_TIMEOUT, self.reader.next())
                .await
                .map_err(|_| FetchError::Failed)?
                .map_err(|_| transport)?;
            let done = self
                .dispatcher
                .on_message(message)
                .map_err(|_| FetchError::Failed)?;
            arrived.push((done.req_id, done.reply));
            while let Some(front) = order.front().copied() {
                let Some(at) = arrived.iter().position(|(id, _)| *id == front) else {
                    break;
                };
                let (_, reply) = arrived.swap_remove(at);
                order.pop_front();
                sink(reply)?;
            }
            if self.dispatcher.expired(now_ms()).is_some() {
                return Err(FetchError::Failed);
            }
        }
    }

    /// One request and its reply.
    ///
    /// # Errors
    ///
    /// As [`Conn::pipeline`].
    pub async fn call(&mut self, ty: MsgType, payload: Vec<u8>) -> Outcome<Reply> {
        let mut answer = None;
        self.pipeline(std::iter::once((ty, payload)), |reply| {
            answer = Some(reply);
            Ok(())
        })
        .await?;
        answer.ok_or(FetchError::Failed)
    }
}
