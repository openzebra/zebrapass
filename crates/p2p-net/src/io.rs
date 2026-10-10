//! Bytes on the wire: length-prefixed handshake messages, and the halves
//! that carry protocol messages through the encrypted channel.
//!
//! After the handshake, every protocol message is cut into pieces of at most
//! one channel message, sealed, and sent over TCP with a `u32` length in
//! front; the reader opens each piece and rebuilds messages from the plain
//! bytes. TCP never sees anything but sealed frames.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{anyhow, Result};
use p2p_core::{Channel, Message, Reassembler, RecvHalf, SendHalf, MAX_PLAINTEXT, OVERHEAD};
use syncwire::{Direction, Header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// How long one handshake message may take to arrive.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn wire_error() -> anyhow::Error {
    anyhow!("connection error")
}

/// Send one handshake message: `u32` big-endian length, then the bytes.
///
/// # Errors
///
/// `connection error` for a write failure or timeout.
pub async fn write_msg(tcp: &mut TcpStream, message: &[u8]) -> Result<()> {
    let len = u32::try_from(message.len()).map_err(|_| wire_error())?;
    timeout(HANDSHAKE_TIMEOUT, async {
        tcp.write_all(&len.to_be_bytes()).await?;
        tcp.write_all(message).await?;
        tcp.flush().await
    })
    .await
    .map_err(|_| wire_error())?
    .map_err(|_| wire_error())
}

/// Read one handshake message of at most `max` bytes. The length is checked
/// before anything is allocated.
///
/// # Errors
///
/// `connection error` for a read failure, a timeout or a length over `max`.
pub async fn read_msg(tcp: &mut TcpStream, max: usize) -> Result<Vec<u8>> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header)
            .await
            .map_err(|_| wire_error())?;
        let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| wire_error())?;
        if len > max {
            return Err(wire_error());
        }
        let mut body = vec![0u8; len];
        tcp.read_exact(&mut body).await.map_err(|_| wire_error())?;
        Ok(body)
    })
    .await
    .map_err(|_| wire_error())?
}

/// Reads sealed messages from the peer and rebuilds protocol messages.
pub struct MuxReader {
    tcp: OwnedReadHalf,
    recv: RecvHalf,
    reassembler: Reassembler,
    ready: VecDeque<Message>,
}

/// Seals protocol messages and writes them to the peer.
pub struct MuxWriter {
    tcp: OwnedWriteHalf,
    send: SendHalf,
}

/// Split an established connection into its two message halves. `incoming`
/// is the direction of the messages the peer sends.
///
/// # Errors
///
/// `connection error` when the socket refuses its options.
pub fn mux(
    tcp: TcpStream,
    channel: Channel,
    incoming: Direction,
) -> Result<(MuxReader, MuxWriter)> {
    tcp.set_nodelay(true).map_err(|_| wire_error())?;
    let (tcp_read, tcp_write) = tcp.into_split();
    let (send, recv) = channel.into_halves();
    Ok((
        MuxReader {
            tcp: tcp_read,
            recv,
            reassembler: Reassembler::new(incoming),
            ready: VecDeque::new(),
        },
        MuxWriter {
            tcp: tcp_write,
            send,
        },
    ))
}

impl MuxReader {
    /// The next complete message.
    ///
    /// # Errors
    ///
    /// `connection error` when the peer closes, a sealed message does not
    /// open, or a header breaks the protocol.
    pub async fn next(&mut self) -> Result<Message> {
        loop {
            if let Some(message) = self.ready.pop_front() {
                return Ok(message);
            }
            let mut header = [0u8; 4];
            self.tcp
                .read_exact(&mut header)
                .await
                .map_err(|_| wire_error())?;
            let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| wire_error())?;
            if len > MAX_PLAINTEXT + OVERHEAD {
                return Err(wire_error());
            }
            let mut body = vec![0u8; len];
            self.tcp
                .read_exact(&mut body)
                .await
                .map_err(|_| wire_error())?;
            let plain = self.recv.open(&body).map_err(|_| wire_error())?;
            let mut out = Vec::new();
            self.reassembler.feed(plain.expose(), &mut out)?;
            self.ready.extend(out);
        }
    }
}

impl MuxWriter {
    /// Send one message, sealed in pieces of at most [`MAX_PLAINTEXT`].
    ///
    /// # Errors
    ///
    /// `connection error` for a write failure or an exhausted channel.
    pub async fn send(&mut self, header: &Header, payload: &[u8]) -> Result<()> {
        let head = header.encode();
        let lead_len = payload.len().min(MAX_PLAINTEXT - head.len());
        let (lead, rest) = payload.split_at_checked(lead_len).ok_or_else(wire_error)?;
        let mut first = Zeroizing::new(Vec::with_capacity(head.len() + lead.len()));
        first.extend_from_slice(&head);
        first.extend_from_slice(lead);
        self.write_sealed(&first).await?;
        for piece in rest.chunks(MAX_PLAINTEXT) {
            self.write_sealed(piece).await?;
        }
        self.tcp.flush().await.map_err(|_| wire_error())
    }

    async fn write_sealed(&mut self, plain: &[u8]) -> Result<()> {
        let wire = self.send.seal(plain).map_err(|_| wire_error())?;
        let len = u32::try_from(wire.len()).map_err(|_| wire_error())?;
        self.tcp
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|_| wire_error())?;
        self.tcp.write_all(&wire).await.map_err(|_| wire_error())
    }
}

/// Unix time in milliseconds.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
