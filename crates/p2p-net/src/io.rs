//! Bytes on the wire: length-prefixed handshake messages, and the bridge that
//! carries an HTTP/2 connection through the encrypted channel.
//!
//! After the handshake, plaintext written by `h2` into one end of an
//! in-memory pipe is sealed message by message and sent over TCP; messages
//! read from TCP are opened and written into the pipe. `h2` never sees
//! anything but plaintext, and TCP never sees anything but sealed frames.

use std::time::Duration;

use anyhow::{anyhow, Result};
use p2p_core::{Channel, MAX_PLAINTEXT, OVERHEAD};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// How long one handshake message may take to arrive.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Plaintext sealed per message.
const CHUNK: usize = 16 * 1024;

/// Buffer between `h2` and the sealer.
const PIPE: usize = 256 * 1024;

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

async fn seal_outbound(
    mut pipe: ReadHalf<DuplexStream>,
    mut tcp: OwnedWriteHalf,
    mut send: p2p_core::SendHalf,
) {
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        let n = match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let Some(plain) = buf.get(..n) else { break };
        let Ok(wire) = send.seal(plain) else { break };
        let Ok(len) = u32::try_from(wire.len()) else {
            break;
        };
        if tcp.write_all(&len.to_be_bytes()).await.is_err() || tcp.write_all(&wire).await.is_err() {
            break;
        }
    }
    let _ = tcp.shutdown().await;
}

async fn open_inbound(
    mut tcp: OwnedReadHalf,
    mut pipe: WriteHalf<DuplexStream>,
    mut recv: p2p_core::RecvHalf,
) {
    loop {
        let mut header = [0u8; 4];
        if tcp.read_exact(&mut header).await.is_err() {
            break;
        }
        let Ok(len) = usize::try_from(u32::from_be_bytes(header)) else {
            break;
        };
        if len > MAX_PLAINTEXT + OVERHEAD {
            break;
        }
        let mut body = vec![0u8; len];
        if tcp.read_exact(&mut body).await.is_err() {
            break;
        }
        let Ok(plain) = recv.open(&body) else { break };
        if pipe.write_all(plain.expose()).await.is_err() {
            break;
        }
    }
    let _ = pipe.shutdown().await;
}

/// Carry an HTTP/2 connection over `channel`: the returned stream is what
/// `h2` reads and writes. Dropping it ends both directions.
#[must_use]
pub fn bridge(tcp: TcpStream, channel: Channel) -> DuplexStream {
    let (app, net) = duplex(PIPE);
    let (net_read, net_write) = split(net);
    let (tcp_read, tcp_write) = tcp.into_split();
    let (send, recv) = channel.into_halves();
    tokio::spawn(seal_outbound(net_read, tcp_write, send));
    tokio::spawn(open_inbound(tcp_read, net_write, recv));
    app
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
