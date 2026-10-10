//! Reading and writing relay frames on a stream.

use std::time::Duration;

use anyhow::{anyhow, Result};
use syncwire::limits::RELAY_HEADER_LEN;
use syncwire::{RelayHeader, RelaySide, RelayType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// How long a peer may take over one relay message.
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(15);

fn broken() -> anyhow::Error {
    anyhow!("relay connection error")
}

/// Send one frame as `from`.
///
/// # Errors
///
/// A payload over the limit of its type, or a write failure or timeout.
pub async fn send(
    stream: &mut (impl AsyncWrite + Unpin),
    from: RelaySide,
    ty: RelayType,
    payload: &[u8],
) -> Result<()> {
    let header = RelayHeader::new(ty, payload.len(), from)?;
    let mut frame = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(payload);
    timeout(MESSAGE_TIMEOUT, async {
        stream.write_all(&frame).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| broken())?
    .map_err(|_| broken())
}

/// Read one frame sent by `from`, waiting at most `wait` for all of it. The
/// length is checked against the limit of the type before the payload is read.
///
/// # Errors
///
/// An unknown type, one `from` may not send, a length over its limit, a
/// closed stream, or a timeout.
pub async fn receive(
    stream: &mut (impl AsyncRead + Unpin),
    from: RelaySide,
    wait: Duration,
) -> Result<(RelayType, Vec<u8>)> {
    timeout(wait, async {
        let mut head = [0u8; RELAY_HEADER_LEN];
        stream.read_exact(&mut head).await.map_err(|_| broken())?;
        let header = RelayHeader::decode(&head, from)?;
        let mut payload = vec![0u8; usize::from(header.len)];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|_| broken())?;
        Ok((header.ty, payload))
    })
    .await
    .map_err(|_| broken())?
}
