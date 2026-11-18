//! RFC 6455 WebSocket upgrade and binary framing helpers.
//!
//! `sha1` is used exclusively for the RFC 6455 §1.3 `Sec-WebSocket-Accept`
//! handshake token with constant-time comparison.

use std::time::Duration;

use anyhow::anyhow;
use secret::ct_eq;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::b64::encode_standard;
use crate::http_wire::{header_value, io_timeout, read_http_response};
use crate::limits::MAX_WS_FRAME;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// RFC 6455 opcodes handled by the sync transport.
pub const WS_OP_CONT: u8 = 0x0;
pub const WS_OP_TEXT: u8 = 0x1;
pub const WS_OP_BIN: u8 = 0x2;
pub const WS_OP_CLOSE: u8 = 0x8;
pub const WS_OP_PING: u8 = 0x9;
pub const WS_OP_PONG: u8 = 0xA;

/// Compute RFC 6455 `Sec-WebSocket-Accept` response token using SHA-1 as
/// mandated by RFC 6455 §1.3 (never used for keys or content integrity).
#[must_use]
pub fn ws_accept_token(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.trim().as_bytes());
    hasher.update(WS_GUID);
    let digest = hasher.finalize();
    encode_standard(&digest)
}

/// Perform client-side RFC 6455 WebSocket upgrade over `stream`.
///
/// # Errors
///
/// Entropy failure, non-101 response, invalid upgrade headers, or mismatched
/// `Sec-WebSocket-Accept`.
pub async fn ws_client_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    path: &str,
    host: &str,
) -> anyhow::Result<()> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow!("os entropy failed"))?;
    let key_b64 = encode_standard(&nonce);
    let expected_accept = ws_accept_token(&key_b64);

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    timeout(io_timeout(), async {
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow!("WebSocket upgrade write timed out"))??;

    let resp = read_http_response(stream).await?;
    if resp.status != 101 {
        return Err(anyhow!("WebSocket upgrade rejected (HTTP {})", resp.status));
    }
    let upgrade =
        header_value(&resp.headers, "upgrade").ok_or_else(|| anyhow!("missing Upgrade header"))?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(anyhow!("invalid Upgrade header"));
    }
    let accept = header_value(&resp.headers, "sec-websocket-accept")
        .ok_or_else(|| anyhow!("missing Sec-WebSocket-Accept"))?;
    if !ct_eq(accept.as_bytes(), expected_accept.as_bytes()) {
        return Err(anyhow!("Sec-WebSocket-Accept mismatch"));
    }
    Ok(())
}

/// Write one RFC 6455 frame (client side masks with OS CSPRNG bytes).
///
/// # Errors
///
/// Frame payload over [`MAX_WS_FRAME`], OS RNG failure, or write timeout.
pub async fn ws_write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
    mask_payload: bool,
) -> anyhow::Result<()> {
    if payload.len() > MAX_WS_FRAME {
        return Err(anyhow!("WebSocket frame exceeds limit"));
    }
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push(0x80 | (opcode & 0x0F));
    let mask_bit: u8 = if mask_payload { 0x80 } else { 0x00 };
    if payload.len() < 126 {
        let len_u8 = u8::try_from(payload.len()).map_err(|_| anyhow!("WS length overflow"))?;
        out.push(mask_bit | len_u8);
    } else {
        let len_u16 = u16::try_from(payload.len()).map_err(|_| anyhow!("WS length overflow"))?;
        out.push(mask_bit | 0x7E);
        out.extend_from_slice(&len_u16.to_be_bytes());
    }
    if mask_payload {
        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask).map_err(|_| anyhow!("os entropy failed"))?;
        out.extend_from_slice(&mask);
        for (idx, &b) in payload.iter().enumerate() {
            let m = *mask.get(idx % 4).unwrap_or(&0);
            out.push(b ^ m);
        }
    } else {
        out.extend_from_slice(payload);
    }
    timeout(io_timeout(), async {
        writer.write_all(&out).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("WebSocket frame write timed out"))??;
    Ok(())
}

/// Read one complete RFC 6455 frame (automatically rejects oversized or
/// improperly masked frames per RFC 6455 §5.1).
///
/// # Errors
///
/// Protocol violation, frame over [`MAX_WS_FRAME`], EOF, or read timeout.
pub async fn ws_read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    expect_masked: bool,
    wait_timeout: Option<Duration>,
) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    match wait_timeout {
        Some(dur) => timeout(dur, reader.read_exact(&mut hdr))
            .await
            .map_err(|_| anyhow!("WebSocket frame read timed out"))??,
        None => reader.read_exact(&mut hdr).await?,
    };
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    if !fin || opcode == WS_OP_CONT {
        return Err(anyhow!("fragmented WebSocket frames are not permitted"));
    }
    let masked = (hdr[1] & 0x80) != 0;
    if masked != expect_masked {
        return Err(anyhow!("unexpected WebSocket mask bit"));
    }
    let raw_len = hdr[1] & 0x7F;
    let len = match raw_len {
        0..=125 => usize::from(raw_len),
        126 => {
            let mut ext = [0u8; 2];
            timeout(io_timeout(), reader.read_exact(&mut ext))
                .await
                .map_err(|_| anyhow!("WS length read timed out"))??;
            usize::from(u16::from_be_bytes(ext))
        }
        _ => return Err(anyhow!("WebSocket frame exceeds MAX_WS_FRAME")),
    };
    if len > MAX_WS_FRAME {
        return Err(anyhow!("WebSocket frame exceeds MAX_WS_FRAME"));
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        timeout(io_timeout(), reader.read_exact(&mut m))
            .await
            .map_err(|_| anyhow!("WS mask read timed out"))??;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    if len > 0 {
        timeout(io_timeout(), reader.read_exact(&mut payload))
            .await
            .map_err(|_| anyhow!("WS payload read timed out"))??;
    }
    if let Some(m) = mask {
        for (idx, b) in payload.iter_mut().enumerate() {
            *b ^= *m.get(idx % 4).unwrap_or(&0);
        }
    }
    Ok((opcode, payload))
}
