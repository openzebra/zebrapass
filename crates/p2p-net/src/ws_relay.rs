//! WebSocket (RFC 6455) and Nostr envelope transport adapter for relay
//! connections.
//!
//! Upgrades a [`TcpStream`] via HTTP/1.1 `Upgrade: websocket` and bridges
//! framed binary or Nostr event payloads into a local loopback [`TcpStream`]
//! so relay reservations, splices, and the post-quantum `ZPMX` channel run
//! unmodified over port 443/80 WebSocket relays.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::client::FetchError;
use crate::relay_wire::MESSAGE_TIMEOUT;

/// Maximum HTTP/1.1 Upgrade header block accepted from a peer or relay.
const MAX_HTTP_HEADER: usize = 4096;

/// Maximum payload size of a single WebSocket frame accepted before allocation.
const MAX_WS_FRAME: usize = 65_536;

/// Chunk size read from the local stream per WebSocket frame.
const WS_CHUNK_SIZE: usize = 16_384;

/// Standard RFC 6455 §1.3 handshake key and expected accept token.
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// WebSocket binary frame opcode (`FIN | 0x02`).
const OP_BINARY_FIN: u8 = 0x82;

/// WebSocket text frame opcode (`FIN | 0x01`), used for Nostr JSON envelopes.
const OP_TEXT_FIN: u8 = 0x81;

/// WebSocket ping frame opcode (`FIN | 0x09`).
const OP_PING_FIN: u8 = 0x89;

/// WebSocket pong frame opcode (`FIN | 0x0A`).
const OP_PONG_FIN: u8 = 0x8A;

/// WebSocket close frame opcode (`FIN | 0x08`).
const OP_CLOSE_FIN: u8 = 0x88;

/// Dial `addr`, perform an RFC 6455 HTTP/1.1 WebSocket upgrade for `host`, and
/// return a local [`TcpStream`] bridged to the WebSocket tunnel.
///
/// # Errors
///
/// [`FetchError::Unreachable`] if TCP connection or WebSocket upgrade fails.
pub async fn connect_ws_stream(addr: SocketAddr, host: &str) -> Result<TcpStream, FetchError> {
    let mut remote = timeout(MESSAGE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| FetchError::Unreachable)?
        .map_err(|_| FetchError::Unreachable)?;
    client_upgrade(&mut remote, host)
        .await
        .ok_or(FetchError::Unreachable)?;
    spawn_loopback_bridge(remote, true)
        .await
        .ok_or(FetchError::Failed)
}

/// Complete a server-side HTTP/1.1 WebSocket upgrade after the initial `"GET "`
/// prefix has been read from `stream`, returning a bridged [`TcpStream`]
/// carrying the unframed relay protocol bytes.
pub async fn upgrade_after_get(mut stream: TcpStream) -> Option<TcpStream> {
    server_upgrade_after_get(&mut stream).await?;
    spawn_loopback_bridge(stream, false).await
}

async fn client_upgrade(stream: &mut TcpStream, host: &str) -> Option<()> {
    let req = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {WS_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    timeout(MESSAGE_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let header = read_http_header(stream, Vec::with_capacity(256)).await?;
    let lower = header.to_ascii_lowercase();
    if !lower.starts_with("http/1.1 101") || !lower.contains("upgrade: websocket") {
        return None;
    }
    Some(())
}

async fn server_upgrade_after_get(stream: &mut TcpStream) -> Option<()> {
    let mut initial = Vec::with_capacity(512);
    initial.extend_from_slice(b"GET ");
    let header = read_http_header(stream, initial).await?;
    let lower = header.to_ascii_lowercase();
    if !lower.starts_with("get ") || !lower.contains("upgrade: websocket") {
        return None;
    }
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {WS_ACCEPT}\r\n\r\n"
    );
    timeout(MESSAGE_TIMEOUT, stream.write_all(resp.as_bytes()))
        .await
        .ok()?
        .ok()?;
    Some(())
}

async fn read_http_header(stream: &mut TcpStream, mut buf: Vec<u8>) -> Option<String> {
    let mut byte = [0u8; 1];
    timeout(MESSAGE_TIMEOUT, async {
        while buf.len() < MAX_HTTP_HEADER {
            let n = stream.read(&mut byte).await.ok()?;
            if n == 0 {
                return None;
            }
            let [b] = byte;
            buf.push(b);
            if buf.ends_with(b"\r\n\r\n") {
                return String::from_utf8(buf).ok();
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn spawn_loopback_bridge(remote: TcpStream, mask_outgoing: bool) -> Option<TcpStream> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let local_addr = listener.local_addr().ok()?;
    let connect_task = tokio::spawn(TcpStream::connect(local_addr));
    let (local_bridge, _) = listener.accept().await.ok()?;
    let local_caller = connect_task.await.ok()?.ok()?;

    let (mut ws_read, mut ws_write) = tokio::io::split(remote);
    let (mut raw_read, mut raw_write) = tokio::io::split(local_bridge);

    let to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_CHUNK_SIZE];
        while let Ok(n) = raw_read.read(&mut buf).await {
            if n == 0 {
                let _ = write_ws_frame(&mut ws_write, OP_CLOSE_FIN, &[], mask_outgoing).await;
                break;
            }
            let Some(chunk) = buf.get(..n) else {
                break;
            };
            if write_ws_frame(&mut ws_write, OP_BINARY_FIN, chunk, mask_outgoing)
                .await
                .is_none()
            {
                break;
            }
        }
    });

    let from_ws = tokio::spawn(async move {
        while let Some((opcode, payload)) = read_ws_frame(&mut ws_read).await {
            match opcode {
                OP_BINARY_FIN => {
                    if raw_write.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                OP_TEXT_FIN => {
                    if let Some(decoded) = decode_nostr_envelope(&payload) {
                        if raw_write.write_all(&decoded).await.is_err() {
                            break;
                        }
                    }
                }
                OP_PING_FIN | OP_PONG_FIN => {}
                _ => break,
            }
        }
    });

    tokio::spawn(async move {
        let _ = to_ws.await;
        let _ = from_ws.await;
    });

    Some(local_caller)
}

/// Encode and write one RFC 6455 WebSocket frame.
pub async fn write_ws_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> Option<()> {
    if payload.len() > MAX_WS_FRAME {
        return None;
    }
    let mask_bit = if masked { 0x80u8 } else { 0x00u8 };
    let mut header = Vec::with_capacity(14);
    header.push(opcode);
    if payload.len() < 126 {
        let len_u8 = u8::try_from(payload.len()).ok()?;
        header.push(mask_bit | len_u8);
    } else {
        let len_u16 = u16::try_from(payload.len()).ok()?;
        header.push(mask_bit | 0x7E);
        header.extend_from_slice(&len_u16.to_be_bytes());
    }
    if masked {
        let mask_key: [u8; 4] = p2p_core::relay_random()
            .ok()
            .and_then(|r| r.get(0..4)?.try_into().ok())
            .unwrap_or([0x5A, 0x50, 0x52, 0x59]);
        header.extend_from_slice(&mask_key);
        let mut body = Vec::with_capacity(payload.len());
        for (i, &b) in payload.iter().enumerate() {
            let m = mask_key.get(i & 0x03).copied().unwrap_or(0);
            body.push(b ^ m);
        }
        writer.write_all(&header).await.ok()?;
        writer.write_all(&body).await.ok()?;
    } else {
        writer.write_all(&header).await.ok()?;
        writer.write_all(payload).await.ok()?;
    }
    writer.flush().await.ok()
}

/// Read and decode one RFC 6455 WebSocket frame, enforcing [`MAX_WS_FRAME`].
pub async fn read_ws_frame(reader: &mut (impl AsyncRead + Unpin)) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await.ok()?;
    let [b0, b1] = head;
    let opcode = 0x80 | (b0 & 0x0F);
    let masked = (b1 & 0x80) != 0;
    let len_code = usize::from(b1 & 0x7F);
    let payload_len = match len_code {
        0..=125 => len_code,
        126 => {
            let mut ext = [0u8; 2];
            reader.read_exact(&mut ext).await.ok()?;
            usize::from(u16::from_be_bytes(ext))
        }
        127 => {
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext).await.ok()?;
            usize::try_from(u64::from_be_bytes(ext)).ok()?
        }
        _ => return None,
    };
    if payload_len > MAX_WS_FRAME {
        return None;
    }
    let mask_key = if masked {
        let mut key = [0u8; 4];
        reader.read_exact(&mut key).await.ok()?;
        Some(key)
    } else {
        None
    };
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await.ok()?;
    if let Some(key) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            let m = key.get(i & 3).copied().unwrap_or(0);
            *b ^= m;
        }
    }
    Some((opcode, payload))
}

/// Encode binary relay bytes into a Nostr NIP-01 ephemeral `EVENT` JSON
/// envelope (`kind: 24242`) for text-only Nostr relays.
#[must_use]
pub fn encode_nostr_envelope(slot: &[u8; 16], payload: &[u8]) -> String {
    let slot_hex = to_hex(slot);
    let content_hex = to_hex(payload);
    format!(
        "[\"EVENT\",{{\"kind\":24242,\"tags\":[[\"d\",\"{slot_hex}\"]],\"content\":\"{content_hex}\"}}]"
    )
}

/// Extract the hex-encoded binary payload from a Nostr NIP-01 `EVENT` JSON
/// envelope.
#[must_use]
pub fn decode_nostr_envelope(text_bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(text_bytes).ok()?;
    let marker = "\"content\":\"";
    let start = text.find(marker)?.checked_add(marker.len())?;
    let rest = text.get(start..)?;
    let end = rest.find('"')?;
    from_hex(rest.get(..end)?)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
        out.push(char::from(hi));
        out.push(char::from(lo));
    }
    out
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 || hex.len() > MAX_WS_FRAME * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = hex_val(*pair.first()?)?;
        let lo = hex_val(*pair.get(1)?)?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]
mod tests {
    use super::*;

    #[test]
    fn websocket_binary_and_nostr_envelope_round_trip() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut c_side, mut s_side) = tokio::io::duplex(4096);
            write_ws_frame(&mut c_side, OP_BINARY_FIN, b"hello-zpry!", true)
                .await
                .unwrap();
            let (op, payload) = read_ws_frame(&mut s_side).await.unwrap();
            assert_eq!(op, OP_BINARY_FIN);
            assert_eq!(payload, b"hello-zpry!");

            let slot = [0xAB; 16];
            let env = encode_nostr_envelope(&slot, b"ZPRY\x01payload");
            write_ws_frame(&mut s_side, OP_TEXT_FIN, env.as_bytes(), false)
                .await
                .unwrap();
            let (op2, text_bytes) = read_ws_frame(&mut c_side).await.unwrap();
            assert_eq!(op2, OP_TEXT_FIN);
            assert_eq!(
                decode_nostr_envelope(&text_bytes).unwrap(),
                b"ZPRY\x01payload"
            );

            let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
                return;
            };
            let Ok(addr) = listener.local_addr() else {
                return;
            };
            if TcpStream::connect(addr).await.is_err() {
                return;
            }
            let _ = listener.accept().await;
            let server = tokio::spawn(async move {
                let (mut raw, _) = listener.accept().await.unwrap();
                let mut prefix = [0u8; 4];
                raw.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"GET ");
                let mut upgraded = upgrade_after_get(raw).await.unwrap();
                let mut buf = [0u8; 11];
                upgraded.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello-zpry!");
                upgraded.write_all(b"world-zpry!").await.unwrap();
            });

            let mut client = connect_ws_stream(addr, "127.0.0.1").await.unwrap();
            client.write_all(b"hello-zpry!").await.unwrap();
            let mut reply = [0u8; 11];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"world-zpry!");
            server.await.unwrap();
        });
    }
}
