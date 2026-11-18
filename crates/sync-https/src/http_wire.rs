//! Bounded HTTP/1.1 request and response codecs for `SplitHTTP` transport.

use std::fmt::Write as _;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::limits::{IO_TIMEOUT_SECS, MAX_HTTP_BODY, MAX_HTTP_HEADER};
pub use crate::ws_wire::{
    WS_OP_BIN, WS_OP_CLOSE, WS_OP_CONT, WS_OP_PING, WS_OP_PONG, WS_OP_TEXT, ws_accept_token,
    ws_client_upgrade, ws_read_frame, ws_write_frame,
};

/// Parsed HTTP/1.1 request with bounded header and body.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Box<str>,
    pub path: Box<str>,
    pub headers: Vec<(Box<str>, Box<str>)>,
    pub body: Vec<u8>,
}

/// Parsed HTTP/1.1 response with bounded header and body.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: Box<str>,
    pub headers: Vec<(Box<str>, Box<str>)>,
    pub body: Vec<u8>,
}

pub(crate) const fn io_timeout() -> Duration {
    Duration::from_secs(IO_TIMEOUT_SECS)
}

/// Find a header value using ASCII case-insensitive header name matching.
#[must_use]
pub fn header_value<'a>(headers: &'a [(Box<str>, Box<str>)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| &**v)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

async fn read_head_block<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = timeout(io_timeout(), reader.read(&mut chunk))
            .await
            .map_err(|_| anyhow!("HTTP read timed out"))??;
        if n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(anyhow!("unexpected EOF in HTTP headers"));
        }
        let slice = chunk.get(..n).ok_or_else(|| anyhow!("read length error"))?;
        if raw.len().saturating_add(slice.len()) > MAX_HTTP_HEADER + MAX_HTTP_BODY {
            return Err(anyhow!("HTTP read buffer bound exceeded"));
        }
        raw.extend_from_slice(slice);
        if let Some(end) = find_header_end(&raw) {
            let (head, rest) = raw
                .split_at_checked(end)
                .ok_or_else(|| anyhow!("invalid header boundary"))?;
            return Ok(Some((head.to_vec(), rest.to_vec())));
        }
        if raw.len() > MAX_HTTP_HEADER {
            return Err(anyhow!("HTTP header exceeds limit"));
        }
    }
}

fn parse_headers_block<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> anyhow::Result<Vec<(Box<str>, Box<str>)>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() >= 64 {
            return Err(anyhow!("too many HTTP headers"));
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed HTTP header line"))?;
        headers.push((k.trim().into(), v.trim().into()));
    }
    Ok(headers)
}

fn parse_content_length(headers: &[(Box<str>, Box<str>)]) -> anyhow::Result<Option<usize>> {
    if let Some(te) = header_value(headers, "transfer-encoding")
        && !te.trim().eq_ignore_ascii_case("identity")
    {
        return Err(anyhow!("unsupported transfer-encoding"));
    }
    match header_value(headers, "content-length") {
        Some(raw) => {
            let len: usize = raw
                .trim()
                .parse()
                .map_err(|_| anyhow!("invalid content-length"))?;
            if len > MAX_HTTP_BODY {
                return Err(anyhow!("HTTP body exceeds MAX_HTTP_BODY"));
            }
            Ok(Some(len))
        }
        None => Ok(None),
    }
}

/// Read one bounded HTTP/1.1 request, returning `Ok(None)` on clean EOF before
/// any request bytes arrive.
///
/// # Errors
///
/// Oversized headers/body, malformed HTTP syntax, or read timeout/IO error.
pub async fn read_http_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<HttpRequest>> {
    let Some((head_bytes, mut body)) = read_head_block(reader).await? else {
        return Ok(None);
    };
    let head_str = std::str::from_utf8(&head_bytes).map_err(|_| anyhow!("non-UTF8 HTTP header"))?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing HTTP request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("missing HTTP method"))?;
    let path = parts.next().ok_or_else(|| anyhow!("missing HTTP path"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Err(anyhow!("unsupported HTTP request version"));
    }
    let headers = parse_headers_block(lines)?;
    let content_len = parse_content_length(&headers)?.unwrap_or(0);
    if body.len() > content_len {
        body.truncate(content_len);
    }
    while body.len() < content_len {
        let need = content_len.saturating_sub(body.len());
        let mut buf = vec![0u8; need.min(8_192)];
        let n = timeout(io_timeout(), reader.read(&mut buf))
            .await
            .map_err(|_| anyhow!("HTTP body read timed out"))??;
        if n == 0 {
            return Err(anyhow!("truncated HTTP request body"));
        }
        let slice = buf.get(..n).ok_or_else(|| anyhow!("read bound error"))?;
        body.extend_from_slice(slice);
    }
    Ok(Some(HttpRequest {
        method: method.into(),
        path: path.into(),
        headers,
        body,
    }))
}

/// Read one bounded HTTP/1.1 response.
///
/// # Errors
///
/// Oversized headers/body, malformed status line, EOF, or IO timeout.
pub async fn read_http_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<HttpResponse> {
    let (head_bytes, mut body) = read_head_block(reader)
        .await?
        .ok_or_else(|| anyhow!("unexpected EOF waiting for HTTP response"))?;
    let head_str =
        std::str::from_utf8(&head_bytes).map_err(|_| anyhow!("non-UTF8 HTTP response"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing HTTP status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(anyhow!("unsupported HTTP response version"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("invalid HTTP status code"))?;
    let reason = parts.next().unwrap_or("");
    let headers = parse_headers_block(lines)?;
    if let Some(content_len) = parse_content_length(&headers)? {
        if body.len() > content_len {
            body.truncate(content_len);
        }
        while body.len() < content_len {
            let need = content_len.saturating_sub(body.len());
            let mut buf = vec![0u8; need.min(8_192)];
            let n = timeout(io_timeout(), reader.read(&mut buf))
                .await
                .map_err(|_| anyhow!("HTTP response body timed out"))??;
            if n == 0 {
                return Err(anyhow!("truncated HTTP response body"));
            }
            let slice = buf.get(..n).ok_or_else(|| anyhow!("read bound error"))?;
            body.extend_from_slice(slice);
        }
    } else if status != 101 && status != 204 {
        let mut buf = [0u8; 4_096];
        loop {
            let n = timeout(io_timeout(), reader.read(&mut buf))
                .await
                .map_err(|_| anyhow!("HTTP EOF read timed out"))??;
            if n == 0 {
                break;
            }
            if body.len().saturating_add(n) > MAX_HTTP_BODY {
                return Err(anyhow!("HTTP close-delimited body exceeds limit"));
            }
            let slice = buf.get(..n).ok_or_else(|| anyhow!("read bound error"))?;
            body.extend_from_slice(slice);
        }
    }
    Ok(HttpResponse {
        status,
        reason: reason.into(),
        headers,
        body,
    })
}

/// Write a compact HTTP/1.1 request (`Connection: close`) over `writer`.
///
/// # Errors
///
/// Write failure or timeout.
pub async fn write_http_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    method: &str,
    path: &str,
    host: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> anyhow::Result<()> {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n"
    );
    if !body.is_empty() || method == "POST" {
        if let Some(ct) = content_type {
            head.push_str("Content-Type: ");
            head.push_str(ct);
            head.push_str("\r\n");
        }
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    timeout(io_timeout(), async {
        writer.write_all(head.as_bytes()).await?;
        if !body.is_empty() {
            writer.write_all(body).await?;
        }
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("HTTP request write timed out"))??;
    Ok(())
}

/// Write an HTTP/1.1 response over `writer`.
///
/// # Errors
///
/// Write failure or timeout.
pub async fn write_http_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    let mut has_len = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_len = true;
        }
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if !has_len && status != 101 && status != 204 {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    timeout(io_timeout(), async {
        writer.write_all(head.as_bytes()).await?;
        if !body.is_empty() {
            writer.write_all(body).await?;
        }
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("HTTP response write timed out"))??;
    Ok(())
}
