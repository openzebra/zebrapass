//! Endpoint parsing, direct SSRF-guarded dialing, native `socks5h://` (remote
//! DNS `ATYP=0x03`) and `http://` (`CONNECT`) proxy tunneling, and TLS
//! connection establishment.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use local::{never_dialable, parse_sync_proxy_url, parse_sync_server_url};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use secret::Secret;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::b64::encode_standard;
use crate::limits::{IO_TIMEOUT_SECS, MAX_HTTP_HEADER, MIN_SECRET_SLUG_LEN};
use crate::tls::{NegotiatedTls, inspect_client_tls};

/// Parsed and validated remote (or test loopback) sync server endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncEndpoint {
    /// Canonical origin without the secret path slug (`https://host[:port]`).
    pub origin: Box<str>,
    /// Normalized host (`[::1]` retained for IPv6 literals).
    pub host: Box<str>,
    /// Target TCP port.
    pub port: u16,
    /// `WebTunnel` secret URL path slug (no leading or trailing slash).
    pub slug: Box<str>,
    /// Whether TLS (`https://` / `wss://`) is enabled.
    pub tls: bool,
    /// Whether loopback targets (`localhost` / `127.0.0.1` / `[::1]`) are allowed.
    pub allow_loopback: bool,
}

impl SyncEndpoint {
    /// Validate and parse a sync endpoint URL.
    ///
    /// Enforce SSRF guards via [`local::parse_sync_server_url`] and require a
    /// `WebTunnel` secret path slug of at least [`MIN_SECRET_SLUG_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Invalid URL format, blocked/private non-loopback address, non-TLS remote
    /// scheme, or short secret slug.
    pub fn parse(raw: &str, allow_loopback: bool) -> anyhow::Result<Self> {
        let normalized = parse_sync_server_url(raw, allow_loopback).map_err(|msg| anyhow!(msg))?;
        let (scheme, rest) = normalized
            .split_once("://")
            .ok_or_else(|| anyhow!("invalid endpoint URL"))?;
        let (authority, slug) = rest
            .split_once('/')
            .ok_or_else(|| anyhow!("missing endpoint secret path"))?;
        if slug.len() < MIN_SECRET_SLUG_LEN {
            return Err(anyhow!(
                "endpoint secret path must be at least {MIN_SECRET_SLUG_LEN} characters"
            ));
        }
        let tls = matches!(scheme, "https" | "wss");
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = split_authority(authority, default_port)?;
        let origin_scheme = if tls { "https" } else { "http" };
        let origin = if port == default_port {
            format!("{origin_scheme}://{host}")
        } else {
            format!("{origin_scheme}://{host}:{port}")
        };
        Ok(Self {
            origin: origin.into_boxed_str(),
            host: host.into(),
            port,
            slug: slug.into(),
            tls,
            allow_loopback,
        })
    }

    /// Host string with IPv6 brackets stripped for TLS SNI / `SOCKS5h` domain wire.
    #[must_use]
    pub fn bare_host(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&self.host)
    }

    /// Canonical `Host` HTTP header value.
    #[must_use]
    pub fn host_header(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn split_authority(authority: &str, default_port: u16) -> anyhow::Result<(&str, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inner, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid IPv6 host"))?;
        let host = authority
            .get(..inner.len() + 2)
            .ok_or_else(|| anyhow!("invalid IPv6 host"))?;
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| anyhow!("invalid port"))?
        };
        return Ok((host, port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| anyhow!("invalid port"))?;
        Ok((host, port))
    } else {
        Ok((authority, default_port))
    }
}

/// Encrypted/redacted username/password credentials for a proxy tunnel.
pub struct ProxyCreds {
    user: Box<str>,
    pass: Secret<String>,
}

impl fmt::Debug for ProxyCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCreds")
            .field("user", &self.user)
            .field("pass", &"[REDACTED]")
            .finish()
    }
}

/// Outbound proxy configuration (`socks5h://` remote DNS or `http://` CONNECT).
#[derive(Debug)]
pub enum ProxyConfig {
    /// SOCKS5 with remote domain resolution (`ATYP = 0x03`).
    Socks5h {
        host: Box<str>,
        port: u16,
        auth: Option<ProxyCreds>,
    },
    /// HTTP `CONNECT` proxy tunnel.
    HttpConnect {
        host: Box<str>,
        port: u16,
        auth: Option<ProxyCreds>,
    },
}

impl ProxyConfig {
    /// Parse a proxy URL (`socks5h://[user:pass@]host:port` or
    /// `http://[user:pass@]host:port`).
    ///
    /// # Errors
    ///
    /// Invalid scheme, host, port, or credentials exceeding RFC 1929 limits.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let normalized = parse_sync_proxy_url(raw).map_err(|msg| anyhow!(msg))?;
        let (scheme, rest) = normalized
            .split_once("://")
            .ok_or_else(|| anyhow!("invalid proxy URL"))?;
        let (auth, hp) = match rest.rsplit_once('@') {
            Some((creds, hp)) => {
                let (user, pass) = creds
                    .split_once(':')
                    .ok_or_else(|| anyhow!("invalid proxy credentials"))?;
                if user.len() > 255 || pass.len() > 255 {
                    return Err(anyhow!("proxy credentials too long"));
                }
                (
                    Some(ProxyCreds {
                        user: user.into(),
                        pass: Secret::new(pass.to_owned()),
                    }),
                    hp,
                )
            }
            None => (None, rest),
        };
        let (host, port) = split_authority(hp, 0)?;
        let bare = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        match scheme {
            "socks5h" => Ok(Self::Socks5h {
                host: bare.into(),
                port,
                auth,
            }),
            "http" => Ok(Self::HttpConnect {
                host: bare.into(),
                port,
                auth,
            }),
            _ => Err(anyhow!("unsupported proxy scheme")),
        }
    }
}

/// Active transport stream to a sync server (PQ TLS 1.3 or test loopback TCP).
pub enum TransportStream {
    /// TLS stream over TCP (using `aws-lc-rs` PQ key exchange).
    Tls(Box<TlsStream<TcpStream>>),
    /// Loopback plaintext TCP stream (permitted only when `allow_loopback` is true).
    Plain(TcpStream),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

const fn io_timeout() -> Duration {
    Duration::from_secs(IO_TIMEOUT_SECS)
}

async fn connect_tcp_checked(
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> anyhow::Result<TcpStream> {
    let addrs = timeout(io_timeout(), lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("DNS lookup timed out"))??;
    let mut last_err = None;
    for addr in addrs {
        let ip = addr.ip().to_canonical();
        if ip.is_loopback() {
            if !allow_loopback {
                continue;
            }
        } else if never_dialable(ip) {
            continue;
        }
        match timeout(io_timeout(), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Some(anyhow!("connect failed: {err}")),
            Err(_) => last_err = Some(anyhow!("connect timed out")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no permitted address for endpoint")))
}

async fn dial_socks5h(
    proxy_host: &str,
    proxy_port: u16,
    auth: Option<&ProxyCreds>,
    endpoint: &SyncEndpoint,
) -> anyhow::Result<TcpStream> {
    let mut tcp = timeout(io_timeout(), TcpStream::connect((proxy_host, proxy_port)))
        .await
        .map_err(|_| anyhow!("proxy connect timed out"))??;
    let _ = tcp.set_nodelay(true);

    let greeting: &[u8] = if auth.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    timeout(io_timeout(), tcp.write_all(greeting))
        .await
        .map_err(|_| anyhow!("proxy handshake timed out"))??;

    let mut method_rep = [0u8; 2];
    timeout(io_timeout(), tcp.read_exact(&mut method_rep))
        .await
        .map_err(|_| anyhow!("proxy handshake timed out"))??;
    if method_rep[0] != 0x05 {
        return Err(anyhow!("invalid SOCKS5 greeting version"));
    }
    match method_rep[1] {
        0x00 => {}
        0x02 => {
            let creds = auth.ok_or_else(|| anyhow!("proxy requested unexpected auth"))?;
            let user_b = creds.user.as_bytes();
            let pass_b = creds.pass.expose().as_bytes();
            let ulen = u8::try_from(user_b.len()).map_err(|_| anyhow!("proxy user too long"))?;
            let plen =
                u8::try_from(pass_b.len()).map_err(|_| anyhow!("proxy password too long"))?;
            let mut msg = Zeroizing::new(Vec::with_capacity(3 + user_b.len() + pass_b.len()));
            msg.push(0x01);
            msg.push(ulen);
            msg.extend_from_slice(user_b);
            msg.push(plen);
            msg.extend_from_slice(pass_b);
            timeout(io_timeout(), tcp.write_all(&msg))
                .await
                .map_err(|_| anyhow!("proxy auth timed out"))??;
            let mut auth_rep = [0u8; 2];
            timeout(io_timeout(), tcp.read_exact(&mut auth_rep))
                .await
                .map_err(|_| anyhow!("proxy auth timed out"))??;
            if auth_rep != [0x01, 0x00] {
                return Err(anyhow!("SOCKS5 proxy authentication rejected"));
            }
        }
        _ => return Err(anyhow!("SOCKS5 proxy auth method unsupported")),
    }

    let domain = endpoint.bare_host().as_bytes();
    let dlen =
        u8::try_from(domain.len()).map_err(|_| anyhow!("target host too long for SOCKS5h"))?;
    let mut req = Vec::with_capacity(7 + domain.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, dlen]);
    req.extend_from_slice(domain);
    req.extend_from_slice(&endpoint.port.to_be_bytes());
    timeout(io_timeout(), tcp.write_all(&req))
        .await
        .map_err(|_| anyhow!("proxy connect timed out"))??;

    let mut rep_head = [0u8; 4];
    timeout(io_timeout(), tcp.read_exact(&mut rep_head))
        .await
        .map_err(|_| anyhow!("proxy reply timed out"))??;
    if rep_head[0] != 0x05 || rep_head[1] != 0x00 {
        return Err(anyhow!("SOCKS5h CONNECT refused"));
    }
    let drain_len = match rep_head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len_b = [0u8; 1];
            timeout(io_timeout(), tcp.read_exact(&mut len_b))
                .await
                .map_err(|_| anyhow!("proxy reply timed out"))??;
            usize::from(len_b[0]) + 2
        }
        _ => return Err(anyhow!("invalid SOCKS5 reply ATYP")),
    };
    let mut discard = vec![0u8; drain_len];
    timeout(io_timeout(), tcp.read_exact(&mut discard))
        .await
        .map_err(|_| anyhow!("proxy reply timed out"))??;
    Ok(tcp)
}

async fn dial_http_connect(
    proxy_host: &str,
    proxy_port: u16,
    auth: Option<&ProxyCreds>,
    endpoint: &SyncEndpoint,
) -> anyhow::Result<TcpStream> {
    let mut tcp = timeout(io_timeout(), TcpStream::connect((proxy_host, proxy_port)))
        .await
        .map_err(|_| anyhow!("proxy connect timed out"))??;
    let _ = tcp.set_nodelay(true);

    let target = format!("{}:{}", endpoint.host, endpoint.port);
    let mut req = Zeroizing::new(format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n"
    ));
    if let Some(creds) = auth {
        let pair = Zeroizing::new(format!("{}:{}", creds.user, creds.pass.expose()));
        let token = Zeroizing::new(encode_standard(pair.as_bytes()));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&token);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    timeout(io_timeout(), tcp.write_all(req.as_bytes()))
        .await
        .map_err(|_| anyhow!("proxy CONNECT write timed out"))??;

    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HTTP_HEADER {
            return Err(anyhow!("HTTP proxy CONNECT response header too large"));
        }
        let n = timeout(io_timeout(), tcp.read(&mut byte))
            .await
            .map_err(|_| anyhow!("proxy CONNECT read timed out"))??;
        if n == 0 {
            return Err(anyhow!("proxy closed before CONNECT response"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&head).map_err(|_| anyhow!("non-UTF8 proxy response"))?;
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty proxy response"))?;
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next();
    let code = parts.next().and_then(|s| s.parse::<u16>().ok());
    if code != Some(200) {
        return Err(anyhow!("HTTP CONNECT proxy returned non-200 status"));
    }
    Ok(tcp)
}

/// Dial `endpoint` (optionally through `proxy`) and wrap with PQ TLS 1.3 when
/// TLS is enabled on `endpoint`.
///
/// # Errors
///
/// DNS resolution, SSRF guard, proxy tunnel, or TLS handshake failure.
pub async fn connect_transport(
    endpoint: &SyncEndpoint,
    proxy: Option<&ProxyConfig>,
    tls_cfg: &Arc<ClientConfig>,
) -> anyhow::Result<(TransportStream, Option<NegotiatedTls>)> {
    let tcp = match proxy {
        Some(ProxyConfig::Socks5h { host, port, auth }) => {
            dial_socks5h(host, *port, auth.as_ref(), endpoint).await?
        }
        Some(ProxyConfig::HttpConnect { host, port, auth }) => {
            dial_http_connect(host, *port, auth.as_ref(), endpoint).await?
        }
        None => {
            connect_tcp_checked(endpoint.bare_host(), endpoint.port, endpoint.allow_loopback)
                .await?
        }
    };
    if !endpoint.tls {
        if !endpoint.allow_loopback {
            return Err(anyhow!("non-TLS sync endpoints are forbidden"));
        }
        return Ok((TransportStream::Plain(tcp), None));
    }
    let server_name = ServerName::try_from(endpoint.bare_host().to_owned())
        .map_err(|_| anyhow!("invalid TLS SNI hostname"))?;
    let connector = TlsConnector::from(Arc::clone(tls_cfg));
    let tls_stream = timeout(io_timeout(), connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))??;
    let info = inspect_client_tls(&tls_stream);
    Ok((TransportStream::Tls(Box::new(tls_stream)), Some(info)))
}
