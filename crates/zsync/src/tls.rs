//! Post-quantum TLS 1.3 (`X25519MLKEM768` preferred) transport configuration
//! and endpoint resolution.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use local::parse_sync_server_url;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::limits::IO_TIMEOUT;

/// Parsed canonical sync/relay server endpoint (`host:port`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// Canonical lowercase hostname or bracketed IPv6 literal.
    pub host: Box<str>,
    /// TCP port (default `443`).
    pub port: u16,
    /// Canonical `host:port` text.
    pub raw: Box<str>,
}

impl Endpoint {
    /// Parse and validate a `host[:port]` endpoint.
    ///
    /// # Errors
    ///
    /// Invalid host, forbidden IP range, or port outside `1..=65535`.
    pub fn parse(input: &str, allow_loopback: bool) -> anyhow::Result<Self> {
        let canonical = parse_sync_server_url(input, allow_loopback).map_err(|msg| anyhow!(msg))?;
        let (host_part, port_str) = canonical
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("missing port in endpoint"))?;
        let port: u16 = port_str.parse()?;
        Ok(Self {
            host: host_part.into(),
            port,
            raw: canonical,
        })
    }

    /// Server name for TLS SNI and certificate verification.
    ///
    /// # Errors
    ///
    /// Invalid DNS name or IP literal.
    pub fn server_name(&self) -> anyhow::Result<ServerName<'static>> {
        let bare = self
            .host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&self.host);
        ServerName::try_from(bare.to_owned()).map_err(|_| anyhow!("invalid TLS server name"))
    }
}

/// Build the PQ TLS 1.3 `rustls` client configuration (`X25519MLKEM768`
/// preferred via `aws-lc-rs`, `WebPKI` roots + optional extra CA PEMs).
///
/// # Errors
///
/// Invalid extra CA PEM certificates or TLS builder rejection.
pub fn client_config(extra_roots_pem: Option<&[u8]>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_roots_pem {
        for item in CertificateDer::pem_slice_iter(pem) {
            let cert = item.map_err(|_| anyhow!("invalid extra CA certificate PEM"))?;
            roots.add(cert)?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Build a PQ TLS 1.3 `rustls` server configuration from leaf/chain cert PEM
/// and private key PEM bytes.
///
/// # Errors
///
/// Invalid certificate chain or private key PEM.
pub fn server_config_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("invalid TLS certificate PEM"))?;
    if certs.is_empty() {
        anyhow::bail!("empty TLS certificate chain");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| anyhow!("invalid TLS private key PEM"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Establish a TCP + PQ TLS 1.3 connection to `ep`.
///
/// # Errors
///
/// DNS resolution, TCP connect, handshake timeout, or TLS verification failure.
pub async fn connect_tls(
    ep: &Endpoint,
    cfg: &Arc<ClientConfig>,
) -> anyhow::Result<(TlsStream<TcpStream>, SocketAddr)> {
    let server_name = ep.server_name()?;
    let bare = ep
        .host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&ep.host);
    let mut addrs = timeout(IO_TIMEOUT, tokio::net::lookup_host((bare, ep.port)))
        .await
        .map_err(|_| anyhow!("DNS lookup timeout"))??;
    let addr = addrs.next().ok_or_else(|| anyhow!("no resolved address"))?;
    let tcp = timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("TCP connect timeout"))??;
    let _ = tcp.set_nodelay(true);
    let tls = timeout(
        IO_TIMEOUT,
        TlsConnector::from(Arc::clone(cfg)).connect(server_name, tcp),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake timeout"))??;
    Ok((tls, addr))
}
