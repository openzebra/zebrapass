//! Post-quantum TLS 1.3 (`X25519MLKEM768` strictly enforced) transport
//! configuration and SSRF-hardened endpoint resolution.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use local::{is_private_or_local_ip, never_dialable, parse_sync_server_url};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use secret::Secret;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::limits::{IO_TIMEOUT, MAX_EXTRA_CERTS};
use crate::tls_pin::PinnedOrWebPkiVerifier;

/// Parsed canonical sync/relay server endpoint (`host:port`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// Canonical lowercase hostname or bracketed IPv6 literal.
    pub host: Box<str>,
    /// Canonical `host:port` text.
    pub raw: Box<str>,
    /// TCP port (default `443`).
    pub port: u16,
    /// Whether loopback and private/RFC1918/CGNAT/ULA resolved IPs are allowed.
    pub allow_private: bool,
}

impl Endpoint {
    /// Parse and validate a `host[:port]` endpoint.
    ///
    /// # Errors
    ///
    /// Invalid host, forbidden IP range, or port outside `1..=65535`.
    pub fn parse(input: &str, allow_private: bool) -> anyhow::Result<Self> {
        let canonical = parse_sync_server_url(input, allow_private).map_err(|msg| anyhow!(msg))?;
        let (host_part, port_str) = canonical
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("missing port in endpoint"))?;
        let port: u16 = port_str.parse()?;
        Ok(Self {
            host: host_part.into(),
            raw: canonical,
            port,
            allow_private,
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

fn pq_tls13_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

/// Check whether a resolved socket address is permitted under `allow_private`.
#[must_use]
pub const fn resolved_addr_allowed(addr: SocketAddr, allow_private: bool) -> bool {
    let ip = addr.ip().to_canonical();
    if addr.port() == 0 || never_dialable(ip) {
        return false;
    }
    if is_private_or_local_ip(ip) {
        return allow_private;
    }
    true
}

/// Build the pure PQ TLS 1.3 `rustls` client configuration (`X25519MLKEM768`
/// only, TLS 1.3 only, `WebPKI` roots + optional extra CA / pinned PEMs).
///
/// # Errors
///
/// Invalid extra CA/pin PEM certificates or TLS builder rejection.
pub fn client_config(extra_roots_pem: Option<&[u8]>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = pq_tls13_provider();
    let mut cfg = if let Some(pem) = extra_roots_pem {
        let mut pins = Vec::new();
        for item in CertificateDer::pem_slice_iter(pem) {
            if pins.len() >= MAX_EXTRA_CERTS {
                anyhow::bail!("too many certificates in extra CA PEM");
            }
            let cert = item.map_err(|_| anyhow!("invalid extra CA certificate PEM"))?;
            let _ = roots.add(cert.clone());
            pins.push(cert);
        }
        if pins.is_empty() {
            anyhow::bail!("no certificates found in extra CA PEM");
        }
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()?;
        let verifier = Arc::new(PinnedOrWebPkiVerifier::new(webpki, pins));
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Build a pure PQ TLS 1.3 `rustls` server configuration from leaf/chain cert PEM
/// and zeroizing private key PEM bytes.
///
/// # Errors
///
/// Invalid certificate chain or private key PEM.
pub fn server_config_pem(
    cert_pem: &[u8],
    key_pem: &Secret<Vec<u8>>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("invalid TLS certificate PEM"))?;
    if certs.is_empty() {
        anyhow::bail!("empty TLS certificate chain");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.expose())
        .map_err(|_| anyhow!("invalid TLS private key PEM"))?;
    let provider = pq_tls13_provider();
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Establish a TCP + PQ TLS 1.3 connection to `ep`, rejecting any DNS-resolved
/// address that violates `ep.allow_private` or `never_dialable`.
///
/// # Errors
///
/// DNS resolution, forbidden resolved IP, TCP connect, timeout, or TLS failure.
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
    let addr = addrs
        .find(|addr| resolved_addr_allowed(*addr, ep.allow_private))
        .ok_or_else(|| anyhow!("resolved address forbidden by sync policy"))?;
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
