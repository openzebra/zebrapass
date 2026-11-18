//! Post-quantum TLS 1.3 (`X25519MLKEM768` via `aws-lc-rs`) configuration and
//! handshake inspection helpers. ECH is deliberately disabled to avoid
//! middlebox fingerprint blocking.

use std::sync::Arc;

use anyhow::anyhow;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, NamedGroup, ProtocolVersion, RootCertStore, ServerConfig};

/// Negotiated TLS parameters observed on a client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedTls {
    /// Negotiated TLS protocol version (expected `TLSv1_3`).
    pub protocol: Option<ProtocolVersion>,
    /// Negotiated key-exchange group (expected `X25519MLKEM768`).
    pub kx_group: Option<NamedGroup>,
}

impl NegotiatedTls {
    /// Returns `true` when TLS 1.3 with hybrid PQ key exchange (`X25519MLKEM768`)
    /// was negotiated.
    #[must_use]
    pub const fn is_pq_tls13(&self) -> bool {
        matches!(self.protocol, Some(ProtocolVersion::TLSv1_3))
            && matches!(self.kx_group, Some(NamedGroup::X25519MLKEM768))
    }
}

/// Construct the workspace's PQ-preferring `rustls` crypto provider.
#[must_use]
pub fn pq_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Build a `rustls::ClientConfig` configured for TLS 1.3 + TLS 1.2 fallback,
/// PQ hybrid `X25519MLKEM768` preferred, zero ECH, and `WebPKI` roots plus
/// optional extra PEM root certificates.
///
/// # Errors
///
/// Invalid extra root PEM certificates or crypto provider initialization failure.
pub fn client_config(extra_roots_pem: Option<&[u8]>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_roots_pem {
        let mut parsed = 0usize;
        for item in CertificateDer::pem_slice_iter(pem) {
            let cert = item.map_err(|_| anyhow!("invalid extra root CA certificate"))?;
            roots
                .add(cert)
                .map_err(|_| anyhow!("rejected extra root CA certificate"))?;
            parsed = parsed.saturating_add(1);
        }
        if parsed == 0 {
            return Err(anyhow!("no root certificates found in extra PEM"));
        }
    }
    let config = ClientConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| anyhow!("tls protocol version setup failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a `rustls::ServerConfig` from PEM certificate chain and private key
/// bytes using the PQ-preferring `aws-lc-rs` provider and TLS 1.3 + 1.2.
///
/// # Errors
///
/// Missing/invalid PEM certificate chain, missing/invalid private key, or
/// mismatched keypair.
pub fn server_config_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("invalid server certificate PEM"))?;
    if certs.is_empty() {
        return Err(anyhow!("server certificate PEM contained no certs"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| anyhow!("invalid server private key PEM"))?;
    let mut config = ServerConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| anyhow!("tls protocol version setup failed"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| anyhow!("server TLS cert/key mismatch"))?;
    config.alpn_protocols.push(b"http/1.1".to_vec());
    Ok(Arc::new(config))
}

/// Inspect the negotiated protocol and key-exchange group of an established
/// `tokio_rustls` client stream.
#[must_use]
pub fn inspect_client_tls<S>(stream: &tokio_rustls::client::TlsStream<S>) -> NegotiatedTls {
    let (_, conn) = stream.get_ref();
    NegotiatedTls {
        protocol: conn.protocol_version(),
        kx_group: conn
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name),
    }
}
