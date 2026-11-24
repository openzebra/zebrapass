//! Mutual `ML-DSA-65` mesh peer authentication bound to TLS 1.3 exporter
//! keying material (`RFC 8446 §7.5`), preventing unauthorized server cloning
//! or MITM splicing even under a compromised CA.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::anyhow;
use pq::{MESH_AUTH_CTX, SYNC_SIG_LEN, SYNC_VK_LEN, sync_sign, sync_verify, sync_verifying_key};
use rustls::ClientConfig;
use secret::{Secret, ct_eq};
use session::frame_parts;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use zeroize::Zeroizing;

use crate::limits::{IO_TIMEOUT, MAX_SMALL_FRAME};
use crate::tls::Endpoint;
use crate::wire::{TAG_ACK, TAG_MESH_AUTH, TAG_MESH_HELLO, read_wire, write_wire};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-zebrapass-mesh-v1";
const DOMAIN_MESH_AUTH: &[u8] = b"brby/v3/mesh-auth";
const HELLO_INIT_LEN: usize = 16 + SYNC_VK_LEN;
const HELLO_RESP_LEN: usize = 16 + SYNC_VK_LEN + SYNC_SIG_LEN;

/// Configured outbound mesh peer endpoint pinned to its `ML-DSA-65` verifying key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshPeer {
    /// Canonical `host[:port]` endpoint.
    pub endpoint: Box<str>,
    /// Expected `ML-DSA-65` verifying key of the remote peer server.
    pub peer_vk: Box<[u8; SYNC_VK_LEN]>,
}

impl MeshPeer {
    /// Parse `<host[:port]>@<vk_hex>` into a [`MeshPeer`].
    ///
    /// # Errors
    ///
    /// Missing `@`, invalid endpoint, or malformed verifying key hex.
    pub fn parse(spec: &str, allow_private: bool) -> anyhow::Result<Self> {
        let (raw_ep, raw_vk) = spec
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("--peer expects <host[:port]>@<mesh_vk_hex>"))?;
        let ep = Endpoint::parse(raw_ep, allow_private)?;
        let peer_vk = parse_mesh_vk_hex(raw_vk)?;
        Ok(Self {
            endpoint: ep.raw,
            peer_vk,
        })
    }
}

/// Server-to-server `ML-DSA-65` mesh authentication configuration.
pub struct MeshAuthConfig {
    /// This server's 32-byte `ML-DSA-65` signing seed.
    pub seed: Secret<[u8; 32]>,
    /// Outbound peer servers to dial and replicate with.
    pub peers: Vec<MeshPeer>,
    /// Additional inbound peer `ML-DSA-65` verifying keys allowed to connect.
    pub allowed_vks: Vec<[u8; SYNC_VK_LEN]>,
}

impl std::fmt::Debug for MeshAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshAuthConfig")
            .field("peers", &self.peers.len())
            .field("allowed_vks", &self.allowed_vks.len())
            .finish_non_exhaustive()
    }
}

/// Decode a hex-encoded 1952-byte `ML-DSA-65` verifying key.
///
/// # Errors
///
/// Wrong hex length or non-hex characters.
pub fn parse_mesh_vk_hex(hex_str: &str) -> anyhow::Result<Box<[u8; SYNC_VK_LEN]>> {
    let trimmed = hex_str.trim();
    if trimmed.len() != SYNC_VK_LEN * 2 {
        anyhow::bail!("mesh verifying key hex must be {} chars", SYNC_VK_LEN * 2);
    }
    let mut out = Box::new([0u8; SYNC_VK_LEN]);
    for (idx, dst) in out.iter_mut().enumerate() {
        let pos = idx * 2;
        let pair = trimmed
            .get(pos..pos + 2)
            .ok_or_else(|| anyhow!("invalid mesh key hex"))?;
        *dst = u8::from_str_radix(pair, 16).map_err(|_| anyhow!("invalid mesh key hex"))?;
    }
    Ok(out)
}

/// Format a 1952-byte `ML-DSA-65` verifying key as lowercase hex.
#[must_use]
pub fn format_mesh_vk_hex(vk: &[u8; SYNC_VK_LEN]) -> String {
    let mut out = String::with_capacity(SYNC_VK_LEN * 2);
    for b in vk {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Validated runtime mesh state shared across server tasks.
pub struct MeshRuntime {
    seed: Secret<[u8; 32]>,
    own_vk: Box<[u8; SYNC_VK_LEN]>,
    pub peers: Vec<(Endpoint, Box<[u8; SYNC_VK_LEN]>)>,
    allowed_vks: Vec<[u8; SYNC_VK_LEN]>,
    pub tls_cfg: Arc<ClientConfig>,
}

impl std::fmt::Debug for MeshRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshRuntime")
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl MeshRuntime {
    /// Build validated [`MeshRuntime`] from `cfg`.
    ///
    /// # Errors
    ///
    /// Invalid peer endpoint or signing seed.
    pub fn from_config(
        cfg: MeshAuthConfig,
        tls_cfg: Arc<ClientConfig>,
        allow_private: bool,
    ) -> anyhow::Result<Arc<Self>> {
        let raw_vk = sync_verifying_key(cfg.seed.expose())?;
        let own_vk = Box::new(
            <[u8; SYNC_VK_LEN]>::try_from(raw_vk)
                .map_err(|_| anyhow!("unexpected mesh vk length"))?,
        );
        let mut peers = Vec::with_capacity(cfg.peers.len());
        let mut allowed_vks = cfg.allowed_vks;
        for p in cfg.peers {
            let ep = Endpoint::parse(&p.endpoint, allow_private)?;
            if !allowed_vks
                .iter()
                .any(|k| ct_eq(k.as_slice(), p.peer_vk.as_slice()))
            {
                allowed_vks.push(*p.peer_vk);
            }
            peers.push((ep, p.peer_vk));
        }
        Ok(Arc::new(Self {
            seed: cfg.seed,
            own_vk,
            peers,
            allowed_vks,
            tls_cfg,
        }))
    }

    fn is_peer_allowed(&self, candidate_vk: &[u8; SYNC_VK_LEN]) -> bool {
        let mut ok = false;
        for allowed in &self.allowed_vks {
            ok |= ct_eq(allowed.as_slice(), candidate_vk);
        }
        ok
    }

    /// Authenticate an outbound `PeerMesh` connection to `expected_peer_vk`.
    ///
    /// # Errors
    ///
    /// Exporter extraction, wrong peer key, bad signature, or I/O timeout.
    pub async fn handshake_initiator(
        &self,
        tls: &mut ClientTlsStream<TcpStream>,
        expected_peer_vk: &[u8; SYNC_VK_LEN],
    ) -> anyhow::Result<()> {
        let mut exporter = Zeroizing::new([0u8; 32]);
        tls.get_ref()
            .1
            .export_keying_material(exporter.as_mut(), EXPORTER_LABEL, None)
            .map_err(|_| anyhow!("TLS exporter unavailable"))?;
        let mut init_nonce = [0u8; 16];
        getrandom::fill(&mut init_nonce).map_err(|_| anyhow!("os entropy failed"))?;
        let mut hello = Vec::with_capacity(HELLO_INIT_LEN);
        hello.extend_from_slice(&init_nonce);
        hello.extend_from_slice(self.own_vk.as_slice());
        timeout(IO_TIMEOUT, write_wire(tls, TAG_MESH_HELLO, &hello)).await??;

        let (tag, body) = timeout(IO_TIMEOUT, read_wire(tls, MAX_SMALL_FRAME)).await??;
        if tag != TAG_MESH_HELLO || body.len() != HELLO_RESP_LEN {
            anyhow::bail!("mesh responder hello rejected");
        }
        let (resp_nonce, rest) = body
            .split_first_chunk::<16>()
            .ok_or_else(|| anyhow!("corrupt mesh hello"))?;
        let (resp_vk, resp_sig) = rest
            .split_first_chunk::<SYNC_VK_LEN>()
            .ok_or_else(|| anyhow!("corrupt mesh hello"))?;
        if !ct_eq(resp_vk, expected_peer_vk) {
            anyhow::bail!("mesh peer verifying key mismatch");
        }
        let resp_msg = auth_transcript(
            b"responder",
            &exporter,
            &init_nonce,
            resp_nonce,
            &self.own_vk,
            resp_vk,
        )?;
        sync_verify(resp_vk, MESH_AUTH_CTX, &resp_msg, resp_sig)?;

        let init_msg = auth_transcript(
            b"initiator",
            &exporter,
            &init_nonce,
            resp_nonce,
            &self.own_vk,
            resp_vk,
        )?;
        let init_sig = sync_sign(self.seed.expose(), MESH_AUTH_CTX, &init_msg)?;
        timeout(IO_TIMEOUT, write_wire(tls, TAG_MESH_AUTH, &init_sig)).await??;

        let (ack, _) = timeout(IO_TIMEOUT, read_wire(tls, MAX_SMALL_FRAME)).await??;
        if ack != TAG_ACK {
            anyhow::bail!("mesh auth rejected by responder");
        }
        Ok(())
    }

    /// Authenticate an inbound `PeerMesh` connection against `self.allowed_vks`.
    ///
    /// # Errors
    ///
    /// Unauthorized peer key, bad signature, or I/O timeout.
    pub async fn handshake_responder(
        &self,
        tls: &mut ServerTlsStream<TcpStream>,
    ) -> anyhow::Result<()> {
        if self.allowed_vks.is_empty() {
            anyhow::bail!("peer mesh disabled");
        }
        let mut exporter = Zeroizing::new([0u8; 32]);
        tls.get_ref()
            .1
            .export_keying_material(exporter.as_mut(), EXPORTER_LABEL, None)
            .map_err(|_| anyhow!("TLS exporter unavailable"))?;
        let (tag, body) = timeout(IO_TIMEOUT, read_wire(tls, MAX_SMALL_FRAME)).await??;
        if tag != TAG_MESH_HELLO || body.len() != HELLO_INIT_LEN {
            anyhow::bail!("mesh initiator hello rejected");
        }
        let (init_nonce, rest) = body
            .split_first_chunk::<16>()
            .ok_or_else(|| anyhow!("corrupt mesh hello"))?;
        let init_vk: &[u8; SYNC_VK_LEN] =
            rest.try_into().map_err(|_| anyhow!("corrupt mesh hello"))?;
        if !self.is_peer_allowed(init_vk) {
            anyhow::bail!("unauthorized mesh peer key");
        }

        let mut resp_nonce = [0u8; 16];
        getrandom::fill(&mut resp_nonce).map_err(|_| anyhow!("os entropy failed"))?;
        let resp_msg = auth_transcript(
            b"responder",
            &exporter,
            init_nonce,
            &resp_nonce,
            init_vk,
            &self.own_vk,
        )?;
        let resp_sig = sync_sign(self.seed.expose(), MESH_AUTH_CTX, &resp_msg)?;
        let mut reply = Vec::with_capacity(HELLO_RESP_LEN);
        reply.extend_from_slice(&resp_nonce);
        reply.extend_from_slice(self.own_vk.as_slice());
        reply.extend_from_slice(&resp_sig);
        timeout(IO_TIMEOUT, write_wire(tls, TAG_MESH_HELLO, &reply)).await??;

        let (atag, abody) = timeout(IO_TIMEOUT, read_wire(tls, MAX_SMALL_FRAME)).await??;
        if atag != TAG_MESH_AUTH || abody.len() != SYNC_SIG_LEN {
            anyhow::bail!("mesh initiator auth rejected");
        }
        let init_msg = auth_transcript(
            b"initiator",
            &exporter,
            init_nonce,
            &resp_nonce,
            init_vk,
            &self.own_vk,
        )?;
        sync_verify(init_vk, MESH_AUTH_CTX, &init_msg, &abody)?;
        timeout(IO_TIMEOUT, write_wire(tls, TAG_ACK, &[])).await??;
        Ok(())
    }
}

fn auth_transcript(
    role: &[u8],
    exporter: &[u8; 32],
    init_nonce: &[u8; 16],
    resp_nonce: &[u8; 16],
    init_vk: &[u8; SYNC_VK_LEN],
    resp_vk: &[u8; SYNC_VK_LEN],
) -> anyhow::Result<Vec<u8>> {
    frame_parts(&[
        DOMAIN_MESH_AUTH,
        role,
        exporter,
        init_nonce,
        resp_nonce,
        init_vk,
        resp_vk,
    ])
}
