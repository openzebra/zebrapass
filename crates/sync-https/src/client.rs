//! Multi-endpoint HTTPS + `SplitHTTP` client transport with automatic
//! certificate registration (`StageCert` / `AnchorPersonalRoot`), proxy
//! tunneling, and `<= 6 KiB` TSPU-resilient chunk transfers.

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use local::SyncIdentity;
use pq::SYNC_VK_LEN;
use syncwire::encode_cert;
use zeroize::Zeroizing;

use crate::auth::{sign_chunk_query, sign_op, sign_state_query};
use crate::http_wire::{read_http_response, write_http_request};
use crate::limits::{MAX_ENDPOINTS, SPLIT_TRANSFER_CHUNK};
use crate::proxy::{ProxyConfig, SyncEndpoint, connect_transport};
use crate::tls::{NegotiatedTls, client_config};
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};
use crate::wire_rpc::{ChunkQuery, ChunkReply, MailboxSummary, OpReply, OpStatus, SignedOp};

/// HTTPS/WSS + `SplitHTTP` zero-knowledge sync and backup client.
pub struct SyncClient {
    endpoints: Vec<SyncEndpoint>,
    proxy: Option<Arc<ProxyConfig>>,
    tls_cfg: Arc<rustls::ClientConfig>,
    last_tls: Mutex<Option<NegotiatedTls>>,
}

impl SyncClient {
    /// Construct a client over `1..=MAX_ENDPOINTS` endpoints, an optional
    /// `socks5h://` / `http://` proxy URL, and optional extra trusted CA PEMs.
    ///
    /// # Errors
    ///
    /// Empty or oversized endpoint list, invalid URL/proxy, or TLS config failure.
    pub fn new(
        urls: &[String],
        proxy_url: Option<&str>,
        extra_roots_pem: Option<&[u8]>,
        allow_loopback: bool,
    ) -> anyhow::Result<Self> {
        if urls.is_empty() || urls.len() > MAX_ENDPOINTS {
            anyhow::bail!("between 1 and {MAX_ENDPOINTS} sync endpoints required");
        }
        let mut endpoints = Vec::with_capacity(urls.len());
        for raw in urls {
            let ep = SyncEndpoint::parse(raw, allow_loopback)?;
            if !endpoints.contains(&ep) {
                endpoints.push(ep);
            }
        }
        let proxy = match proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(Arc::new(ProxyConfig::parse(raw)?)),
            None => None,
        };
        let tls_cfg = client_config(extra_roots_pem)?;
        Ok(Self {
            endpoints,
            proxy,
            tls_cfg,
            last_tls: Mutex::new(None),
        })
    }

    /// Configured server endpoints in priority order.
    #[must_use]
    pub fn endpoints(&self) -> &[SyncEndpoint] {
        &self.endpoints
    }

    /// Configured outbound proxy, if any.
    #[must_use]
    pub const fn proxy(&self) -> Option<&Arc<ProxyConfig>> {
        self.proxy.as_ref()
    }

    /// Client `rustls` configuration (PQ `X25519MLKEM768` preferred, no ECH).
    #[must_use]
    pub const fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        &self.tls_cfg
    }

    /// Last observed TLS handshake parameters from this client.
    #[must_use]
    pub fn last_negotiated_tls(&self) -> Option<NegotiatedTls> {
        self.last_tls.lock().ok().and_then(|g| *g)
    }

    pub(crate) async fn post_raw(
        &self,
        ep: &SyncEndpoint,
        subpath: &str,
        body: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (mut stream, tls_info) =
            connect_transport(ep, self.proxy.as_deref(), &self.tls_cfg).await?;
        if let Some(info) = tls_info
            && let Ok(mut guard) = self.last_tls.lock()
        {
            *guard = Some(info);
        }
        let path = format!("/{}/v1/{subpath}", ep.slug);
        write_http_request(
            &mut stream,
            "POST",
            &path,
            &ep.host_header(),
            Some("application/octet-stream"),
            body,
        )
        .await?;
        let resp = read_http_response(&mut stream).await?;
        if resp.status != 200 {
            anyhow::bail!("sync server HTTP {}", resp.status);
        }
        Ok(resp.body)
    }

    pub(crate) async fn post_op_once(
        &self,
        ep: &SyncEndpoint,
        op: &SignedOp,
    ) -> anyhow::Result<OpReply> {
        let raw = self.post_raw(ep, "op", &op.encode()?).await?;
        OpReply::decode(&raw)
    }

    async fn stage_cert_raw(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        kind: MailboxKind,
    ) -> anyhow::Result<()> {
        let own_cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("missing local device certificate"))?;
        let stage = sign_op(
            identity,
            &ep.origin,
            box_id,
            kind,
            &OpPayload::StageCert {
                cert_wire: encode_cert(own_cert)?,
            },
        )?;
        let reply = self.post_op_once(ep, &stage).await?;
        if reply.status == OpStatus::Rejected {
            anyhow::bail!("device certificate rejected by server");
        }
        Ok(())
    }

    /// Stage this device's certificate and anchor the personal mailbox root key.
    pub(crate) async fn ensure_personal_cert(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
    ) -> anyhow::Result<()> {
        self.stage_cert_raw(ep, identity, box_id, MailboxKind::Personal)
            .await?;
        let root_vk: Box<[u8; SYNC_VK_LEN]> = Box::new(*identity.root_vk());
        let anchor = sign_op(
            identity,
            &ep.origin,
            box_id,
            MailboxKind::Personal,
            &OpPayload::AnchorPersonalRoot { root_vk },
        )?;
        let r2 = self.post_op_once(ep, &anchor).await?;
        if r2.status != OpStatus::Ok {
            anyhow::bail!("personal mailbox anchor rejected ({:?})", r2.status);
        }
        Ok(())
    }

    /// Stage this device's certificate (and optionally initialize a shared mailbox)
    /// on `ep`.
    pub(crate) async fn ensure_shared_cert(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        init: Option<([u8; 16], [u8; 32], &[u8])>,
    ) -> anyhow::Result<()> {
        self.stage_cert_raw(ep, identity, box_id, MailboxKind::Shared)
            .await?;
        if let Some((vault_id, anchor, entries_raw)) = init {
            let (chunk_id, total_chunks) = self
                .upload_chunks_raw(ep, identity, box_id, MailboxKind::Shared, entries_raw)
                .await?;
            let commit = sign_op(
                identity,
                &ep.origin,
                box_id,
                MailboxKind::Shared,
                &OpPayload::CommitInitShared {
                    vault_id,
                    anchor,
                    chunk_id,
                    total_chunks,
                },
            )?;
            let r2 = self.post_op_once(ep, &commit).await?;
            if r2.status != OpStatus::Ok {
                anyhow::bail!("shared mailbox init rejected ({:?})", r2.status);
            }
        }
        Ok(())
    }

    pub(crate) async fn send_personal_op(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        payload: &OpPayload,
    ) -> anyhow::Result<OpReply> {
        let op = sign_op(identity, &ep.origin, box_id, MailboxKind::Personal, payload)?;
        let reply = self.post_op_once(ep, &op).await?;
        if matches!(reply.status, OpStatus::NeedCert | OpStatus::NeedAnchor) {
            self.ensure_personal_cert(ep, identity, box_id).await?;
            let retry = sign_op(identity, &ep.origin, box_id, MailboxKind::Personal, payload)?;
            let r2 = self.post_op_once(ep, &retry).await?;
            if r2.status != OpStatus::Ok {
                anyhow::bail!("personal sync op rejected ({:?})", r2.status);
            }
            return Ok(r2);
        }
        if reply.status != OpStatus::Ok {
            anyhow::bail!("personal sync op rejected ({:?})", reply.status);
        }
        Ok(reply)
    }

    pub(crate) async fn send_shared_op(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        payload: &OpPayload,
        init: Option<([u8; 16], [u8; 32], &[u8])>,
    ) -> anyhow::Result<OpReply> {
        let op = sign_op(identity, &ep.origin, box_id, MailboxKind::Shared, payload)?;
        let reply = self.post_op_once(ep, &op).await?;
        if matches!(reply.status, OpStatus::NeedCert | OpStatus::NeedAnchor) {
            self.ensure_shared_cert(ep, identity, box_id, init).await?;
            let retry = sign_op(identity, &ep.origin, box_id, MailboxKind::Shared, payload)?;
            let r2 = self.post_op_once(ep, &retry).await?;
            if r2.status != OpStatus::Ok {
                anyhow::bail!("shared sync op rejected ({:?})", r2.status);
            }
            return Ok(r2);
        }
        if reply.status != OpStatus::Ok {
            anyhow::bail!("shared sync op rejected ({:?})", reply.status);
        }
        Ok(reply)
    }

    pub(crate) async fn upload_chunks_raw(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        kind: MailboxKind,
        bytes: &[u8],
    ) -> anyhow::Result<([u8; 32], u32)> {
        let mut chunk_id = [0u8; 32];
        getrandom::fill(&mut chunk_id).map_err(|_| anyhow!("os entropy failed"))?;
        let slices: Vec<&[u8]> = if bytes.is_empty() {
            vec![&[][..]]
        } else {
            bytes.chunks(SPLIT_TRANSFER_CHUNK).collect()
        };
        let total = u32::try_from(slices.len()).map_err(|_| anyhow!("chunk count overflow"))?;
        for (idx, slice) in slices.into_iter().enumerate() {
            let index = u32::try_from(idx).map_err(|_| anyhow!("chunk index overflow"))?;
            let payload = OpPayload::PutChunk {
                chunk_id,
                index,
                total,
                data: slice.to_vec(),
            };
            let op = sign_op(identity, &ep.origin, box_id, kind, &payload)?;
            let reply = self.post_op_once(ep, &op).await?;
            if matches!(reply.status, OpStatus::NeedCert | OpStatus::NeedAnchor) {
                match kind {
                    MailboxKind::Personal => {
                        self.ensure_personal_cert(ep, identity, box_id).await?;
                    }
                    MailboxKind::Shared => {
                        self.stage_cert_raw(ep, identity, box_id, MailboxKind::Shared)
                            .await?;
                    }
                }
                let retry = sign_op(identity, &ep.origin, box_id, kind, &payload)?;
                let r2 = self.post_op_once(ep, &retry).await?;
                if r2.status != OpStatus::Ok {
                    anyhow::bail!("chunk upload rejected ({:?})", r2.status);
                }
            } else if reply.status != OpStatus::Ok {
                anyhow::bail!("chunk upload rejected ({:?})", reply.status);
            }
        }
        Ok((chunk_id, total))
    }

    pub(crate) async fn post_state(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        kind: MailboxKind,
        since_seq: u64,
        since_member_seq: u64,
    ) -> anyhow::Result<MailboxSummary> {
        let q = sign_state_query(
            identity,
            &ep.origin,
            box_id,
            kind,
            since_seq,
            since_member_seq,
        )?;
        let mut summary = MailboxSummary::decode(&self.post_raw(ep, "state", &q.encode()?).await?)?;
        if matches!(summary.status, OpStatus::NeedCert | OpStatus::NeedAnchor) {
            match kind {
                MailboxKind::Personal => self.ensure_personal_cert(ep, identity, box_id).await?,
                MailboxKind::Shared => self.ensure_shared_cert(ep, identity, box_id, None).await?,
            }
            let q2 = sign_state_query(
                identity,
                &ep.origin,
                box_id,
                kind,
                since_seq,
                since_member_seq,
            )?;
            summary = MailboxSummary::decode(&self.post_raw(ep, "state", &q2.encode()?).await?)?;
        }
        if summary.status != OpStatus::Ok {
            anyhow::bail!("state query rejected ({:?})", summary.status);
        }
        Ok(summary)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "explicit chunk slice coordinates"
    )]
    pub(crate) async fn post_chunk_once(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        kind: MailboxKind,
        target: ChunkTarget,
        object_id: [u8; 32],
        index: u32,
        offset: u32,
        max_len: u32,
    ) -> anyhow::Result<ChunkReply> {
        let q: ChunkQuery = sign_chunk_query(
            identity, &ep.origin, box_id, kind, target, object_id, index, offset, max_len,
        )?;
        let reply = ChunkReply::decode(&self.post_raw(ep, "chunk", &q.encode()?).await?)?;
        if reply.status != OpStatus::Ok {
            anyhow::bail!("chunk query rejected ({:?})", reply.status);
        }
        Ok(reply)
    }

    pub(crate) async fn download_sliced(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        spec: ChunkFetch,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let max_slice = u32::try_from(SPLIT_TRANSFER_CHUNK).unwrap_or(6_144);
        let mut out = Zeroizing::new(Vec::new());
        for index in 0..spec.chunk_count {
            let mut offset = 0u32;
            loop {
                let rep = self
                    .post_chunk_once(
                        ep,
                        identity,
                        spec.box_id,
                        spec.kind,
                        spec.target,
                        spec.object_id,
                        index,
                        offset,
                        max_slice,
                    )
                    .await?;
                if out.len().saturating_add(rep.data.len()) > spec.max_total_bytes {
                    anyhow::bail!("downloaded object exceeds limit");
                }
                out.extend_from_slice(&rep.data);
                let slice_u32 =
                    u32::try_from(rep.data.len()).map_err(|_| anyhow!("slice overflow"))?;
                offset = offset.saturating_add(slice_u32);
                if rep.data.is_empty() || offset >= rep.total_len {
                    break;
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ChunkFetch {
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub target: ChunkTarget,
    pub object_id: [u8; 32],
    pub chunk_count: u32,
    pub max_total_bytes: usize,
}
