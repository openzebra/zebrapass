//! High-level PQ TLS 1.3 client performing 1.5-RTT Git-like frontier
//! reconciliation for personal and shared vaults with `VK`-bound envelopes
//! (preventing post-revocation `SignedHead` decryption) and automatic failover.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use kdf::zsync_vk_envelope_key;
use local::SyncIdentity;
use secret::Secret;
use session::{DeviceCert, Revocation};
use sha2::{Digest, Sha256};
use syncwire::encode_cert;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::auth::sign_frontier;
use crate::client_personal::{PersonalPushCtx, decode_pulled_personal};
use crate::client_shared::wraps_tag;
use crate::limits::{IO_TIMEOUT, MAX_SMALL_FRAME, MAX_WIRE_FRAME};
use crate::tls::{Endpoint, client_config, connect_tls};
use crate::wire::{
    HeadVer, RecordVer, RepoFrontier, RepoKind, StorageId, StreamRole, SyncDelta, TAG_ACK,
    TAG_DELTA, TAG_DIFF, TAG_FRONTIER, Wanted, read_wire, write_wire,
};
use crate::wire_codec::{decode_diff, encode_delta, encode_frontier};

/// Decrypted personal vault snapshot `(vault_bytes, head_meta_plain, head_epoch)`.
pub type DecryptedSnapshot = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, u64);

/// Local personal vault state offered during reconciliation.
#[derive(Debug)]
pub struct PersonalStateInput<'a> {
    pub vk: Option<&'a Secret<[u8; 32]>>,
    pub master_seed: Option<&'a [u8; 64]>,
    pub master_grant: Option<&'a [u8]>,
    pub vault_bytes: &'a [u8],
    pub head_meta_plain: &'a [u8],
    pub generation: u64,
    /// Monotonic head epoch for wrap/VK changes (`0` falls back to `generation`).
    pub head_epoch: u64,
    /// `(record_id, revision, origin_device, raw_frame_bytes)`
    pub records: &'a [(u32, u64, [u8; 16], Vec<u8>)],
    pub revocations: &'a [Revocation],
    /// `(generation, target_device, hybrid_grant_blob)`
    pub rekeys: &'a [(u64, [u8; 16], Vec<u8>)],
    pub push_head_always: bool,
}

/// Verified state pulled from the server for a personal vault.
#[derive(Debug)]
pub struct PulledPersonal {
    pub snapshot: Option<DecryptedSnapshot>,
    pub master_grant: Option<Vec<u8>>,
    pub adopted_vk: Option<(u64, Secret<[u8; 32]>)>,
    pub head_epoch: u64,
    pub frames: Vec<Zeroizing<Vec<u8>>>,
    pub rekeys: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub revocations: Vec<Revocation>,
    pub certs: Vec<DeviceCert>,
    pub pushed_records: usize,
    pub pushed_head: bool,
}

/// Unified PQ TLS 1.3 sync & relay client.
#[derive(Debug)]
pub struct ZebraClient {
    endpoints: Vec<Endpoint>,
    tls_cfg: Arc<rustls::ClientConfig>,
    preferred: AtomicUsize,
}

impl ZebraClient {
    /// Construct a client over `1..=8` endpoints (`host[:port]`).
    ///
    /// # Errors
    ///
    /// Empty endpoint list, invalid endpoint, or TLS root config failure.
    pub fn new(
        servers: &[String],
        extra_roots_pem: Option<&[u8]>,
        allow_private: bool,
    ) -> anyhow::Result<Self> {
        if servers.is_empty() {
            anyhow::bail!("at least one sync server is required");
        }
        let mut endpoints = Vec::with_capacity(servers.len());
        for raw in servers {
            let ep = Endpoint::parse(raw, allow_private)?;
            if !endpoints.contains(&ep) {
                endpoints.push(ep);
            }
        }
        let tls_cfg = client_config(extra_roots_pem)?;
        Ok(Self {
            endpoints,
            tls_cfg,
            preferred: AtomicUsize::new(0),
        })
    }

    /// Configured server endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// TLS configuration used for client connections.
    #[must_use]
    pub const fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        &self.tls_cfg
    }

    /// Preferred endpoint (most recently reachable).
    #[must_use]
    pub fn preferred_endpoint(&self) -> Option<&Endpoint> {
        let idx = self.preferred.load(Ordering::Relaxed);
        self.endpoints.get(idx).or_else(|| self.endpoints.first())
    }

    /// Execute one authenticated 1.5-RTT frontier RPC across endpoints with failover.
    ///
    /// # Errors
    ///
    /// Encoding errors, unreachable endpoints, or invalid server responses.
    pub async fn run_rpc<F>(
        &self,
        frontier: &RepoFrontier,
        build_push: F,
    ) -> anyhow::Result<(SyncDelta, Wanted, Option<u64>, usize)>
    where
        F: Fn(&SyncDelta, &Wanted) -> anyhow::Result<SyncDelta> + Send + Sync,
    {
        let start = self.preferred.load(Ordering::Relaxed) % self.endpoints.len();
        let req_bytes = encode_frontier(frontier)?;
        let mut last_err = None;
        for offset in 0..self.endpoints.len() {
            let idx = (start + offset) % self.endpoints.len();
            let Some(ep) = self.endpoints.get(idx) else {
                continue;
            };
            match self.rpc_once(ep, &req_bytes, &build_push).await {
                Ok(res) => {
                    self.preferred.store(idx, Ordering::Relaxed);
                    return Ok(res);
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no sync servers reachable")))
    }

    async fn rpc_once<F>(
        &self,
        ep: &Endpoint,
        req_bytes: &[u8],
        build_push: &F,
    ) -> anyhow::Result<(SyncDelta, Wanted, Option<u64>, usize)>
    where
        F: Fn(&SyncDelta, &Wanted) -> anyhow::Result<SyncDelta> + Send + Sync,
    {
        let (mut tls, _) = connect_tls(ep, &self.tls_cfg).await?;
        timeout(IO_TIMEOUT, tls.write_all(&[StreamRole::ClientRpc as u8])).await??;
        timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_FRONTIER, req_bytes)).await??;
        let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await??;
        if tag != TAG_DIFF {
            anyhow::bail!("unexpected server reply");
        }
        let (pull, wanted) = decode_diff(&body)?;
        let push = build_push(&pull, &wanted)?;
        let mut pushed_head = None;
        let mut pushed_records = 0usize;
        if !push.is_empty() {
            pushed_head = push.head.as_ref().map(|h| h.ver.generation);
            pushed_records = push.records.len();
            let enc = encode_delta(&push)?;
            timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_DELTA, &enc)).await??;
            let (ack, _) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await??;
            if ack != TAG_ACK {
                anyhow::bail!("server rejected push delta");
            }
        }
        Ok((pull, wanted, pushed_head, pushed_records))
    }

    /// Reconcile a personal vault bidirectionally with the server cluster.
    ///
    /// # Errors
    ///
    /// Missing personal anchor/cert, unreachable servers, or verification failure.
    pub async fn reconcile_personal(
        &self,
        identity: &SyncIdentity,
        input: PersonalStateInput<'_>,
    ) -> anyhow::Result<PulledPersonal> {
        let anchor = identity
            .personal_anchor()
            .ok_or_else(|| anyhow!("personal anchor missing from sync identity"))?;
        let anchor_wire = anchor.encode()?;
        let sid = anchor.storage_id()?;
        let own_cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("missing local device certificate"))?;
        let env_key = input
            .vk
            .map(|vk| zsync_vk_envelope_key(vk.expose(), &sid))
            .transpose()?;
        let base_epoch = input.head_epoch.max(input.generation).max(1);
        let frontier_head_gen = if input.push_head_always {
            base_epoch
        } else {
            input.head_epoch
        };
        let head_ver = HeadVer {
            generation: frontier_head_gen,
            commit_tag: wraps_tag(input.vault_bytes)?,
            origin_device: own_cert.device_id,
        };
        let mut records_ver = Vec::new();
        if env_key.is_some() {
            records_ver.reserve(input.records.len());
            for (id, rev, org, raw) in input.records {
                records_ver.push(RecordVer {
                    revision: *rev,
                    origin_device: *org,
                    frame_hash: Sha256::digest(raw).into(),
                    record_id: *id,
                });
            }
        }
        let mut frontier = RepoFrontier {
            kind: RepoKind::Personal,
            storage_id: sid,
            personal_anchor: Some(anchor_wire.clone()),
            root_vk: Some(Box::new(*identity.root_vk())),
            shared_proof: None,
            auth: None,
            certs: Vec::new(),
            head: (!input.vault_bytes.is_empty() && env_key.is_some()).then_some(head_ver),
            records: records_ver,
            rev_count: u32::try_from(input.revocations.len()).unwrap_or(u32::MAX),
            member_count: 0,
            dev_key_count: 0,
        };
        let own_cert_wire = encode_cert(own_cert)?;
        sign_frontier(&identity.sign_key(), &mut frontier, own_cert_wire.clone())?;
        let sign_key = identity.sign_key();
        let push_ctx = PersonalPushCtx {
            identity,
            sign_key: &sign_key,
            env_key: env_key.as_ref(),
            anchor_wire: &anchor_wire,
            sid: &sid,
            own_device_id: own_cert.device_id,
            own_cert_wire: &own_cert_wire,
            head_ver,
            head_epoch: base_epoch,
            input: &input,
        };
        let (pull, _wanted, pushed_head, pushed_records) = self
            .run_rpc(&frontier, |pull, wanted| push_ctx.build(pull, wanted))
            .await?;

        decode_pulled_personal(
            env_key.as_ref(),
            input.master_seed,
            &sid,
            identity,
            &pull,
            (pushed_head, input.head_epoch),
            pushed_records,
        )
    }
}

/// Self-certifying personal [`StorageId`] derived from this identity's anchor.
#[must_use]
pub fn personal_storage_id(identity: &SyncIdentity) -> Option<StorageId> {
    identity.personal_storage_id()
}

/// Deterministic high-bit record slot (`0x8000_0000..=0xFFFF_FFFF`) reserved per
/// device for its outer-sealed `PersonalDeviceEntry`.
#[must_use]
pub fn device_announce_record_id(device_id: &[u8; 16]) -> u32 {
    let prefix = device_id
        .get(..4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(1, u32::from_be_bytes);
    0x8000_0000 | (prefix & 0x7FFF_FFFF).max(1)
}
