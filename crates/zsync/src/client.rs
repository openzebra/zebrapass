//! High-level PQ TLS 1.3 client performing 1.5-RTT Git-like frontier
//! reconciliation for personal and shared vaults with automatic failover
//! across `[ru.zebra.sh, eu.zebra.sh, zh.zebra.sh]` or custom servers.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use kdf::personal_envelope_key;
use local::SyncIdentity;
use secret::Secret;
use session::{DeviceCert, Revocation};
use sha2::{Digest, Sha256};
use syncwire::{decode_cert, decode_revocation, encode_cert, encode_revocation};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::auth::{
    EnvelopePurpose, RecordMeta, now_ms, open_blob, seal_blob, sign_frontier, sign_head,
    sign_record, sign_rekey,
};
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
    pub vault_bytes: &'a [u8],
    pub head_meta_plain: &'a [u8],
    pub generation: u64,
    /// Monotonic head epoch for wrap/VK changes (`0` falls back to `generation`).
    pub head_epoch: u64,
    /// `(record_id, revision, origin_device, raw_frame_bytes)`
    pub records: &'a [(u32, u64, [u8; 16], Vec<u8>)],
    pub revocations: &'a [Revocation],
    /// `(generation, target_device, grant_blob)`
    pub rekeys: &'a [(u64, [u8; 16], Vec<u8>)],
    pub push_head_always: bool,
}

/// Verified state pulled from the server for a personal vault.
#[derive(Debug)]
pub struct PulledPersonal {
    pub snapshot: Option<DecryptedSnapshot>,
    pub head_epoch: u64,
    pub frames: Vec<Zeroizing<Vec<u8>>>,
    pub rekeys: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub revocations: Vec<Revocation>,
    pub certs: Vec<DeviceCert>,
    pub pushed_head: bool,
    pub pushed_records: usize,
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
        allow_loopback: bool,
    ) -> anyhow::Result<Self> {
        if servers.is_empty() {
            anyhow::bail!("at least one sync server is required");
        }
        let mut endpoints = Vec::with_capacity(servers.len());
        for raw in servers {
            let ep = Endpoint::parse(raw, allow_loopback)?;
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

    /// Execute one authenticated 1.5-RTT frontier RPC across endpoints with
    /// failover, returning `(pull_delta, wanted, pushed_head, pushed_records)`.
    ///
    /// # Errors
    ///
    /// Encoding errors, unreachable endpoints, or invalid server responses.
    pub async fn run_rpc<F>(
        &self,
        frontier: &RepoFrontier,
        build_push: F,
    ) -> anyhow::Result<(SyncDelta, Wanted, bool, usize)>
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
    ) -> anyhow::Result<(SyncDelta, Wanted, bool, usize)>
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
        let mut pushed_head = false;
        let mut pushed_records = 0usize;
        if !push.is_empty() {
            pushed_head = push.head.is_some();
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
    /// Normal record edits push only changed `RecordCommit` frames; `SignedHead`
    /// is pushed only when the server lacks it or when wraps rotated.
    ///
    /// # Errors
    ///
    /// Missing account gate/cert, unreachable servers, or verification failure.
    pub async fn reconcile_personal(
        &self,
        identity: &SyncIdentity,
        input: PersonalStateInput<'_>,
    ) -> anyhow::Result<PulledPersonal> {
        let gate = identity
            .account_gate()
            .ok_or_else(|| anyhow!("account gate missing from sync identity"))?;
        let own_cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("missing local device certificate"))?;
        let sid = own_cert.client_id;
        let env_key = personal_envelope_key(gate.expose(), &sid)?;
        let head_epoch = if input.head_epoch > 0 {
            input.head_epoch
        } else {
            input.generation
        };
        let head_ver = HeadVer {
            generation: head_epoch,
            commit_tag: wraps_tag(input.vault_bytes)?,
            origin_device: own_cert.device_id,
        };
        let records_ver: Vec<RecordVer> = input
            .records
            .iter()
            .map(|(id, rev, org, raw)| RecordVer {
                revision: *rev,
                origin_device: *org,
                frame_hash: Sha256::digest(raw).into(),
                record_id: *id,
            })
            .collect();
        let mut frontier = RepoFrontier {
            kind: RepoKind::Personal,
            storage_id: sid,
            root_vk: Some(Box::new(*identity.root_vk())),
            shared_init: None,
            auth: None,
            certs: Vec::new(),
            rev_count: u32::try_from(input.revocations.len()).unwrap_or(u32::MAX),
            member_count: 0,
            head: (!input.vault_bytes.is_empty()).then_some(head_ver),
            records: records_ver,
        };
        let own_cert_wire = encode_cert(own_cert)?;
        sign_frontier(&identity.sign_key(), &mut frontier, own_cert_wire.clone())?;
        let sign_key = identity.sign_key();
        let push_ctx = PersonalPushCtx {
            identity,
            sign_key: &sign_key,
            env_key: &env_key,
            sid: &sid,
            own_device_id: own_cert.device_id,
            own_cert_wire: &own_cert_wire,
            head_ver,
            head_epoch,
            input: &input,
        };
        let (pull, _wanted, pushed_head, pushed_records) = self
            .run_rpc(&frontier, |pull, wanted| push_ctx.build(pull, wanted))
            .await?;

        decode_pulled_personal(&env_key, &sid, identity, &pull, pushed_head, pushed_records)
    }
}

struct PersonalPushCtx<'a> {
    identity: &'a SyncIdentity,
    sign_key: &'a session::DeviceSignKey,
    env_key: &'a Secret<[u8; 32]>,
    sid: &'a StorageId,
    own_device_id: [u8; 16],
    own_cert_wire: &'a [u8],
    head_ver: HeadVer,
    head_epoch: u64,
    input: &'a PersonalStateInput<'a>,
}

impl PersonalPushCtx<'_> {
    fn build(&self, pull: &SyncDelta, wanted: &Wanted) -> anyhow::Result<SyncDelta> {
        let mut push = SyncDelta::empty(RepoKind::Personal, *self.sid);
        push.root_vk = Some(Box::new(*self.identity.root_vk()));
        if !pull
            .certs
            .iter()
            .any(|c| c.as_slice() == self.own_cert_wire)
        {
            push.certs.push(self.own_cert_wire.to_vec());
        }
        if wanted.need_revs {
            for rev in self.input.revocations {
                push.revocations.push(encode_revocation(rev)?);
            }
        }
        if (wanted.need_head || self.input.push_head_always) && !self.input.vault_bytes.is_empty() {
            let epoch = pull.head.as_ref().map_or(self.head_epoch, |h| {
                self.head_epoch.max(h.ver.generation.saturating_add(1))
            });
            let head_ver = HeadVer {
                generation: epoch,
                ..self.head_ver
            };
            let head_env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::PersonalHead,
                epoch,
                self.input.head_meta_plain,
            )?;
            let snap_env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::PersonalSnapshot,
                epoch,
                self.input.vault_bytes,
            )?;
            push.head = Some(sign_head(
                self.sign_key,
                RepoKind::Personal,
                self.sid,
                head_ver,
                head_env,
                snap_env,
            )?);
        }
        for (rgen, target, blob) in self.input.rekeys {
            let env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::PersonalRekey,
                *rgen,
                blob,
            )?;
            push.rekeys.push(sign_rekey(
                self.sign_key,
                RepoKind::Personal,
                self.sid,
                *rgen,
                self.own_device_id,
                *target,
                env,
            )?);
        }
        for id in &wanted.record_ids {
            if let Some((_, rev, org, raw)) = self.input.records.iter().find(|r| r.0 == *id) {
                let env = seal_blob(
                    self.env_key,
                    self.sid,
                    EnvelopePurpose::PersonalFrame,
                    *rev,
                    raw,
                )?;
                let meta = RecordMeta {
                    storage_id: self.sid,
                    revision: *rev,
                    key_generation: self.input.generation,
                    record_id: *id,
                    origin_device: *org,
                    signer_device: self.own_device_id,
                    kind: RepoKind::Personal,
                };
                push.records.push(sign_record(self.sign_key, meta, env)?);
            }
        }
        Ok(push)
    }
}

fn decode_pulled_personal(
    env_key: &Secret<[u8; 32]>,
    sid: &StorageId,
    identity: &SyncIdentity,
    pull: &SyncDelta,
    pushed_head: bool,
    pushed_records: usize,
) -> anyhow::Result<PulledPersonal> {
    let now = now_ms();
    let mut certs = Vec::with_capacity(pull.certs.len());
    for raw in &pull.certs {
        if let Ok(c) = decode_cert(raw)
            && c.verify(identity.root_vk(), now).is_ok()
        {
            certs.push(c);
        }
    }
    let mut revocations = Vec::with_capacity(pull.revocations.len());
    for raw in &pull.revocations {
        if let Ok(r) = decode_revocation(raw)
            && r.verify(identity.root_vk(), now).is_ok()
        {
            revocations.push(r);
        }
    }
    let head_epoch = pull.head.as_ref().map_or(0, |h| h.ver.generation);
    let snapshot = match &pull.head {
        Some(h) => {
            let (_, head_plain) =
                open_blob(env_key, sid, EnvelopePurpose::PersonalHead, &h.head_meta)?;
            let (_, snap_plain) = open_blob(
                env_key,
                sid,
                EnvelopePurpose::PersonalSnapshot,
                &h.snapshot_env,
            )?;
            Some((snap_plain, head_plain, h.ver.generation))
        }
        None => None,
    };
    let mut frames = Vec::with_capacity(pull.records.len());
    for rec in &pull.records {
        let (_, plain) = open_blob(env_key, sid, EnvelopePurpose::PersonalFrame, &rec.envelope)?;
        frames.push(plain);
    }
    let own_dev = identity.device_id().unwrap_or([0u8; 16]);
    let mut rekeys = Vec::new();
    for rk in &pull.rekeys {
        if rk.target_device == own_dev || rk.target_device == [0u8; 16] {
            let (_, plain) = open_blob(env_key, sid, EnvelopePurpose::PersonalRekey, &rk.envelope)?;
            rekeys.push((rk.generation, plain));
        }
    }
    Ok(PulledPersonal {
        snapshot,
        head_epoch,
        frames,
        rekeys,
        revocations,
        certs,
        pushed_head,
        pushed_records,
    })
}

/// Canonical personal [`StorageId`] stored on this identity's primary cert.
#[must_use]
pub fn personal_storage_id(identity: &SyncIdentity) -> Option<StorageId> {
    identity.devices().first().map(|c| c.client_id)
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
