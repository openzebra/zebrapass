//! Outer Cascade (`0xA005`) sealing and server-independent `ML-DSA-65`
//! commit signatures for `zsync`.

use anyhow::anyhow;
use frame::{ALG_CASCADE, FrameMeta, KIND_REVISION, open, parse, seal};
use pq::{SYNC_CTX, SYNC_SIG_LEN, SYNC_VK_LEN, sync_sign, sync_verify};
use secret::{Secret, ct_eq};
use session::{DeviceSignKey, frame_parts};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{
    FrontierAuth, HeadVer, RecordCommit, RecordVer, RepoFrontier, RepoKind, SignedHead,
    SignedRekey, StorageId, WatchSub,
};

const DOMAIN_ENVELOPE_AD: &[u8] = b"brby/v3/zsync-ad";
const DOMAIN_HEAD: &[u8] = b"brby/v3/zsync-head-v2";
const DOMAIN_RECORD: &[u8] = b"brby/v3/zsync-record";
const DOMAIN_REKEY: &[u8] = b"brby/v3/zsync-rekey";
const DOMAIN_WATCH: &[u8] = b"brby/v3/zsync-watch-v2";
const DOMAIN_FRONTIER: &[u8] = b"brby/v3/zsync-frontier";

/// Outer-envelope payload purpose byte bound into the Cascade AD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnvelopePurpose {
    PersonalHead = 1,
    PersonalSnapshot = 2,
    PersonalFrame = 3,
    SharedHead = 5,
    SharedSnapshot = 6,
    SharedFrame = 7,
}

fn ad_origin(storage_id: &StorageId, purpose: EnvelopePurpose) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN_ENVELOPE_AD)
        .chain_update([purpose as u8])
        .chain_update(storage_id)
        .finalize()
        .into();
    let mut origin = [0u8; 16];
    if let Some((head, _)) = digest.split_at_checked(16) {
        origin.copy_from_slice(head);
    }
    origin
}

/// Seal `plaintext` into a PQ Cascade (`0xA005`) outer envelope bound to `(storage_id, purpose, seq)`.
pub fn seal_blob(
    key: &Secret<[u8; 32]>,
    storage_id: &StorageId,
    purpose: EnvelopePurpose,
    seq: u64,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: u32::from(purpose as u8),
        revision: seq,
        origin_device: ad_origin(storage_id, purpose),
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    seal(key, &meta, plaintext)
}

/// Verify AD metadata and open an outer Cascade (`0xA005`) envelope.
pub fn open_blob(
    key: &Secret<[u8; 32]>,
    storage_id: &StorageId,
    purpose: EnvelopePurpose,
    ciphertext: &[u8],
) -> anyhow::Result<(u64, Zeroizing<Vec<u8>>)> {
    let hdr = parse(ciphertext)?;
    if hdr.alg != ALG_CASCADE
        || hdr.kind != KIND_REVISION
        || hdr.record_id != u32::from(purpose as u8)
        || !ct_eq(&hdr.origin_device, &ad_origin(storage_id, purpose))
    {
        anyhow::bail!("envelope authentication failed");
    }
    let plain = open(key, ciphertext)?;
    Ok((hdr.revision, Zeroizing::new(plain.expose().clone())))
}

fn fixed_sig(sig: Vec<u8>) -> anyhow::Result<Box<[u8; SYNC_SIG_LEN]>> {
    sig.try_into()
        .map(Box::new)
        .map_err(|_| anyhow!("unexpected signature length"))
}

fn master_grant_digest(grant: Option<&[u8]>) -> [u8; 33] {
    let mut out = [0u8; 33];
    if let Some(bytes) = grant {
        out[0] = 1;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some((_, rest)) = out.split_at_mut_checked(1) {
            rest.copy_from_slice(&digest);
        }
    }
    out
}

fn head_msg(
    kind: RepoKind,
    storage_id: &StorageId,
    ver: &HeadVer,
    head_hash: &[u8; 32],
    snap_hash: &[u8; 32],
    grant_digest: &[u8; 33],
) -> anyhow::Result<Vec<u8>> {
    frame_parts(&[
        DOMAIN_HEAD,
        &[kind as u8],
        storage_id,
        &ver.generation.to_be_bytes(),
        &ver.commit_tag,
        &ver.origin_device,
        head_hash,
        snap_hash,
        grant_digest,
    ])
}

/// Sign a [`SignedHead`] using `key`, binding `master_grant` into the signed digest.
///
/// # Errors
///
/// Signing failure.
pub fn sign_head(
    key: &DeviceSignKey,
    kind: RepoKind,
    storage_id: &StorageId,
    ver: HeadVer,
    head_meta: Vec<u8>,
    snapshot_env: Vec<u8>,
    master_grant: Option<Vec<u8>>,
) -> anyhow::Result<SignedHead> {
    let head_hash: [u8; 32] = Sha256::digest(&head_meta).into();
    let snap_hash: [u8; 32] = Sha256::digest(&snapshot_env).into();
    let grant_digest = master_grant_digest(master_grant.as_deref());
    let msg = head_msg(
        kind,
        storage_id,
        &ver,
        &head_hash,
        &snap_hash,
        &grant_digest,
    )?;
    let sig = fixed_sig(sync_sign(key.seed(), SYNC_CTX, &msg)?)?;
    Ok(SignedHead {
        ver,
        head_meta,
        snapshot_env,
        master_grant,
        signature: sig,
    })
}

/// Verify a [`SignedHead`] against `device_vk`.
///
/// # Errors
///
/// Bad signature.
pub fn verify_head(
    device_vk: &[u8; SYNC_VK_LEN],
    kind: RepoKind,
    storage_id: &StorageId,
    head: &SignedHead,
) -> anyhow::Result<()> {
    let head_hash: [u8; 32] = Sha256::digest(&head.head_meta).into();
    let snap_hash: [u8; 32] = Sha256::digest(&head.snapshot_env).into();
    let grant_digest = master_grant_digest(head.master_grant.as_deref());
    let msg = head_msg(
        kind,
        storage_id,
        &head.ver,
        &head_hash,
        &snap_hash,
        &grant_digest,
    )?;
    sync_verify(device_vk, SYNC_CTX, &msg, &*head.signature)
}

fn record_msg(
    kind: RepoKind,
    storage_id: &StorageId,
    ver: &RecordVer,
    key_generation: u64,
    signer_device: &[u8; 16],
) -> anyhow::Result<Vec<u8>> {
    frame_parts(&[
        DOMAIN_RECORD,
        &[kind as u8],
        storage_id,
        &ver.record_id.to_be_bytes(),
        &ver.revision.to_be_bytes(),
        &ver.origin_device,
        &ver.frame_hash,
        &key_generation.to_be_bytes(),
        signer_device,
    ])
}

/// Metadata binding one [`RecordCommit`] to a vault repository and revision.
#[derive(Clone, Copy, Debug)]
pub struct RecordMeta<'a> {
    pub storage_id: &'a StorageId,
    pub revision: u64,
    pub key_generation: u64,
    pub record_id: u32,
    pub origin_device: [u8; 16],
    pub signer_device: [u8; 16],
    pub kind: RepoKind,
}

/// Sign a [`RecordCommit`] covering `(kind, storage_id, ver, key_generation, signer_device)`.
///
/// # Errors
///
/// Signing failure.
pub fn sign_record(
    key: &DeviceSignKey,
    meta: RecordMeta<'_>,
    envelope: Vec<u8>,
) -> anyhow::Result<RecordCommit> {
    let frame_hash: [u8; 32] = Sha256::digest(&envelope).into();
    let ver = RecordVer {
        revision: meta.revision,
        origin_device: meta.origin_device,
        frame_hash,
        record_id: meta.record_id,
    };
    let msg = record_msg(
        meta.kind,
        meta.storage_id,
        &ver,
        meta.key_generation,
        &meta.signer_device,
    )?;
    let sig = fixed_sig(sync_sign(key.seed(), SYNC_CTX, &msg)?)?;
    Ok(RecordCommit {
        ver,
        key_generation: meta.key_generation,
        envelope,
        signature: sig,
        signer_device: meta.signer_device,
    })
}

/// Verify `commit.envelope` hash and `ML-DSA-65` signature against `device_vk`.
///
/// # Errors
///
/// Hash mismatch or bad signature.
pub fn verify_record(
    device_vk: &[u8; SYNC_VK_LEN],
    kind: RepoKind,
    storage_id: &StorageId,
    commit: &RecordCommit,
) -> anyhow::Result<()> {
    let actual_hash: [u8; 32] = Sha256::digest(&commit.envelope).into();
    if !ct_eq(&actual_hash, &commit.ver.frame_hash) {
        anyhow::bail!("record commit hash mismatch");
    }
    let msg = record_msg(
        kind,
        storage_id,
        &commit.ver,
        commit.key_generation,
        &commit.signer_device,
    )?;
    sync_verify(device_vk, SYNC_CTX, &msg, &*commit.signature)
}

fn rekey_msg(
    kind: RepoKind,
    storage_id: &StorageId,
    generation: u64,
    origin_device: &[u8; 16],
    target_device: &[u8; 16],
    env_hash: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    frame_parts(&[
        DOMAIN_REKEY,
        &[kind as u8],
        storage_id,
        &generation.to_be_bytes(),
        origin_device,
        target_device,
        env_hash,
    ])
}

/// Sign a [`SignedRekey`].
///
/// # Errors
///
/// Signing failure.
pub fn sign_rekey(
    key: &DeviceSignKey,
    kind: RepoKind,
    storage_id: &StorageId,
    generation: u64,
    origin_device: [u8; 16],
    target_device: [u8; 16],
    envelope: Vec<u8>,
) -> anyhow::Result<SignedRekey> {
    let env_hash: [u8; 32] = Sha256::digest(&envelope).into();
    let msg = rekey_msg(
        kind,
        storage_id,
        generation,
        &origin_device,
        &target_device,
        &env_hash,
    )?;
    let sig = fixed_sig(sync_sign(key.seed(), SYNC_CTX, &msg)?)?;
    Ok(SignedRekey {
        generation,
        origin_device,
        target_device,
        envelope,
        signature: sig,
    })
}

/// Verify a [`SignedRekey`] against `device_vk`.
///
/// # Errors
///
/// Bad signature.
pub fn verify_rekey(
    device_vk: &[u8; SYNC_VK_LEN],
    kind: RepoKind,
    storage_id: &StorageId,
    rekey: &SignedRekey,
) -> anyhow::Result<()> {
    let env_hash: [u8; 32] = Sha256::digest(&rekey.envelope).into();
    let msg = rekey_msg(
        kind,
        storage_id,
        rekey.generation,
        &rekey.origin_device,
        &rekey.target_device,
        &env_hash,
    )?;
    sync_verify(device_vk, SYNC_CTX, &msg, &*rekey.signature)
}

fn watch_msg(w: &WatchSub) -> anyhow::Result<Vec<u8>> {
    let mut repo_buf = Vec::with_capacity(w.repos.len() * 65);
    for (kind, sid) in &w.repos {
        repo_buf.push(*kind as u8);
        repo_buf.extend_from_slice(sid);
    }
    frame_parts(&[
        DOMAIN_WATCH,
        &w.device_id,
        &w.timestamp_s.to_be_bytes(),
        &w.nonce,
        &repo_buf,
        &w.cert_wire,
    ])
}

/// Sign a [`WatchSub`] stream subscription.
///
/// # Errors
///
/// Entropy or signing failure.
pub fn sign_watch(
    key: &DeviceSignKey,
    device_id: [u8; 16],
    repos: Vec<(RepoKind, StorageId)>,
    cert_wire: Vec<u8>,
    personal_anchor: Option<Vec<u8>>,
    root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    shared_proofs: Vec<Vec<u8>>,
) -> anyhow::Result<WatchSub> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow!("os entropy failed"))?;
    let mut sub = WatchSub {
        timestamp_s: now_unix_secs(),
        device_id,
        nonce,
        repos,
        cert_wire,
        personal_anchor,
        root_vk,
        shared_proofs,
        signature: Box::new([0u8; SYNC_SIG_LEN]),
    };
    let msg = watch_msg(&sub)?;
    sub.signature = fixed_sig(sync_sign(key.seed(), SYNC_CTX, &msg)?)?;
    Ok(sub)
}

/// Verify a [`WatchSub`] signature against `device_vk`.
pub fn verify_watch(device_vk: &[u8; SYNC_VK_LEN], sub: &WatchSub) -> anyhow::Result<()> {
    let msg = watch_msg(sub)?;
    sync_verify(device_vk, SYNC_CTX, &msg, &*sub.signature)
}

fn frontier_msg(
    f: &RepoFrontier,
    ts: u64,
    nonce: &[u8; 16],
    cert_wire: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let head_bytes = f.head.map_or_else(Vec::new, |h| {
        let mut v = Vec::with_capacity(56);
        v.extend_from_slice(&h.generation.to_be_bytes());
        v.extend_from_slice(&h.commit_tag);
        v.extend_from_slice(&h.origin_device);
        v
    });
    let mut rec_bytes = Vec::with_capacity(f.records.len() * 60);
    for r in &f.records {
        rec_bytes.extend_from_slice(&r.record_id.to_be_bytes());
        rec_bytes.extend_from_slice(&r.revision.to_be_bytes());
        rec_bytes.extend_from_slice(&r.origin_device);
        rec_bytes.extend_from_slice(&r.frame_hash);
    }
    frame_parts(&[
        DOMAIN_FRONTIER,
        &[f.kind as u8],
        &f.storage_id,
        &ts.to_be_bytes(),
        nonce,
        cert_wire,
        &head_bytes,
        &rec_bytes,
    ])
}

/// Sign a [`RepoFrontier`] request for authenticated server queries.
pub fn sign_frontier(
    key: &DeviceSignKey,
    f: &mut RepoFrontier,
    cert_wire: Vec<u8>,
) -> anyhow::Result<()> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow!("os entropy failed"))?;
    let ts = now_unix_secs();
    let msg = frontier_msg(f, ts, &nonce, &cert_wire)?;
    let sig = fixed_sig(sync_sign(key.seed(), SYNC_CTX, &msg)?)?;
    f.auth = Some(FrontierAuth {
        timestamp_s: ts,
        nonce,
        cert_wire,
        signature: sig,
    });
    Ok(())
}

/// Verify a signed [`RepoFrontier`] against `device_vk`.
pub fn verify_frontier(device_vk: &[u8; SYNC_VK_LEN], f: &RepoFrontier) -> anyhow::Result<()> {
    let auth = f
        .auth
        .as_ref()
        .ok_or_else(|| anyhow!("missing frontier auth"))?;
    let msg = frontier_msg(f, auth.timestamp_s, &auth.nonce, &auth.cert_wire)?;
    sync_verify(device_vk, SYNC_CTX, &msg, &*auth.signature)
}

/// Current unix timestamp in milliseconds.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Current unix timestamp in seconds.
#[must_use]
pub fn now_unix_secs() -> u64 {
    now_ms() / 1000
}
