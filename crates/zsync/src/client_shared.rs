//! Shared vault reconciliation over `ZebraClient`.

use anyhow::anyhow;
use container::WrapEntry;
use kdf::{shared_envelope_key, shared_storage_id};
use local::SyncIdentity;
use memberlog::Entry;
use secret::Secret;
use session::{DeviceCert, Revocation, VaultFile};
use sha2::{Digest, Sha256};
use syncwire::{decode_cert, decode_revocation, decode_snapshot, encode_cert};
use zeroize::Zeroizing;

use crate::auth::{
    EnvelopePurpose, RecordMeta, open_blob, seal_blob, sign_frontier, sign_head, sign_record,
    sign_rekey,
};
use crate::client::ZebraClient;
use crate::wire::{HeadVer, RecordVer, RepoFrontier, RepoKind, StorageId, SyncDelta, Wanted};

/// Local shared vault state offered during reconciliation.
#[derive(Debug)]
pub struct SharedStateInput<'a> {
    pub shared_seed: &'a [u8; 64],
    pub vault_id: [u8; 16],
    pub anchor: [u8; 32],
    pub member_entries: &'a [Vec<u8>],
    pub snapshot_bytes: Option<&'a [u8]>,
    pub generation: u64,
    /// Monotonic head epoch for membership/VK changes (`0` falls back to `generation`).
    pub head_epoch: u64,
    /// `(record_id, revision, origin_device, encoded_bundle)`
    pub bundles: &'a [(u32, u64, [u8; 16], Vec<u8>)],
    pub rekeys: &'a [(u64, Vec<u8>)],
}

/// Verified state pulled from the server for a shared vault.
#[derive(Debug)]
pub struct PulledShared {
    pub member_entries: Vec<Entry>,
    pub snapshot: Option<(Zeroizing<Vec<u8>>, u64)>,
    pub head_epoch: u64,
    pub bundles: Vec<Zeroizing<Vec<u8>>>,
    pub rekeys: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub revocations: Vec<Revocation>,
    pub certs: Vec<DeviceCert>,
}

fn hash_wraps(entries: &[WrapEntry<'_>], domain: &[u8], include_chip: bool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for entry in entries {
        match entry {
            WrapEntry::Password(pw) => {
                h.update(b"pw");
                h.update(pw.kid);
                h.update(pw.nonce);
                h.update(pw.ct);
                h.update(pw.tag);
            }
            WrapEntry::HumanPassword(ph) => {
                h.update(b"ph");
                h.update(ph.kid);
                h.update(ph.kdf.m_kib.to_be_bytes());
                h.update(ph.kdf.t.to_be_bytes());
                h.update(ph.kdf.p.to_be_bytes());
                h.update(ph.salt);
                h.update(ph.nonce);
                h.update(ph.ct);
                h.update(ph.tag);
            }
            WrapEntry::Prf(prf) => {
                h.update(b"prf");
                h.update(prf.id);
                h.update(prf.cred_id);
                h.update(prf.salt);
                h.update(prf.nonce);
                h.update(prf.ct);
                h.update(prf.tag);
            }
            WrapEntry::Chip(chip) if include_chip => {
                h.update(b"chip");
                h.update(chip.id);
                h.update(chip.kem_ct);
                h.update(chip.eph_pub);
                h.update(chip.nonce);
                h.update(chip.ct);
                h.update(chip.tag);
            }
            WrapEntry::Chip(_) => {}
        }
    }
    h.finalize().into()
}

/// Deterministic digest of wrap entries in a personal vault file.
///
/// Unchanged across normal record edits, so only wrap/VK changes trigger a
/// `SignedHead` snapshot re-upload.
///
/// # Errors
///
/// Unparseable vault file (returns empty digest when `bytes` is empty).
pub fn wraps_tag(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes.is_empty() {
        return Ok([0u8; 32]);
    }
    let file = VaultFile::new(bytes.to_vec());
    let parsed = file.parse()?;
    let has_non_chip = parsed
        .entries
        .iter()
        .any(|e| !matches!(e, WrapEntry::Chip(_)));
    Ok(hash_wraps(
        &parsed.entries,
        b"brby/v3/wraps-tag",
        !has_non_chip,
    ))
}

/// Deterministic digest of all wrap entries inside an encoded shared snapshot.
///
/// # Errors
///
/// Malformed snapshot container.
pub fn shared_wraps_tag(encoded_snapshot: &[u8]) -> anyhow::Result<[u8; 32]> {
    if encoded_snapshot.is_empty() {
        return Ok([0u8; 32]);
    }
    let (vault_bytes, _) = decode_snapshot(encoded_snapshot.to_vec())?;
    let file = VaultFile::new(vault_bytes);
    let parsed = file.parse()?;
    Ok(hash_wraps(
        &parsed.entries,
        b"brby/v3/shared-wraps-tag",
        true,
    ))
}

impl ZebraClient {
    /// Reconcile a shared vault bidirectionally with the server cluster.
    ///
    /// # Errors
    ///
    /// Missing cert, unreachable servers, or verification/decryption failure.
    pub async fn reconcile_shared(
        &self,
        identity: &SyncIdentity,
        input: SharedStateInput<'_>,
    ) -> anyhow::Result<PulledShared> {
        let own_cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow!("missing local device certificate"))?;
        let sid = shared_storage_id(input.shared_seed, &input.vault_id)?;
        let env_key = shared_envelope_key(input.shared_seed, &sid)?;
        let head_epoch = if input.head_epoch > 0 {
            input.head_epoch
        } else {
            input.generation
        };
        let head_ver = input
            .snapshot_bytes
            .map(|bytes| {
                Ok::<HeadVer, anyhow::Error>(HeadVer {
                    generation: head_epoch,
                    commit_tag: shared_wraps_tag(bytes)?,
                    origin_device: own_cert.device_id,
                })
            })
            .transpose()?;
        let records_ver: Vec<RecordVer> = input
            .bundles
            .iter()
            .map(|(id, rev, org, raw)| RecordVer {
                revision: *rev,
                origin_device: *org,
                frame_hash: Sha256::digest(raw).into(),
                record_id: *id,
            })
            .collect();
        let mut frontier = RepoFrontier {
            kind: RepoKind::Shared,
            storage_id: sid,
            root_vk: Some(Box::new(*identity.root_vk())),
            shared_init: Some((input.vault_id, input.anchor)),
            auth: None,
            certs: Vec::new(),
            rev_count: 0,
            member_count: u32::try_from(input.member_entries.len()).unwrap_or(u32::MAX),
            head: head_ver,
            records: records_ver,
        };
        let own_cert_wire = encode_cert(own_cert)?;
        sign_frontier(&identity.sign_key(), &mut frontier, own_cert_wire.clone())?;
        let sign_key = identity.sign_key();
        let push_ctx = SharedPushCtx {
            sign_key: &sign_key,
            env_key: &env_key,
            sid: &sid,
            own_device_id: own_cert.device_id,
            own_cert_wire: &own_cert_wire,
            head_ver,
            head_epoch,
            input: &input,
        };
        let (pull, _wanted, _, _) = self
            .run_rpc(&frontier, |pull, wanted| push_ctx.build(pull, wanted))
            .await?;

        decode_pulled_shared(&env_key, &sid, &pull)
    }
}

struct SharedPushCtx<'a> {
    sign_key: &'a session::DeviceSignKey,
    env_key: &'a Secret<[u8; 32]>,
    sid: &'a StorageId,
    own_device_id: [u8; 16],
    own_cert_wire: &'a [u8],
    head_ver: Option<HeadVer>,
    head_epoch: u64,
    input: &'a SharedStateInput<'a>,
}

impl SharedPushCtx<'_> {
    fn build(&self, pull: &SyncDelta, wanted: &Wanted) -> anyhow::Result<SyncDelta> {
        let mut push = SyncDelta::empty(RepoKind::Shared, *self.sid);
        push.shared_init = Some((self.input.vault_id, self.input.anchor));
        if !pull
            .certs
            .iter()
            .any(|c| c.as_slice() == self.own_cert_wire)
        {
            push.certs.push(self.own_cert_wire.to_vec());
        }
        if wanted.need_members {
            push.member_entries = self.input.member_entries.to_vec();
        }
        if wanted.need_head
            && let (Some(bytes), Some(hv)) = (self.input.snapshot_bytes, self.head_ver)
        {
            let head_env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::SharedHead,
                self.head_epoch,
                &self.input.vault_id,
            )?;
            let snap_env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::SharedSnapshot,
                self.head_epoch,
                bytes,
            )?;
            push.head = Some(sign_head(
                self.sign_key,
                RepoKind::Shared,
                self.sid,
                hv,
                head_env,
                snap_env,
            )?);
        }
        for (epoch, blob) in self.input.rekeys {
            let env = seal_blob(
                self.env_key,
                self.sid,
                EnvelopePurpose::SharedRekey,
                *epoch,
                blob,
            )?;
            push.rekeys.push(sign_rekey(
                self.sign_key,
                RepoKind::Shared,
                self.sid,
                *epoch,
                self.own_device_id,
                [0u8; 16],
                env,
            )?);
        }
        for id in &wanted.record_ids {
            if let Some((_, rev, org, raw)) = self.input.bundles.iter().find(|r| r.0 == *id) {
                let env = seal_blob(
                    self.env_key,
                    self.sid,
                    EnvelopePurpose::SharedFrame,
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
                    kind: RepoKind::Shared,
                };
                push.records.push(sign_record(self.sign_key, meta, env)?);
            }
        }
        Ok(push)
    }
}

fn decode_pulled_shared(
    env_key: &Secret<[u8; 32]>,
    sid: &StorageId,
    pull: &SyncDelta,
) -> anyhow::Result<PulledShared> {
    let mut entries = Vec::with_capacity(pull.member_entries.len());
    for raw in &pull.member_entries {
        if let Ok(e) = Entry::decode(raw) {
            entries.push(e);
        }
    }
    let head_epoch = pull.head.as_ref().map_or(0, |h| h.ver.generation);
    let snapshot = match &pull.head {
        Some(h) => {
            let _ = open_blob(env_key, sid, EnvelopePurpose::SharedHead, &h.head_meta)?;
            let (_, snap_plain) = open_blob(
                env_key,
                sid,
                EnvelopePurpose::SharedSnapshot,
                &h.snapshot_env,
            )?;
            Some((snap_plain, h.ver.generation))
        }
        None => None,
    };
    let mut bundles = Vec::with_capacity(pull.records.len());
    for rec in &pull.records {
        let (_, plain) = open_blob(env_key, sid, EnvelopePurpose::SharedFrame, &rec.envelope)?;
        bundles.push(plain);
    }
    let mut rekeys = Vec::with_capacity(pull.rekeys.len());
    for rk in &pull.rekeys {
        let (_, plain) = open_blob(env_key, sid, EnvelopePurpose::SharedRekey, &rk.envelope)?;
        rekeys.push((rk.generation, plain));
    }
    let mut certs = Vec::with_capacity(pull.certs.len());
    for raw in &pull.certs {
        if let Ok(c) = decode_cert(raw) {
            certs.push(c);
        }
    }
    let mut revocations = Vec::with_capacity(pull.revocations.len());
    for raw in &pull.revocations {
        if let Ok(r) = decode_revocation(raw) {
            revocations.push(r);
        }
    }
    Ok(PulledShared {
        member_entries: entries,
        snapshot,
        head_epoch,
        bundles,
        rekeys,
        revocations,
        certs,
    })
}
