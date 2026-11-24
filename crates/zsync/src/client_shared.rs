//! Shared vault reconciliation over `ZebraClient` with self-certifying
//! repository proofs, signed member-device `SharePublics` announcements, and
//! hybrid P-256 + ML-KEM-768 rotation grants.

use anyhow::anyhow;
use container::WrapEntry;
use kdf::shared_envelope_key;
use local::{PersonalDeviceEntry, SharedRepoProof, SyncIdentity, seal_shared_rekey};
use memberlog::{Entry, MemberLog};
use secret::Secret;
use session::{DeviceCert, Revocation, VaultFile};
use sha2::{Digest, Sha256};
use syncwire::{decode_cert, decode_revocation, decode_snapshot, encode_cert};
use zeroize::Zeroizing;

use crate::auth::{
    EnvelopePurpose, RecordMeta, now_ms, open_blob, seal_blob, sign_frontier, sign_head,
    sign_record, sign_rekey, verify_rekey,
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
    /// `(new_epoch, target_device, hybrid_grant_blob)`
    pub rekeys: &'a [(u64, [u8; 16], Vec<u8>)],
    /// Optional `(new_seed, new_epoch)` to seal dynamically to all remaining
    /// member devices returned by `sid_0` during rotation/removal.
    pub rotate_to: Option<(&'a Secret<[u8; 64]>, u32)>,
}

/// Verified state pulled from the server for a shared vault.
#[derive(Debug)]
pub struct PulledShared {
    pub member_entries: Vec<Entry>,
    pub member_devices: Vec<PersonalDeviceEntry>,
    pub snapshot: Option<(Zeroizing<Vec<u8>>, u64)>,
    pub head_epoch: u64,
    pub bundles: Vec<Zeroizing<Vec<u8>>>,
    pub rekeys: Vec<(u64, [u8; 16], Zeroizing<Vec<u8>>)>,
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
/// # Errors
///
/// Unparseable vault file.
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
        let (proof, sid) = SharedRepoProof::issue(input.shared_seed, input.vault_id, input.anchor)?;
        let proof_wire = proof.encode()?;
        let env_key = shared_envelope_key(input.shared_seed, &sid)?;
        let own_dev_entry = PersonalDeviceEntry::issue(identity, &input.vault_id, None)?;
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
            personal_anchor: None,
            root_vk: Some(Box::new(*identity.root_vk())),
            shared_proof: Some(proof_wire.clone()),
            auth: None,
            certs: Vec::new(),
            head: head_ver,
            records: records_ver,
            rev_count: 0,
            member_count: u32::try_from(input.member_entries.len()).unwrap_or(u32::MAX),
            dev_key_count: 0,
        };
        let own_cert_wire = encode_cert(own_cert)?;
        sign_frontier(&identity.sign_key(), &mut frontier, own_cert_wire.clone())?;
        let sign_key = identity.sign_key();
        let push_ctx = SharedPushCtx {
            sign_key: &sign_key,
            env_key: &env_key,
            proof_wire: &proof_wire,
            own_dev_entry: &own_dev_entry,
            sid: &sid,
            own_device_id: own_cert.device_id,
            own_cert_wire: &own_cert_wire,
            head_ver,
            head_epoch,
            input: &input,
        };
        let (pull, _wanted, pushed_head, _) = self
            .run_rpc(&frontier, |pull, wanted| push_ctx.build(pull, wanted))
            .await?;
        let mut pulled = decode_pulled_shared(
            &env_key,
            &sid,
            &input.vault_id,
            &input.anchor,
            input.member_entries,
            &pull,
        )?;
        pulled.head_epoch = pulled
            .head_epoch
            .max(pushed_head.unwrap_or(input.head_epoch));
        Ok(pulled)
    }
}

struct SharedPushCtx<'a> {
    sign_key: &'a session::DeviceSignKey,
    env_key: &'a Secret<[u8; 32]>,
    proof_wire: &'a [u8],
    own_dev_entry: &'a [u8],
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
        push.shared_proof = Some(self.proof_wire.to_vec());
        if !pull
            .certs
            .iter()
            .any(|c| c.as_slice() == self.own_cert_wire)
        {
            push.certs.push(self.own_cert_wire.to_vec());
        }
        if !pull
            .device_keys
            .iter()
            .any(|dk| dk.as_slice() == self.own_dev_entry)
        {
            push.device_keys.push(self.own_dev_entry.to_vec());
        }
        if wanted.need_members() || !self.input.rekeys.is_empty() || self.input.rotate_to.is_some()
        {
            push.member_entries = self.input.member_entries.to_vec();
        }
        if wanted.need_head()
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
                None,
            )?);
        }
        for (epoch, target_dev, hybrid_grant) in self.input.rekeys {
            push.rekeys.push(sign_rekey(
                self.sign_key,
                RepoKind::Shared,
                self.sid,
                *epoch,
                self.own_device_id,
                *target_dev,
                hybrid_grant.clone(),
            )?);
        }
        if let Some((new_seed, new_epoch)) = self.input.rotate_to {
            self.seal_pulled_rekeys(&mut push, pull, new_seed, new_epoch)?;
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
                    key_generation: 1,
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

    fn seal_pulled_rekeys(
        &self,
        push: &mut SyncDelta,
        pull: &SyncDelta,
        new_seed: &Secret<[u8; 64]>,
        new_epoch: u32,
    ) -> anyhow::Result<()> {
        let decoded: Vec<Entry> = self
            .input
            .member_entries
            .iter()
            .filter_map(|raw| Entry::decode(raw).ok())
            .collect();
        let Ok(log) = MemberLog::from_entries(self.input.vault_id, &decoded, &self.input.anchor)
        else {
            return Ok(());
        };
        let now = now_ms();
        for raw_dk in &pull.device_keys {
            for member in log.members() {
                let Ok(entry) = PersonalDeviceEntry::verify_decode(
                    raw_dk,
                    &member.root_vk,
                    &self.input.vault_id,
                    now,
                ) else {
                    continue;
                };
                if !secret::ct_eq(&entry.cert.client_id, &member.client_id)
                    || entry.cert.device_id == self.own_device_id
                    || push
                        .rekeys
                        .iter()
                        .any(|r| r.target_device == entry.cert.device_id)
                {
                    break;
                }
                let grant = seal_shared_rekey(
                    &entry.publics,
                    &entry.cert.device_id,
                    &self.input.vault_id,
                    &self.input.anchor,
                    new_epoch,
                    new_seed,
                )?;
                push.rekeys.push(sign_rekey(
                    self.sign_key,
                    RepoKind::Shared,
                    self.sid,
                    u64::from(new_epoch),
                    self.own_device_id,
                    entry.cert.device_id,
                    grant,
                )?);
                break;
            }
        }
        Ok(())
    }
}

fn decode_pulled_shared(
    env_key: &Secret<[u8; 32]>,
    sid: &StorageId,
    vault_id: &[u8; 16],
    anchor: &[u8; 32],
    local_member_entries: &[Vec<u8>],
    pull: &SyncDelta,
) -> anyhow::Result<PulledShared> {
    let entries: Vec<Entry> = pull
        .member_entries
        .iter()
        .filter_map(|raw| Entry::decode(raw).ok())
        .collect();
    let combined: Vec<Entry> = local_member_entries
        .iter()
        .filter_map(|raw| Entry::decode(raw).ok())
        .collect();
    let log = MemberLog::from_entries(*vault_id, &combined, anchor).map_or_else(
        |_| MemberLog::from_entries(*vault_id, &entries, anchor).ok(),
        |mut base| {
            let _ = base.merge(&entries);
            Some(base)
        },
    );
    let now = now_ms();
    let certs: Vec<DeviceCert> = pull
        .certs
        .iter()
        .filter_map(|raw| decode_cert(raw).ok())
        .collect();
    let mut member_devices = Vec::with_capacity(pull.device_keys.len());
    if let Some(l) = log.as_ref() {
        for raw_dk in &pull.device_keys {
            for m in l.members() {
                if let Ok(entry) =
                    PersonalDeviceEntry::verify_decode(raw_dk, &m.root_vk, vault_id, now)
                    && secret::ct_eq(&entry.cert.client_id, &m.client_id)
                {
                    member_devices.push(entry);
                    break;
                }
            }
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
        let verified = log.as_ref().is_some_and(|l| {
            certs
                .iter()
                .chain(member_devices.iter().map(|d| &d.cert))
                .any(|c| {
                    c.device_id == rk.origin_device
                        && l.role_of(&c.client_id)
                            .is_some_and(memberlog::Role::can_manage)
                        && verify_rekey(&c.device_vk, RepoKind::Shared, sid, rk).is_ok()
                })
        });
        if verified {
            rekeys.push((
                rk.generation,
                rk.target_device,
                Zeroizing::new(rk.envelope.clone()),
            ));
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
        member_devices,
        snapshot,
        head_epoch,
        bundles,
        rekeys,
        revocations,
        certs,
    })
}
