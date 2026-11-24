//! Personal vault `VK`-bound envelope push builder and pull verifier/decoder.

use kdf::zsync_vk_envelope_key;
use local::{SyncIdentity, open_master_grant, open_personal_rekey_any};
use secret::Secret;
use session::{DeviceCert, Revocation};
use syncwire::{decode_cert, decode_revocation, encode_revocation};
use zeroize::Zeroizing;

use crate::auth::{
    EnvelopePurpose, RecordMeta, now_ms, open_blob, seal_blob, sign_head, sign_record, sign_rekey,
    verify_rekey,
};
use crate::client::{PersonalStateInput, PulledPersonal};
use crate::wire::{HeadVer, RepoKind, SignedHead, StorageId, SyncDelta, Wanted};

type HeadPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);
type AdoptedVk = (u64, Secret<[u8; 32]>);
type RekeyList = Vec<(u64, Zeroizing<Vec<u8>>)>;

pub struct PersonalPushCtx<'a> {
    pub identity: &'a SyncIdentity,
    pub sign_key: &'a session::DeviceSignKey,
    pub env_key: Option<&'a Secret<[u8; 32]>>,
    pub anchor_wire: &'a [u8],
    pub sid: &'a StorageId,
    pub own_device_id: [u8; 16],
    pub own_cert_wire: &'a [u8],
    pub head_ver: HeadVer,
    pub head_epoch: u64,
    pub input: &'a PersonalStateInput<'a>,
}

impl PersonalPushCtx<'_> {
    pub fn build(&self, pull: &SyncDelta, wanted: &Wanted) -> anyhow::Result<SyncDelta> {
        let mut push = SyncDelta::empty(RepoKind::Personal, *self.sid);
        push.personal_anchor = Some(self.anchor_wire.to_vec());
        push.root_vk = Some(Box::new(*self.identity.root_vk()));
        if !pull
            .certs
            .iter()
            .any(|c| c.as_slice() == self.own_cert_wire)
        {
            push.certs.push(self.own_cert_wire.to_vec());
        }
        if wanted.need_revs() {
            for rev in self.input.revocations {
                push.revocations.push(encode_revocation(rev)?);
            }
        }
        let Some(env_key) = self.env_key else {
            return Ok(push);
        };
        let pushed_epoch = if (wanted.need_head() || self.input.push_head_always)
            && !self.input.vault_bytes.is_empty()
        {
            let epoch = pull.head.as_ref().map_or(self.head_epoch, |h| {
                self.head_epoch.max(h.ver.generation.saturating_add(1))
            });
            let head_ver = HeadVer {
                generation: epoch,
                ..self.head_ver
            };
            let head_env = seal_blob(
                env_key,
                self.sid,
                EnvelopePurpose::PersonalHead,
                epoch,
                self.input.head_meta_plain,
            )?;
            let snap_env = seal_blob(
                env_key,
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
                self.input.master_grant.map(<[u8]>::to_vec),
            )?);
            Some(epoch)
        } else {
            None
        };
        for (rgen, target, blob) in self.input.rekeys {
            push.rekeys.push(sign_rekey(
                self.sign_key,
                RepoKind::Personal,
                self.sid,
                *rgen,
                self.own_device_id,
                *target,
                blob.clone(),
            )?);
        }
        let key_gen = pushed_epoch
            .or_else(|| pull.head.as_ref().map(|h| h.ver.generation))
            .unwrap_or(self.input.head_epoch);
        for id in &wanted.record_ids {
            if let Some((_, rev, org, raw)) = self.input.records.iter().find(|r| r.0 == *id) {
                let env = seal_blob(env_key, self.sid, EnvelopePurpose::PersonalFrame, *rev, raw)?;
                let meta = RecordMeta {
                    storage_id: self.sid,
                    revision: *rev,
                    key_generation: key_gen,
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

pub fn decode_pulled_personal(
    current_env_key: Option<&Secret<[u8; 32]>>,
    master_seed: Option<&[u8; 64]>,
    sid: &StorageId,
    identity: &SyncIdentity,
    pull: &SyncDelta,
    (pushed_head_epoch, known_head_epoch): (Option<u64>, u64),
    pushed_records: usize,
) -> anyhow::Result<PulledPersonal> {
    let (certs, revocations) = verify_certs_and_revocations(identity, pull);
    let (rekeys, rekey_vk) = extract_rekeys(identity, sid, &certs, &revocations, pull);
    let head_epoch = pull
        .head
        .as_ref()
        .map_or(0, |h| h.ver.generation)
        .max(pushed_head_epoch.unwrap_or(known_head_epoch));
    let pushed_head = pushed_head_epoch.is_some();
    let master_grant = pull.head.as_ref().and_then(|h| h.master_grant.clone());

    let mut adopted_vk = None;
    let mut derived_env_key: Option<Secret<[u8; 32]>> = None;
    if let Some((rgen, vk)) = rekey_vk {
        derived_env_key = Some(zsync_vk_envelope_key(vk.expose(), sid)?);
        adopted_vk = Some((rgen, vk));
    } else if current_env_key.is_none()
        && let (Some(seed), Some(grant_blob)) = (master_seed, master_grant.as_deref())
        && let Ok((_, vk)) = open_master_grant(seed, sid, grant_blob)
    {
        derived_env_key = Some(zsync_vk_envelope_key(vk.expose(), sid)?);
        adopted_vk = Some((head_epoch, vk));
    }

    let Some(ek) = current_env_key.or(derived_env_key.as_ref()) else {
        return Ok(PulledPersonal {
            snapshot: None,
            master_grant,
            adopted_vk: None,
            head_epoch,
            frames: Vec::new(),
            rekeys,
            revocations,
            certs,
            pushed_records,
            pushed_head,
        });
    };

    let fallback_ek = derived_env_key.as_ref();
    let snapshot = match (&pull.head, pushed_head) {
        (Some(h), false) => {
            let (head_plain, snap_plain) = match open_head_pair(ek, sid, h) {
                Ok(pair) => pair,
                Err(e) => match fallback_ek {
                    Some(fb) => open_head_pair(fb, sid, h)?,
                    None => return Err(e),
                },
            };
            Some((snap_plain, head_plain, h.ver.generation))
        }
        _ => None,
    };
    let mut frames = Vec::with_capacity(pull.records.len());
    for rec in &pull.records {
        let opened = open_blob(ek, sid, EnvelopePurpose::PersonalFrame, &rec.envelope)
            .map(|(_, pt)| pt)
            .or_else(|e| {
                fallback_ek.map_or_else(
                    || Err(e),
                    |fb| {
                        open_blob(fb, sid, EnvelopePurpose::PersonalFrame, &rec.envelope)
                            .map(|(_, pt)| pt)
                    },
                )
            });
        match opened {
            Ok(plain) => frames.push(plain),
            Err(_) if snapshot.is_some() || pushed_head => {}
            Err(e) => return Err(e),
        }
    }
    Ok(PulledPersonal {
        snapshot,
        master_grant,
        adopted_vk,
        head_epoch,
        frames,
        rekeys,
        revocations,
        certs,
        pushed_records,
        pushed_head,
    })
}

fn verify_certs_and_revocations(
    identity: &SyncIdentity,
    pull: &SyncDelta,
) -> (Vec<DeviceCert>, Vec<Revocation>) {
    let now = now_ms();
    let certs = pull
        .certs
        .iter()
        .filter_map(|raw| decode_cert(raw).ok())
        .filter(|c| c.verify(identity.root_vk(), now).is_ok())
        .collect();
    let revocations = pull
        .revocations
        .iter()
        .filter_map(|raw| decode_revocation(raw).ok())
        .filter(|r| r.verify(identity.root_vk(), now).is_ok())
        .collect();
    (certs, revocations)
}

fn extract_rekeys(
    identity: &SyncIdentity,
    sid: &StorageId,
    certs: &[DeviceCert],
    revocations: &[Revocation],
    pull: &SyncDelta,
) -> (RekeyList, Option<AdoptedVk>) {
    let own_dev = identity.device_id().unwrap_or([0u8; 16]);
    let mut rekeys = Vec::new();
    let mut rekey_vk: Option<AdoptedVk> = None;
    for rk in &pull.rekeys {
        if rk.target_device != own_dev {
            continue;
        }
        let signer_cert = certs.iter().chain(identity.devices().iter()).find(|c| {
            c.device_id == rk.origin_device
                && !revocations.iter().any(|r| r.covers(c))
                && !identity.revocations().is_revoked(c)
        });
        if let Some(sc) = signer_cert
            && verify_rekey(&sc.device_vk, RepoKind::Personal, sid, rk).is_ok()
        {
            if let Ok((_, vk)) = open_personal_rekey_any(
                identity.share_keys(),
                &own_dev,
                rk.generation,
                &rk.envelope,
            ) && rekey_vk.as_ref().is_none_or(|(g, _)| rk.generation >= *g)
            {
                rekey_vk = Some((rk.generation, vk));
            }
            rekeys.push((rk.generation, Zeroizing::new(rk.envelope.clone())));
        }
    }
    (rekeys, rekey_vk)
}

fn open_head_pair(
    ek: &Secret<[u8; 32]>,
    sid: &StorageId,
    h: &SignedHead,
) -> anyhow::Result<HeadPair> {
    let (_, head_plain) = open_blob(ek, sid, EnvelopePurpose::PersonalHead, &h.head_meta)?;
    let (_, snap_plain) = open_blob(ek, sid, EnvelopePurpose::PersonalSnapshot, &h.snapshot_env)?;
    Ok((head_plain, snap_plain))
}
