//! Wrap-list rewriting for vault-key rotations: password replacement,
//! public-key presence checks, and the full re-seal pass.

use aead::BodyAlg;
use container::{VaultFile, WrapEntry};
use secret::Secret;
use wraps::{seal_chip, seal_human_password, seal_password, seal_prf, ChipPublics, PrfPublics};

use crate::create::{
    assemble_committed, commit_mode, dir_bytes, draw_secret, encode_entry, encrypt_records,
    next_generation, Session,
};
use kdf::derive_vault_keys;

use frame::encode_frames;

use crate::create::fold_log;
use crate::error::SessionError;
use crate::rotate::RotateCreds;

/// The one vault-key rotation: re-seal the wrap list, re-key the record log
/// under the new vault key, publish, and swap the session keys. `drop`
/// removes that kind and id first. On error, nothing changes.
pub fn rotate_all(
    session: &mut Session,
    file: &mut VaultFile,
    creds: &RotateCreds<'_>,
    drop: Option<(u16, [u8; 16])>,
) -> anyhow::Result<()> {
    let (header, generation, sealed, body, keys, raw, digest) = {
        let parsed = file.parse()?;
        let entries: Vec<WrapEntry<'_>> = match drop {
            Some((kind, id)) => {
                let (kept, gone): (Vec<WrapEntry<'_>>, Vec<WrapEntry<'_>>) = parsed
                    .entries
                    .iter()
                    .copied()
                    .partition(|entry| entry.kind() != kind || entry.wrap_id() != Some(id));
                if gone.is_empty() {
                    return Err(anyhow::anyhow!("wrap not found"));
                }
                kept
            }
            None => parsed.entries.clone(),
        };
        require_prf_publics(&entries, creds.prfs)?;
        let vk = draw_secret()?;
        let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
        let sealed = reseal(&entries, &parsed.header, vk.expose(), creds)?;
        let generation = next_generation(parsed.generation)?;
        // Frame keys derive from the vault key in every body mode, so the log
        // is re-keyed before the body is encoded, whole-body modes included.
        let raw = reseal_frames(
            session.vk.expose(),
            vk.expose(),
            &session.vault_id,
            session.records.expose(),
        )?;
        let (body, digest) = match session.body_alg {
            BodyAlg::Frames => {
                let digest = fold_log(&raw)?;
                (encode_frames(&raw)?, digest)
            }
            alg => {
                let body =
                    encrypt_records(alg, &parsed.header, k_body.expose(), k_bmac.expose(), &raw)?;
                (body, [0u8; 32])
            }
        };
        (
            parsed.header,
            generation,
            sealed,
            body,
            RotatedKeys {
                vk,
                k_body,
                k_bmac,
                k_commit,
            },
            raw,
            digest,
        )
    };
    publish_rotated(session, file, &header, &sealed, &body, generation, keys)?;
    session.records = Secret::new(raw);
    session.frames_digest = digest;
    Ok(())
}

/// Re-key every frame in the raw log: open under `old_vk`, seal under
/// `new_vk`. Frame metadata (kind, record, revision, origin, timestamp) and
/// ordering are preserved; the sealing key and nonce change, and every frame
/// is re-sealed as a cascade frame, so legacy AEGIS-only frames upgrade.
///
/// # Errors
///
/// `corrupted length` when the log does not parse as whole frames or a span
/// overflows the buffer; `frame authentication failed` when a frame does not
/// open under `old_vk`; key-derivation and OS-RNG errors otherwise.
fn reseal_frames(
    old_vk: &[u8; 32],
    new_vk: &[u8; 32],
    vault_id: &[u8; 16],
    log: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(log.len());
    for (start, len) in frame::spans(log)? {
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let sealed = log
            .get(start..end)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let header = frame::parse(sealed)?;
        let plaintext = frame::open(&kdf::frame_key(old_vk, vault_id, header.record_id)?, sealed)?;
        let meta = frame::FrameMeta {
            kind: header.kind,
            record_id: header.record_id,
            revision: header.revision,
            origin_device: header.origin_device,
            timestamp_ms: header.timestamp_ms,
            alg: frame::ALG_CASCADE,
        };
        out.extend_from_slice(&frame::seal(
            &kdf::frame_key(new_vk, vault_id, header.record_id)?,
            &meta,
            plaintext.expose(),
        )?);
    }
    Ok(out)
}

struct RotatedKeys {
    vk: Secret<[u8; 32]>,
    k_body: Secret<[u8; 32]>,
    k_bmac: Secret<[u8; 32]>,
    k_commit: Secret<[u8; 32]>,
}

fn publish_rotated(
    session: &mut Session,
    file: &mut VaultFile,
    header: &container::StaticHeader,
    records: &[Vec<u8>],
    body: &[u8],
    generation: u64,
    keys: RotatedKeys,
) -> anyhow::Result<()> {
    let wrap_dir = dir_bytes(generation, records)?;
    let (updated, tag) = assemble_committed(
        keys.k_commit.expose(),
        header,
        &wrap_dir,
        body,
        commit_mode(session.body_alg),
    )?;
    *file = updated;
    session.vk = keys.vk;
    session.k_body = keys.k_body;
    session.k_bmac = keys.k_bmac;
    session.k_commit = keys.k_commit;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(())
}

pub fn replace_password(
    entries: &[WrapEntry<'_>],
    header: &container::StaticHeader,
    master: &[u8; 64],
    vk: &[u8; 32],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(entries.len());
    let mut replaced = false;
    for entry in entries {
        match entry {
            WrapEntry::Password(_) | WrapEntry::HumanPassword(_) if replaced => {
                return Err(anyhow::anyhow!("corrupted length"));
            }
            WrapEntry::Password(_) => {
                replaced = true;
                records.push(seal_password(header, master, vk)?);
            }
            // A human wrap is carried over unchanged: rotation re-seals the
            // recovery wrap only, and the human KEK still opens the same vk.
            WrapEntry::HumanPassword(_) | WrapEntry::Chip(_) | WrapEntry::Prf(_) => {
                records.push(encode_entry(entry)?);
            }
        }
    }
    if replaced {
        Ok(records)
    } else {
        Err(anyhow::anyhow!("wrap not found"))
    }
}

fn require_prf_publics(
    entries: &[WrapEntry<'_>],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    for entry in entries {
        if let WrapEntry::Prf(wrap) = entry {
            if !prfs.iter().any(|(publics, _)| publics.id == wrap.id) {
                return Err(SessionError::PrfFactorRequired.into());
            }
        }
    }
    Ok(())
}

pub fn reseal(
    entries: &[WrapEntry<'_>],
    header: &container::StaticHeader,
    vk: &[u8; 32],
    creds: &RotateCreds<'_>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let record = match entry {
            WrapEntry::Password(_) => seal_password(header, creds.master, vk)?,
            // A human wrap re-seals under the same human password. The cost
            // profile is carried over from the stored record, and the stored
            // values are ≥ floor (parse enforces it).
            WrapEntry::HumanPassword(human) => {
                let pw = creds
                    .human_password
                    .ok_or(SessionError::HumanFactorRequired)?;
                seal_human_password(
                    header,
                    human.kid,
                    pw,
                    vk,
                    human.kdf.m_kib,
                    human.kdf.t,
                    human.kdf.p,
                )?
            }
            // The chip wrap carries both of its public keys, authenticated by
            // the commit, so it re-seals from the file alone.
            WrapEntry::Chip(chip) => {
                let publics = ChipPublics {
                    id: chip.id,
                    chip_pub: chip.chip_pub,
                    pq_pk: chip.pq_pk,
                };
                let (record, _grant) = seal_chip(header, &publics, vk)?;
                record
            }
            WrapEntry::Prf(wrap) => {
                let (publics, prf_out) = creds
                    .prfs
                    .iter()
                    .find(|(item, _)| item.id == wrap.id)
                    .ok_or(SessionError::PrfFactorRequired)?;
                let (record, _grant) = seal_prf(header, publics, prf_out, vk)?;
                record
            }
        };
        records.push(record);
    }
    Ok(records)
}
