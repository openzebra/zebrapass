//! Wrap-list rewriting for vault-key rotations: password replacement,
//! public-key presence checks, and the full re-seal pass.

use container::{VaultFile, WrapEntry};
use secret::Secret;
use wraps::{
    seal_chip, seal_device, seal_human_password, seal_password, seal_prf, ChipPublics,
    DevicePublics, PrfPublics,
};

use crate::create::{
    assemble_committed, commit_mode, dir_bytes, draw_secret, encode_entry, encrypt_records,
    next_generation, Session,
};
use kdf::derive_vault_keys;

use crate::rotate::RotateCreds;
use crate::error::SessionError;

/// The one vault-key rotation: re-seal the wrap list, re-encrypt `records`,
/// publish, and swap the session keys. `drop` removes that kind and id first.
pub fn rotate_all(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
    creds: &RotateCreds<'_>,
    drop: Option<(u16, [u8; 16])>,
) -> anyhow::Result<()> {
    let (header, generation, sealed, body, keys) = {
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
        require_device_publics(&entries, creds.devices)?;
        require_chip_publics(&entries, creds.chips)?;
        require_prf_publics(&entries, creds.prfs)?;
        let vk = draw_secret()?;
        let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
        // Fresh seals. The records already in the file wrap the old vault key.
        let sealed = reseal(&entries, &parsed.header, vk.expose(), creds)?;
        let body = encrypt_records(
            session.body_alg,
            &parsed.header,
            k_body.expose(),
            k_bmac.expose(),
            records,
        )?;
        let generation = next_generation(parsed.generation)?;
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
        )
    };
    publish_rotated(session, file, &header, &sealed, &body, generation, keys)?;
    session.records = Secret::new(records.to_vec());
    Ok(())
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
            WrapEntry::HumanPassword(_)
            | WrapEntry::Device(_)
            | WrapEntry::Chip(_)
            | WrapEntry::Prf(_) => {
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

fn require_device_publics(
    entries: &[WrapEntry<'_>],
    devices: &[DevicePublics],
) -> anyhow::Result<()> {
    for entry in entries {
        if let WrapEntry::Device(dev) = entry {
            if !devices.iter().any(|item| item.id == dev.device_id) {
                return Err(anyhow::anyhow!("wrap not found"));
            }
        }
    }
    Ok(())
}

fn require_chip_publics(
    entries: &[WrapEntry<'_>],
    chips: &[(ChipPublics, [u8; 32])],
) -> anyhow::Result<()> {
    for entry in entries {
        if let WrapEntry::Chip(chip) = entry {
            if !chips.iter().any(|(publics, _)| publics.id == chip.id) {
                return Err(anyhow::anyhow!("wrap not found"));
            }
        }
    }
    Ok(())
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
                let pw = creds.human_password.ok_or(SessionError::HumanFactorRequired)?;
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
            WrapEntry::Device(dev) => {
                let publics = creds
                    .devices
                    .iter()
                    .find(|item| item.id == dev.device_id)
                    .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
                let (record, _grant) = seal_device(header, publics, vk)?;
                record
            }
            WrapEntry::Chip(chip) => {
                let (publics, _) = creds.chips
                    .iter()
                    .find(|(item, _)| item.id == chip.id)
                    .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
                let (record, _grant) = seal_chip(header, publics, vk)?;
                record
            }
            WrapEntry::Prf(wrap) => {
                let (publics, prf_out) = creds.prfs
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
