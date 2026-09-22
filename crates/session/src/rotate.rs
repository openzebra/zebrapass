//! Password change, record rewrite, and vault-key rotation.

use container::{VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{
    seal_chip, seal_device, seal_password, seal_prf, ChipPublics, DevicePublics, PrfPublics,
};

use crate::create::{
    assemble_committed, dir_bytes, draw_secret, encode_entry, encrypt_records, next_generation,
    publish, Session,
};

/// Replace the password wrap. Header and body bytes stay as they are.
///
/// The new record has a new kid and nonce and seals the same vault key.
/// Generation increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `empty password` when `new_pw` is empty, before Argon2.
/// `wrap not found` when the file has no password wrap.
pub fn change_password(
    session: &mut Session,
    file: &mut VaultFile,
    new_pw: &str,
) -> anyhow::Result<()> {
    if new_pw.is_empty() {
        return Err(anyhow::anyhow!("empty password"));
    }
    let (header, generation, body, records) = {
        let parsed = file.parse()?;
        let records =
            replace_password(&parsed.entries, &parsed.header, new_pw, session.vk.expose())?;
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, parsed.body.to_vec(), records)
    };
    publish(session, file, &header, &records, &body, generation)
}

/// Encrypt `records` under the same vault key and a fresh body nonce.
///
/// Wrap records are copied unchanged. Generation increases by one.
/// On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `unsupported body algorithm` when the session body algorithm is Kuznyechik-MGM.
/// `corrupted length` when the OS RNG fails.
pub fn write_records(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
) -> anyhow::Result<()> {
    let (header, generation, kept, body) = {
        let parsed = file.parse()?;
        let kept = crate::create::owned_entries(&parsed.entries)?;
        let body = encrypt_records(
            session.body_alg,
            &parsed.header,
            session.k_body.expose(),
            session.k_bmac.expose(),
            records,
        )?;
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, kept, body)
    };
    publish(session, file, &header, &kept, &body, generation)
}

/// Rotate the vault key, re-encrypt `records`, and re-seal every wrap.
///
/// Old wrap ciphertexts are not reused: they seal the previous vault key.
/// A file wrap id with no matching entry in `devices`, `chips`, or `prfs` is
/// `wrap not found` and does not modify `file` or `session`. Generation
/// increases by one. Sealing a chip wrap draws a fresh ephemeral P-256 key in
/// this process, so the platform must re-derive its shared secret against the
/// new ephemeral public key after the call; the secret paired with a
/// [`ChipPublics`] is accepted for symmetry with `prfs` and is not read.
///
/// # Errors
///
/// `empty password` when `password` is empty, before Argon2.
/// `wrap not found` when a device, chip, or PRF wrap has no matching public id.
/// `zero shared secret` when a device X25519 public key is zero.
pub fn reencrypt_body(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
    password: &str,
    devices: &[DevicePublics],
    chips: &[(ChipPublics, [u8; 32])],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("empty password"));
    }
    let (header, generation, sealed, body, keys) = {
        let parsed = file.parse()?;
        require_device_publics(&parsed.entries, devices)?;
        require_chip_publics(&parsed.entries, chips)?;
        require_prf_publics(&parsed.entries, prfs)?;
        let vk = draw_secret()?;
        let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
        // Fresh seals. The records already in the file wrap the old vault key.
        let sealed = reseal(
            &parsed.entries,
            &parsed.header,
            vk.expose(),
            password,
            devices,
            chips,
            prfs,
        )?;
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
    publish_rotated(session, file, &header, &sealed, &body, generation, keys)
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
    let (updated, tag) = assemble_committed(keys.k_commit.expose(), header, &wrap_dir, body)?;
    *file = updated;
    session.vk = keys.vk;
    session.k_body = keys.k_body;
    session.k_bmac = keys.k_bmac;
    session.k_commit = keys.k_commit;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(())
}

fn replace_password(
    entries: &[WrapEntry<'_>],
    header: &container::StaticHeader,
    password: &str,
    vk: &[u8; 32],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(entries.len());
    let mut replaced = false;
    for entry in entries {
        match entry {
            WrapEntry::Password(_) if replaced => return Err(anyhow::anyhow!("corrupted length")),
            WrapEntry::Password(_) => {
                replaced = true;
                records.push(seal_password(header, password, vk)?);
            }
            WrapEntry::Device(_) | WrapEntry::Chip(_) | WrapEntry::Prf(_) => {
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
        if let WrapEntry::Prf(prf) = entry {
            if !prfs.iter().any(|(publics, _)| publics.id == prf.id) {
                return Err(anyhow::anyhow!("wrap not found"));
            }
        }
    }
    Ok(())
}

fn reseal(
    entries: &[WrapEntry<'_>],
    header: &container::StaticHeader,
    vk: &[u8; 32],
    password: &str,
    devices: &[DevicePublics],
    chips: &[(ChipPublics, [u8; 32])],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let record = match entry {
            WrapEntry::Password(_) => seal_password(header, password, vk)?,
            WrapEntry::Device(dev) => {
                let publics = devices
                    .iter()
                    .find(|item| item.id == dev.device_id)
                    .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
                let (record, _grant) = seal_device(header, publics, vk)?;
                record
            }
            WrapEntry::Chip(chip) => {
                let (publics, _) = chips
                    .iter()
                    .find(|(item, _)| item.id == chip.id)
                    .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
                let (record, _grant) = seal_chip(header, publics, vk)?;
                record
            }
            WrapEntry::Prf(prf) => {
                let (publics, prf_out) = prfs
                    .iter()
                    .find(|(item, _)| item.id == prf.id)
                    .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
                let (record, _grant) = seal_prf(header, publics, prf_out, vk)?;
                record
            }
        };
        records.push(record);
    }
    Ok(records)
}
