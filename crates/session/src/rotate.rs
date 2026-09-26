//! Master change, record rewrite, and vault-key rotation.

use container::{KIND_CHIP, KIND_DEVICE, KIND_PRF, VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{
    seal_chip, seal_device, seal_human_password, seal_password, seal_prf, ChipPublics,
    DevicePublics, PrfPublics,
};

use crate::create::{
    assemble_committed, dir_bytes, draw_secret, encode_entry, encrypt_records, next_generation,
    publish, Session,
};
use crate::error::SessionError;
use crate::rewrap::rewrap;

/// Replace the master wrap: re-seal the same vault key under a new master
/// seed.
///
/// The new record has a new kid and nonce and seals the same vault key.
/// Header and body bytes stay as they are. Generation increases by one.
/// On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when the file has no master wrap.
pub fn change_master(
    session: &mut Session,
    file: &mut VaultFile,
    new_master: &[u8; 64],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, vk| {
        let mut records = replace_password(&parsed.entries, &parsed.header, new_master, vk)?;
        // The re-sealed PRF wraps below replace the old ones. Keeping both
        // copies would duplicate the grant id (and grow on every rotation).
        let prf_le = KIND_PRF.to_le_bytes();
        records.retain(|record| record.get(0..2) != Some(&prf_le[..]));
        // The password wrap now seals the new vault key; every PRF wrap must
        // follow or its grant dies with the old key.
        for entry in &parsed.entries {
            if let WrapEntry::Prf(wrap) = entry {
                let (publics, prf_out) = prfs
                    .iter()
                    .find(|(item, _)| item.id == wrap.id)
                    .ok_or(SessionError::PrfFactorRequired)?;
                let (record, _grant) = seal_prf(&parsed.header, publics, prf_out, vk)?;
                records.push(record);
            }
        }
        Ok((records, ()))
    })
}

/// Encrypt `records` under the same vault key and a fresh body nonce.
///
/// Wrap records are copied unchanged. Generation increases by one.
/// On success the session's decrypted frame body is replaced with
/// `records`; on error, `file` and `session` are left as they were.
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
    publish(session, file, &header, &kept, &body, generation)?;
    // The plaintext is already in hand; keep the session's copy in step
    // with the file.
    session.records = Secret::new(records.to_vec());
    Ok(())
}

/// Rotate the vault key, re-encrypt `records`, and re-seal every wrap.
///
/// Old wrap ciphertexts are not reused: they seal the previous vault key.
/// A file wrap id with no matching entry in `devices` or `chips` is
/// `wrap not found` and does not modify `file` or `session`. A PRF wrap
/// without a matching output in `prfs` is `prf factor required`. Generation
/// increases by one. Sealing a chip
/// wrap draws a fresh ephemeral P-256 key in this process, so the platform
/// must re-derive its shared secret against the new ephemeral public key
/// after the call. On success the session's decrypted frame body is
/// replaced with `records`.
///
/// # Errors
///
/// `wrap not found` when a device or chip wrap has no matching public id.
/// `prf factor required` when a PRF wrap has no matching output.
/// `zero shared secret` when a device X25519 public key is zero.
pub fn reencrypt_body(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
    master: &[u8; 64],
    devices: &[DevicePublics],
    chips: &[(ChipPublics, [u8; 32])],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    rotate_all(
        session,
        file,
        records,
        &RotateCreds {
            master,
            human_password: None,
            devices,
            chips,
            prfs,
        },
        None,
    )
}

/// Secret material the remaining wraps are re-sealed from: the recovery
/// passphrase and the live outputs of every kept human factor.
///
/// Device and chip wraps are sealed to public keys, so revoking one of them
/// needs no secret from the revoked device.
#[derive(Clone, Copy, Debug)]
pub struct RotateCreds<'a> {
    /// Seals the password (recovery) wrap.
    pub master: &'a [u8; 64],
    /// Public keys of every kept device wrap.
    pub devices: &'a [DevicePublics],
    /// Platform public key plus its P-256 shared secret, per kept chip wrap.
    pub chips: &'a [(ChipPublics, [u8; 32])],
    /// hmac-secret output, per kept PRF wrap.
    pub prfs: &'a [(PrfPublics, [u8; 32])],
    /// The human password, needed only when a human password wrap must be
    /// re-sealed. `None` is fine for vaults without one.
    pub human_password: Option<&'a [u8]>,
}

/// The wrap a revocation removes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revoke<'a> {
    /// The device wrap with this id.
    Device(&'a [u8; 16]),
    /// The chip wrap with this id.
    Chip(&'a [u8; 16]),
    /// The PRF wrap with this id.
    Prf(&'a [u8; 16]),
}

/// Revoke an unlock factor: drop its wrap and rotate the vault key under
/// every remaining one.
///
/// A revoked device keeps its wrap ciphertext and everything it ever
/// decrypted, so dropping the wrap alone proves nothing. The vault key is
/// drawn fresh and the body is re-encrypted, so old key material cannot read
/// records written after this call. Every remaining wrap needs matching
/// material in `creds`; device and chip wraps need only their public keys.
/// The session's decrypted frame body becomes empty. On error, `file` and
/// `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when no wrap of the target kind has the id, or a
/// remaining device or chip wrap has no matching public id in `creds`.
/// `prf factor required` when a remaining PRF wrap has no matching output.
/// `human factor required` when a remaining human wrap has no password in
/// `creds`.
/// `zero shared secret` when a remaining device public key is zero.
pub fn revoke(
    session: &mut Session,
    file: &mut VaultFile,
    target: &Revoke<'_>,
    creds: &RotateCreds<'_>,
) -> anyhow::Result<()> {
    match target {
        Revoke::Device(id) => rotate_all(session, file, &[], creds, Some((KIND_DEVICE, **id))),
        Revoke::Chip(id) => rotate_all(session, file, &[], creds, Some((KIND_CHIP, **id))),
        Revoke::Prf(id) => rotate_all(session, file, &[], creds, Some((KIND_PRF, **id))),
    }
}

/// The one vault-key rotation: re-seal the wrap list, re-encrypt `records`,
/// publish, and swap the session keys. `drop` removes that kind and id first.
fn rotate_all(
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

fn reseal(
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
