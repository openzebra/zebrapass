//! Add and remove device, chip, and PRF wraps. The body bytes stay as they are.

use container::{KIND_CHIP, KIND_DEVICE, KIND_PASSWORD, KIND_PRF, VaultFile, WrapEntry};
use wraps::{
    seal_chip, seal_device, seal_human_password, seal_prf, ChipGrant, ChipPublics, DeviceGrant,
    DevicePublics, HumanPasswordPublics, PrfGrant, PrfPublics,
};

use crate::create::{encode_entry, owned_entries, Session};
use crate::rewrap::{id_in_use, rewrap};

/// Append a device wrap of the session vault key.
///
/// The body is copied unchanged. Generation increases by one and the commit is
/// recomputed. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `corrupted length` when `dev_pks.id` is already in the directory.
/// That check runs before the device is sealed, so the file is unchanged.
/// `zero shared secret` when `dev_pks.x_pk` yields a zero X25519 secret.
/// Parse and RNG failures use the same variants as [`crate::create`].
pub fn add_device(
    session: &mut Session,
    file: &mut VaultFile,
    dev_pks: &DevicePublics,
) -> anyhow::Result<DeviceGrant> {
    rewrap(session, file, |parsed, vk| {
        // A repeated device id does not parse. Reject it before sealing.
        if id_in_use(&parsed.entries, KIND_DEVICE, &dev_pks.id) {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_device(&parsed.header, dev_pks, vk)?;
        let mut records = owned_entries(&parsed.entries)?;
        records.push(record);
        Ok((records, grant))
    })
}

/// Append a chip wrap of the session vault key.
///
/// The body is copied unchanged. Generation increases by one and the commit is
/// recomputed. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `corrupted length` when `chip.id` is already in the directory.
/// That check runs before the wrap is sealed, so the file is unchanged.
/// `os entropy failed` and `kem length` mirror [`wraps::seal_chip`].
/// Parse and RNG failures use the same variants as [`crate::create`].
pub fn add_chip_unlock(
    session: &mut Session,
    file: &mut VaultFile,
    chip: &ChipPublics,
) -> anyhow::Result<ChipGrant> {
    rewrap(session, file, |parsed, vk| {
        // A repeated chip id does not parse. Reject it before sealing.
        if id_in_use(&parsed.entries, KIND_CHIP, &chip.id) {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_chip(&parsed.header, chip, vk)?;
        let mut records = owned_entries(&parsed.entries)?;
        records.push(record);
        Ok((records, grant))
    })
}

/// Append a PRF wrap of the session vault key.
///
/// `prf_out` is the 32-byte hmac-secret response the key computes from
/// `publics.salt`; it stays in memory only for this call. The body is copied
/// unchanged. Generation increases by one. On error, `file` and `session`
/// are left as they were.
///
/// # Errors
///
/// `corrupted length` when `publics.id` is already in the directory.
/// That check runs before the grant is sealed, so the file is unchanged.
/// Sealing failures use the same variants as [`crate::create`].
pub fn add_prf_unlock(
    session: &mut Session,
    file: &mut VaultFile,
    publics: &PrfPublics,
    prf_out: &[u8; 32],
) -> anyhow::Result<PrfGrant> {
    rewrap(session, file, |parsed, vk| {
        // A repeated grant id does not parse. Reject it before sealing.
        if id_in_use(&parsed.entries, KIND_PRF, &publics.id) {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_prf(&parsed.header, publics, prf_out, vk)?;
        let mut records = owned_entries(&parsed.entries)?;
        records.push(record);
        Ok((records, grant))
    })
}

/// Drop the wraps of `kinds` whose id is `id`.
/// Password wraps carry no id; only [`drop_recovery_wrap`] passes their kind.
/// The vault key does not change.
///
/// # Errors
///
/// `wrap not found` when no entry of a listed kind has `id`.
fn remove_wrap_of_kind(
    entries: &[WrapEntry<'_>],
    id: &[u8; 16],
    kinds: &[u16],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut found = false;
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.wrap_id() == Some(*id) && kinds.contains(&entry.kind()) {
            found = true;
            continue;
        }
        records.push(encode_entry(entry)?);
    }
    if !found {
        return Err(anyhow::anyhow!("wrap not found"));
    }
    Ok(records)
}

/// Drop the device wrap with `device_id`.
///
/// The password wrap is never removed. The body is copied unchanged. Generation
/// increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when no device entry has `device_id`.
pub fn remove_device(
    session: &mut Session,
    file: &mut VaultFile,
    device_id: &[u8; 16],
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, _| {
        let records = remove_wrap_of_kind(&parsed.entries, device_id, &[KIND_DEVICE])?;
        Ok((records, ()))
    })
}

/// Drop the chip wrap with `id` — the settings toggle for chip unlock.
///
/// The vault key does not change and the password wrap stays. Generation
/// increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when no chip entry has `id`.
pub fn remove_chip_unlock(
    session: &mut Session,
    file: &mut VaultFile,
    id: &[u8; 16],
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, _| {
        let records = remove_wrap_of_kind(&parsed.entries, id, &[KIND_CHIP])?;
        Ok((records, ()))
    })
}

/// Drop the PRF wrap with `id` — a lost hardware key leaves the vault.
///
/// The password wrap is never removed, so the vault stays openable. The vault
/// key does not change: grant the rotation to [`crate::rotate`] when the key
/// itself must die. The body is copied unchanged. Generation increases by one.
/// On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when no PRF entry has `id`.
pub fn remove_prf_unlock(
    session: &mut Session,
    file: &mut VaultFile,
    id: &[u8; 16],
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, _| {
        let records = remove_wrap_of_kind(&parsed.entries, id, &[KIND_PRF])?;
        Ok((records, ()))
    })
}

/// Drop the seed (recovery) wrap from a local copy: after onboarding, the
/// phrase must not open this copy.
///
/// Refuses while the copy has no human password and no device/chip/PRF wrap:
/// a vault with no remaining factor could never be opened again. The vault
/// key does not change, so the server/backup copy (which keeps the seed
/// wrap) stays in sync. Generation increases by one. On error, `file` and
/// `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when the copy has no seed wrap (already dropped).
/// `no usable wrap` when dropping it would leave no unlock factor.
pub fn drop_recovery_wrap(session: &mut Session, file: &mut VaultFile) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, _| {
        let has_other = parsed.entries.iter().any(|entry| {
            matches!(
                entry,
                WrapEntry::Device(_)
                    | WrapEntry::Chip(_)
                    | WrapEntry::Prf(_)
                    | WrapEntry::HumanPassword(_)
            )
        });
        if !has_other {
            return Err(anyhow::anyhow!("no usable wrap"));
        }
        let mut records = Vec::with_capacity(parsed.entries.len());
        let mut found = false;
        for entry in &parsed.entries {
            if entry.kind() == KIND_PASSWORD {
                found = true;
                continue;
            }
            records.push(encode_entry(entry)?);
        }
        if !found {
            return Err(anyhow::anyhow!("wrap not found"));
        }
        Ok((records, ()))
    })
}

/// Append a human password wrap of the session vault key.
///
/// The cost profile is raised to the wire floor before sealing, so the
/// record always parses back. The body is copied unchanged. Generation
/// increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `kdf parameters rejected` when the floored parameters are out of range;
/// `os entropy failed` on RNG failure; parse and publish failures mirror
/// [`crate::create`].
pub fn add_human_password(
    session: &mut Session,
    file: &mut VaultFile,
    input: &HumanPasswordPublics,
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, vk| {
        let record = seal_human_password(
            &parsed.header,
            input.kid,
            &input.password,
            vk,
            input.m_kib,
            input.t,
            input.p,
        )?;
        let mut records = owned_entries(&parsed.entries)?;
        records.push(record);
        Ok((records, ()))
    })
}
