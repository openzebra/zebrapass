//! Add and remove device and chip wraps. The body bytes stay as they are.

use container::{KIND_CHIP, KIND_DEVICE, VaultFile, WrapEntry};
use wraps::{
    seal_chip, seal_device, seal_prf, ChipGrant, ChipPublics, DeviceGrant, DevicePublics, PrfGrant,
    PrfPublics,
};

use crate::create::{encode_entry, next_generation, publish, Session};

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
    let (header, generation, body, records, grant) = {
        let parsed = file.parse()?;
        // A repeated device id does not parse. Reject it before sealing.
        if parsed
            .entries
            .iter()
            .any(|entry| matches!(entry, WrapEntry::Device(dev) if dev.device_id == dev_pks.id))
        {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_device(&parsed.header, dev_pks, session.vk.expose())?;
        let mut records = Vec::with_capacity(parsed.entries.len().saturating_add(1));
        for entry in &parsed.entries {
            records.push(encode_entry(entry)?);
        }
        records.push(record);
        let generation = next_generation(parsed.generation)?;
        (
            parsed.header,
            generation,
            parsed.body.to_vec(),
            records,
            grant,
        )
    };
    publish(session, file, &header, &records, &body, generation)?;
    Ok(grant)
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
    let (header, generation, body, records, grant) = {
        let parsed = file.parse()?;
        // A repeated chip id does not parse. Reject it before sealing.
        if parsed
            .entries
            .iter()
            .any(|entry| matches!(entry, WrapEntry::Chip(wrap) if wrap.id == chip.id))
        {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_chip(&parsed.header, chip, session.vk.expose())?;
        let mut records = Vec::with_capacity(parsed.entries.len().saturating_add(1));
        for entry in &parsed.entries {
            records.push(encode_entry(entry)?);
        }
        records.push(record);
        let generation = next_generation(parsed.generation)?;
        (
            parsed.header,
            generation,
            parsed.body.to_vec(),
            records,
            grant,
        )
    };
    publish(session, file, &header, &records, &body, generation)?;
    Ok(grant)
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
    let (header, generation, body, records, grant) = {
        let parsed = file.parse()?;
        // A repeated grant id does not parse. Reject it before sealing.
        if parsed
            .entries
            .iter()
            .any(|entry| matches!(entry, WrapEntry::Prf(wrap) if wrap.id == publics.id))
        {
            return Err(anyhow::anyhow!("corrupted length"));
        }
        let (record, grant) = seal_prf(&parsed.header, publics, prf_out, session.vk.expose())?;
        let mut records = Vec::with_capacity(parsed.entries.len().saturating_add(1));
        for entry in &parsed.entries {
            records.push(encode_entry(entry)?);
        }
        records.push(record);
        let generation = next_generation(parsed.generation)?;
        (
            parsed.header,
            generation,
            parsed.body.to_vec(),
            records,
            grant,
        )
    };
    publish(session, file, &header, &records, &body, generation)?;
    Ok(grant)
}

/// Drop the wraps of `kinds` whose id is `id`.
/// Password wraps carry no id and are never removed, so the parse-time policy
/// of at least one password wrap is preserved. The vault key does not change.
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
    let (header, generation, body, records) = {
        let parsed = file.parse()?;
        let records = remove_wrap_of_kind(&parsed.entries, device_id, &[KIND_DEVICE])?;
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, parsed.body.to_vec(), records)
    };
    publish(session, file, &header, &records, &body, generation)
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
    let (header, generation, body, records) = {
        let parsed = file.parse()?;
        let records = remove_wrap_of_kind(&parsed.entries, id, &[KIND_CHIP])?;
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, parsed.body.to_vec(), records)
    };
    publish(session, file, &header, &records, &body, generation)
}
