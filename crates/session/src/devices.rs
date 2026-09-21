//! Add and remove device wraps. The body bytes stay as they are.

use container::{VaultFile, WrapEntry};
use wraps::{seal_device, DeviceGrant, DevicePublics};

use crate::create::{encode_entry, next_generation, publish, Session};
use crate::error::VaultV2Error;

/// Append a device wrap of the session vault key.
///
/// The body is copied unchanged. Generation increases by one and the commit is
/// recomputed. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// [`VaultV2Error::CorruptedLength`] when `dev_pks.id` is already in the directory.
/// That check runs before the device is sealed, so the file is unchanged.
/// [`VaultV2Error::ZeroSharedSecret`] when `dev_pks.x_pk` yields a zero X25519 secret.
/// Parse and RNG failures use the same variants as [`crate::create`].
pub fn add_device(
    session: &mut Session,
    file: &mut VaultFile,
    dev_pks: &DevicePublics,
) -> Result<DeviceGrant, VaultV2Error> {
    let (header, generation, body, records, grant) = {
        let parsed = file.parse()?;
        // A repeated device id does not parse. Reject it before sealing.
        if parsed
            .entries
            .iter()
            .any(|entry| matches!(entry, WrapEntry::Device(dev) if dev.device_id == dev_pks.id))
        {
            return Err(VaultV2Error::CorruptedLength);
        }
        let (record, grant) = seal_device(&parsed.header, dev_pks, session.vk.expose())?;
        let mut records = Vec::with_capacity(parsed.entries.len().saturating_add(1));
        for entry in &parsed.entries {
            records.push(encode_entry(entry));
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

/// Drop the device wrap with `device_id`.
///
/// The password wrap is never removed. The body is copied unchanged. Generation
/// increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// [`VaultV2Error::WrapNotFound`] when no device entry has `device_id`.
pub fn remove_device(
    session: &mut Session,
    file: &mut VaultFile,
    device_id: &[u8; 16],
) -> Result<(), VaultV2Error> {
    let (header, generation, body, records) = {
        let parsed = file.parse()?;
        let mut found = false;
        let mut records = Vec::with_capacity(parsed.entries.len());
        for entry in &parsed.entries {
            match entry {
                WrapEntry::Device(dev) if dev.device_id == *device_id => {
                    found = true;
                }
                other => records.push(encode_entry(other)),
            }
        }
        if !found {
            return Err(VaultV2Error::WrapNotFound);
        }
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, parsed.body.to_vec(), records)
    };
    publish(session, file, &header, &records, &body, generation)
}
