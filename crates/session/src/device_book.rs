//! Device public keys kept in the vault metadata record.
//!
//! A device wrap stores only the X25519 half of the device's public keys,
//! so a rotation could not re-seal it without the device present. The
//! book keeps `id ‖ x_pk ‖ pq_pk` per enrolled device inside the encrypted,
//! committed metadata record, so any holder of the vault key can rotate.

use container::VaultFile;
use pq::PQ_PK_LEN;
use record::{ValueType, TAG_DEVICE_BOOK};
use wraps::{DeviceGrant, DevicePublics};

use crate::create::Session;
use crate::devices::add_device;
use crate::records::{vault_meta, write_vault_meta};

const ENTRY_LEN: usize = 16 + 32 + PQ_PK_LEN;

/// Every device public key set recorded in the vault metadata.
///
/// # Errors
///
/// `corrupted length` when the stored book is not whole entries; frame
/// errors as in [`crate::vault_meta`].
pub fn known_devices(session: &Session) -> anyhow::Result<Vec<DevicePublics>> {
    let meta = vault_meta(session)?;
    let Some(book) = meta.data(TAG_DEVICE_BOOK)? else {
        return Ok(Vec::new());
    };
    if book.len() % ENTRY_LEN != 0 {
        anyhow::bail!("corrupted length");
    }
    book.chunks_exact(ENTRY_LEN).map(decode_entry).collect()
}

/// Add a device wrap and record its public keys in the vault metadata, so
/// later rotations can re-seal the wrap without the device.
///
/// Two publishes: the wrap first, then the metadata revision. Each is
/// fail-atomic; if the second fails the wrap exists and a rotation asks
/// for the publics in `RotateCreds::devices`.
///
/// # Errors
///
/// As in [`crate::add_device`] and [`crate::write_vault_meta`].
pub fn enroll_device(
    session: &mut Session,
    file: &mut VaultFile,
    publics: &DevicePublics,
) -> anyhow::Result<DeviceGrant> {
    let grant = add_device(session, file, publics)?;
    let mut meta = vault_meta(session)?;
    let mut book = meta.data(TAG_DEVICE_BOOK)?.unwrap_or_default().to_vec();
    book.reserve(ENTRY_LEN);
    book.extend_from_slice(&publics.id);
    book.extend_from_slice(&publics.x_pk);
    book.extend_from_slice(&publics.pq_pk);
    meta.set_data(TAG_DEVICE_BOOK, ValueType::Bytes, &book);
    write_vault_meta(session, file, &meta)?;
    Ok(grant)
}

fn decode_entry(entry: &[u8]) -> anyhow::Result<DevicePublics> {
    let corrupted = || anyhow::anyhow!("corrupted length");
    let (id, rest) = entry.split_first_chunk::<16>().ok_or_else(corrupted)?;
    let (x_pk, pq_pk) = rest.split_first_chunk::<32>().ok_or_else(corrupted)?;
    Ok(DevicePublics {
        id: *id,
        x_pk: *x_pk,
        pq_pk: pq_pk.try_into().map_err(|_| corrupted())?,
    })
}
