//! Password change, record rewrite, and vault-key rotation.

use container::{VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{seal_device, seal_password, DevicePublics};

use crate::create::{
    assemble_committed, dir_bytes, draw_secret, encode_entry, encrypt_records, next_generation,
    publish, Session,
};
use crate::error::VaultV2Error;

/// Replace the password wrap. Header and body bytes stay as they are.
///
/// The new record has a new kid and nonce and seals the same vault key.
/// Generation increases by one. On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// [`VaultV2Error::EmptyPassword`] when `new_pw` is empty, before Argon2.
/// [`VaultV2Error::WrapNotFound`] when the file has no password wrap.
pub fn change_password(
    session: &mut Session,
    file: &mut VaultFile,
    new_pw: &str,
) -> Result<(), VaultV2Error> {
    if new_pw.is_empty() {
        return Err(VaultV2Error::EmptyPassword);
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
/// [`VaultV2Error::UnsupportedBodyAlg`] when the session body algorithm is Kuznyechik-MGM.
/// [`VaultV2Error::CorruptedLength`] when the OS RNG fails.
pub fn write_records(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
) -> Result<(), VaultV2Error> {
    let (header, generation, kept, body) = {
        let parsed = file.parse()?;
        let kept = crate::create::owned_entries(&parsed.entries);
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
/// A file device id with no matching [`DevicePublics`] is [`VaultV2Error::WrapNotFound`]
/// and does not modify `file` or `session`. Generation increases by one.
///
/// # Errors
///
/// [`VaultV2Error::EmptyPassword`] when `password` is empty, before Argon2.
/// [`VaultV2Error::WrapNotFound`] when a device wrap has no matching public id.
/// [`VaultV2Error::ZeroSharedSecret`] when a device X25519 public key is zero.
pub fn reencrypt_body(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
    password: &str,
    devices: &[DevicePublics],
) -> Result<(), VaultV2Error> {
    if password.is_empty() {
        return Err(VaultV2Error::EmptyPassword);
    }
    let (header, generation, sealed, body, keys) = {
        let parsed = file.parse()?;
        require_device_publics(&parsed.entries, devices)?;
        let vk = draw_secret()?;
        let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
        // Fresh seals. The records already in the file wrap the old vault key.
        let sealed = reseal(
            &parsed.entries,
            &parsed.header,
            vk.expose(),
            password,
            devices,
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
) -> Result<(), VaultV2Error> {
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
) -> Result<Vec<Vec<u8>>, VaultV2Error> {
    let mut records = Vec::with_capacity(entries.len());
    let mut replaced = false;
    for entry in entries {
        match entry {
            WrapEntry::Password(_) if replaced => return Err(VaultV2Error::CorruptedLength),
            WrapEntry::Password(_) => {
                replaced = true;
                records.push(seal_password(header, password, vk)?);
            }
            WrapEntry::Device(_) => records.push(encode_entry(entry)),
        }
    }
    if replaced {
        Ok(records)
    } else {
        Err(VaultV2Error::WrapNotFound)
    }
}

fn require_device_publics(
    entries: &[WrapEntry<'_>],
    devices: &[DevicePublics],
) -> Result<(), VaultV2Error> {
    for entry in entries {
        if let WrapEntry::Device(dev) = entry {
            if !devices.iter().any(|item| item.id == dev.device_id) {
                return Err(VaultV2Error::WrapNotFound);
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
) -> Result<Vec<Vec<u8>>, VaultV2Error> {
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let record = match entry {
            WrapEntry::Password(_) => seal_password(header, password, vk)?,
            WrapEntry::Device(dev) => {
                let publics = devices
                    .iter()
                    .find(|item| item.id == dev.device_id)
                    .ok_or(VaultV2Error::WrapNotFound)?;
                let (record, _grant) = seal_device(header, publics, vk)?;
                record
            }
        };
        records.push(record);
    }
    Ok(records)
}
