//! This device's unlock factor: a device wrap (P-256 ECDH + ML-KEM-768)
//! whose private halves live in the vault's PIN-sealed `device.key` file.
//!
//! A terminal app cannot reach the Secure Enclave, so the keys never sit in
//! the OS keychain: unlocking takes this disk and the PIN.

use kdf::KdfProfile;
use local::{device_key_info, open_device_key, seal_device_key, DeviceKey, Paths};
use session::{
    add_chip_unlock, unlock as open_vault, wrap_directory, Factor, Session, UnlockCreds, VaultFile,
};

/// Argon2id preset a new device PIN is stretched with.
pub const PIN_PROFILE: KdfProfile = KdfProfile::Strong;

/// The device wrap this machine holds a key file for, read without the PIN.
#[must_use]
pub fn owned_id(paths: &Paths) -> Option<[u8; 16]> {
    device_key_info(&paths.device_key).ok().map(|info| info.id)
}

/// Generate device keys, seal them under `pin`, and add their device wrap.
///
/// The key file is written first and removed again when the wrap cannot be
/// added, so no wrap exists that nothing can open.
///
/// # Errors
///
/// `device PIN length`, entropy, storage, and `session::add_chip_unlock`
/// errors.
pub fn enroll(
    session: &mut Session,
    file: &mut VaultFile,
    paths: &Paths,
    pin: &[u8],
    profile: KdfProfile,
) -> anyhow::Result<()> {
    let key = DeviceKey::generate()?;
    seal_device_key(&paths.device_key, session.vault_id(), &key, pin, profile)?;
    if let Err(error) = key
        .publics()
        .and_then(|publics| add_chip_unlock(session, file, &publics))
    {
        let _ = std::fs::remove_file(&paths.device_key);
        return Err(error);
    }
    Ok(())
}

/// Open `file` with this device's key file and `pin`.
///
/// # Errors
///
/// `no usable wrap` when the file has no wrap for this device's key;
/// key-file and unlock errors otherwise.
pub fn unlock(file: &VaultFile, paths: &Paths, pin: &[u8]) -> anyhow::Result<Session> {
    let vault_id = file.parse()?.header.vault_id;
    let key = open_device_key(&paths.device_key, &vault_id, pin)?;
    let eph_pub = wrap_directory(file)?
        .factors
        .iter()
        .find_map(|factor| match factor {
            Factor::Chip(chip) if chip.publics.id == *key.id() => Some(chip.eph_pub),
            Factor::Chip(_) | Factor::Recovery | Factor::Password { .. } | Factor::Prf { .. } => {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("no usable wrap"))?;
    let shared = key.ecdh(&eph_pub)?;
    open_vault(
        file,
        &UnlockCreds::default().with_chip(key.chip_keys(), *shared.expose()),
        None,
    )
}

/// Re-seal this device's key file under `new_pin`; the vault is untouched.
///
/// # Errors
///
/// `the current PIN is not correct` when `current` does not open the key
/// file (or the file is damaged); `device PIN length` and storage errors
/// when re-sealing fails.
pub fn change_pin(
    paths: &Paths,
    vault_id: &[u8; 16],
    current: &[u8],
    new_pin: &[u8],
    profile: KdfProfile,
) -> anyhow::Result<()> {
    let key = open_device_key(&paths.device_key, vault_id, current)
        .map_err(|_| anyhow::anyhow!("the current PIN is not correct"))?;
    seal_device_key(&paths.device_key, vault_id, &key, new_pin, profile)
}

/// Delete the key file when it belongs to device wrap `id`.
pub fn forget(paths: &Paths, id: &[u8; 16]) {
    if owned_id(paths).is_some_and(|owned| owned == *id) {
        let _ = std::fs::remove_file(&paths.device_key);
    }
}
