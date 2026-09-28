//! Device-factor helpers shared by the session integration tests.
//!
//! A device factor is a chip-kind wrap whose private halves live in a
//! [`local::DeviceKey`]; opening it runs `ECDH(key, eph_pub)` against the
//! ephemeral key the wrap directory publishes.

#![allow(
    dead_code,
    clippy::unwrap_used,
    reason = "each test binary uses a subset of these helpers"
)]

use local::DeviceKey;
use session::{
    add_chip_unlock, unlock, wrap_directory, ChipPublics, Factor, Seen, Session, UnlockCreds,
    VaultFile,
};

/// A fresh device key and its publics.
pub fn device() -> (ChipPublics, DeviceKey) {
    let key = DeviceKey::generate().unwrap();
    (key.publics().unwrap(), key)
}

/// Enroll a fresh device on `file` and return its key.
pub fn enroll(session: &mut Session, file: &mut VaultFile) -> DeviceKey {
    let (publics, key) = device();
    add_chip_unlock(session, file, &publics).unwrap();
    key
}

/// The ephemeral P-256 key of the device wrap with `id`.
///
/// # Errors
///
/// `wrap not found` when the file has no device wrap with `id`.
pub fn eph_pub(file: &VaultFile, id: &[u8; 16]) -> anyhow::Result<[u8; 65]> {
    wrap_directory(file)?
        .factors
        .iter()
        .find_map(|factor| match factor {
            Factor::Chip(chip) if chip.publics.id == *id => Some(chip.eph_pub),
            Factor::Chip(_) | Factor::Recovery | Factor::Password { .. } | Factor::Prf { .. } => {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("wrap not found"))
}

/// Unlock `file` with the device factor `key`.
///
/// # Errors
///
/// `wrap not found` when the wrap is gone; unlock errors otherwise.
pub fn unlock_device(file: &VaultFile, key: &DeviceKey) -> anyhow::Result<Session> {
    unlock_device_seen(file, key, None)
}

/// [`unlock_device`] with a rollback cursor.
///
/// # Errors
///
/// As in [`unlock_device`], plus `rollback` / `conflict`.
pub fn unlock_device_seen(
    file: &VaultFile,
    key: &DeviceKey,
    seen: Option<Seen>,
) -> anyhow::Result<Session> {
    let shared = key.ecdh(&eph_pub(file, key.id())?)?;
    unlock(
        file,
        &UnlockCreds::default().with_chip(key.chip_keys(), *shared.expose()),
        seen,
    )
}
