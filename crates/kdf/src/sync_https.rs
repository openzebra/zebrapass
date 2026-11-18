//! Domain-separated HKDF-SHA512 keys for zero-knowledge HTTPS sync,
//! quantum-safe backups, and personal vault key-rotation grants.

use secret::Secret;

use crate::derive::framed_info;
use crate::hkdf::hkdf_sha512;
use crate::p2p::p2p_key;

/// HKDF info for sealing the auxiliary payload of a `.zpbackup` bundle.
pub const INFO_BACKUP_SEAL: &[u8] = b"brby/v2/backup-seal";

/// HKDF info for the whole-bundle HMAC commitment key of a `.zpbackup` file.
pub const INFO_BACKUP_COMMIT: &[u8] = b"brby/v2/backup-commit";

/// HKDF info for outer-sealing an encrypted cloud backup stored on a sync server.
pub const INFO_CLOUD_BACKUP: &[u8] = b"brby/v2/cloud-backup";

/// HKDF info for deriving per-server unlinkable mailbox identifiers.
pub const INFO_SYNC_MAILBOX: &[u8] = b"brby/v2/sync-mailbox";

/// HKDF info for outer-sealing sync payloads uploaded to a sync server.
pub const INFO_SYNC_ENVELOPE: &[u8] = b"brby/v2/sync-envelope";

/// HKDF info for sealing a rotated personal vault key to a peer device.
pub const INFO_PERSONAL_REKEY: &[u8] = b"brby/v2/personal-rekey";

/// Pair of `(k_seal, k_commit)` keys derived for a `.zpbackup` bundle.
pub type BackupKeys = (Secret<[u8; 32]>, Secret<[u8; 32]>);

/// Derive `(k_seal, k_commit)` for a `.zpbackup` bundle from the personal vault
/// key `vk`, `vault_id`, and length-framed `header_bytes`.
///
/// # Errors
///
/// `info part too long` when `header_bytes` exceeds `u16::MAX` bytes;
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn backup_keys(
    vk: &[u8; 32],
    vault_id: &[u8; 16],
    header_bytes: &[u8],
) -> anyhow::Result<BackupKeys> {
    let seal_info = framed_info(INFO_BACKUP_SEAL, &[header_bytes])?;
    let commit_info = framed_info(INFO_BACKUP_COMMIT, &[header_bytes])?;
    Ok((
        hkdf_sha512(vk, vault_id, &seal_info)?,
        hkdf_sha512(vk, vault_id, &commit_info)?,
    ))
}

/// Derive the outer-envelope key for a cloud backup uploaded to `box_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn cloud_backup_key(
    account_gate: &[u8; 32],
    box_id: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_CLOUD_BACKUP, &[box_id])?;
    hkdf_sha512(account_gate, &[0u8; 16], &info)
}

/// Derive a per-server unlinkable 32-byte mailbox identifier for a personal vault.
///
/// # Errors
///
/// `empty server origin` when `server_origin` is empty; `info part too long`
/// when `server_origin` exceeds `u16::MAX` bytes; `kdf parameters rejected`
/// when HKDF-Expand fails.
pub fn personal_mailbox_id(
    account_gate: &[u8; 32],
    server_origin: &str,
) -> anyhow::Result<[u8; 32]> {
    if server_origin.is_empty() {
        return Err(anyhow::anyhow!("empty server origin"));
    }
    let info = framed_info(INFO_SYNC_MAILBOX, &[b"personal", server_origin.as_bytes()])?;
    let okm = hkdf_sha512(account_gate, &[0u8; 16], &info)?;
    Ok(*okm.expose())
}

/// Derive the outer-envelope cascade key for personal sync payloads in `box_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn personal_envelope_key(
    account_gate: &[u8; 32],
    box_id: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_SYNC_ENVELOPE, &[b"personal", box_id])?;
    hkdf_sha512(account_gate, &[0u8; 16], &info)
}

/// Derive a per-server unlinkable 32-byte mailbox identifier for a shared vault.
///
/// # Errors
///
/// `empty server origin` when `server_origin` is empty; `info part too long`
/// when `server_origin` exceeds `u16::MAX` bytes; `kdf parameters rejected`
/// when HKDF-Expand fails.
pub fn shared_mailbox_id(
    shared_seed: &[u8; 64],
    vault_id: &[u8; 16],
    server_origin: &str,
) -> anyhow::Result<[u8; 32]> {
    if server_origin.is_empty() {
        return Err(anyhow::anyhow!("empty server origin"));
    }
    let info = framed_info(INFO_SYNC_MAILBOX, &[b"shared", server_origin.as_bytes()])?;
    let okm = hkdf_sha512(shared_seed, vault_id, &info)?;
    Ok(*okm.expose())
}

/// Derive the outer-envelope cascade key for shared sync payloads in `box_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_envelope_key(
    shared_seed: &[u8; 64],
    box_id: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_SYNC_ENVELOPE, &[b"shared", box_id])?;
    hkdf_sha512(shared_seed, &[0u8; 16], &info)
}

/// Derive the hybrid P-256 + ML-KEM-768 key that seals a rotated personal vault
/// key to one non-revoked peer device.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn personal_rekey_key(
    ss_kem: &Secret<[u8; 32]>,
    ss_ec: &Secret<[u8; 32]>,
    vault_id: &[u8; 16],
    transcript: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    p2p_key(INFO_PERSONAL_REKEY, ss_kem, ss_ec, vault_id, transcript)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secret::Secret;

    use super::{
        backup_keys, cloud_backup_key, personal_envelope_key, personal_mailbox_id,
        personal_rekey_key, shared_envelope_key, shared_mailbox_id,
    };

    #[test]
    fn backup_keys_are_deterministic_and_separated() {
        let vk = [0x11; 32];
        let vault_id = [0x22; 16];
        let (seal_a, commit_a) = backup_keys(&vk, &vault_id, b"hdr-1").unwrap();
        let (seal_b, commit_b) = backup_keys(&vk, &vault_id, b"hdr-1").unwrap();
        assert_eq!(seal_a.expose(), seal_b.expose());
        assert_eq!(commit_a.expose(), commit_b.expose());
        assert_ne!(seal_a.expose(), commit_a.expose());

        let (seal_c, commit_c) = backup_keys(&vk, &vault_id, b"hdr-2").unwrap();
        assert_ne!(seal_a.expose(), seal_c.expose());
        assert_ne!(commit_a.expose(), commit_c.expose());

        let (seal_d, _) = backup_keys(&vk, &[0x23; 16], b"hdr-1").unwrap();
        assert_ne!(seal_a.expose(), seal_d.expose());
    }

    #[test]
    fn mailbox_and_envelope_keys_separate_origins_roles_and_purposes() {
        let gate = [0x33; 32];
        let seed = [0x44; 64];
        let vault = [0x55; 16];
        let box_a = personal_mailbox_id(&gate, "https://a.example").unwrap();
        let box_b = personal_mailbox_id(&gate, "https://b.example").unwrap();
        assert_eq!(
            box_a,
            personal_mailbox_id(&gate, "https://a.example").unwrap()
        );
        assert_ne!(box_a, box_b);
        assert!(personal_mailbox_id(&gate, "").is_err());

        let sbox_a = shared_mailbox_id(&seed, &vault, "https://a.example").unwrap();
        let sbox_b = shared_mailbox_id(&seed, &vault, "https://b.example").unwrap();
        assert_ne!(sbox_a, sbox_b);
        assert_ne!(sbox_a, box_a);
        assert!(shared_mailbox_id(&seed, &vault, "").is_err());

        let env_p = personal_envelope_key(&gate, &box_a).unwrap();
        let cloud_p = cloud_backup_key(&gate, &box_a).unwrap();
        let env_s = shared_envelope_key(&seed, &sbox_a).unwrap();
        assert_ne!(env_p.expose(), cloud_p.expose());
        assert_ne!(env_p.expose(), env_s.expose());
        assert_ne!(env_p.expose(), &box_a);
    }

    #[test]
    fn personal_rekey_key_differs_from_share_grant_and_p2p_keys() {
        let kem = Secret::new([1u8; 32]);
        let ec = Secret::new([2u8; 32]);
        let vault = [3u8; 16];
        let th = [4u8; 32];
        let k1 = personal_rekey_key(&kem, &ec, &vault, &th).unwrap();
        let k2 = crate::share_grant_key(&kem, &ec, &vault, &th).unwrap();
        let k3 = crate::p2p_key(crate::INFO_P2P_APP_I2R, &kem, &ec, &vault, &th).unwrap();
        assert_ne!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
        assert_eq!(
            k1.expose(),
            personal_rekey_key(&kem, &ec, &vault, &th).unwrap().expose()
        );
    }
}
