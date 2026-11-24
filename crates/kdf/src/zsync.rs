//! Domain-separated HKDF-SHA512 keys for unified PQ TLS sync, live P2P
//! relay slots, quantum-safe backups, and personal vault key-rotation grants.

extern crate hkdf as hkdf_impl;

use hkdf_impl::Hkdf;
use secret::Secret;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::derive::framed_info;
use crate::hkdf::hkdf_sha512;
use crate::p2p::p2p_key;

/// HKDF info for sealing the auxiliary payload of a `.zpbackup` bundle.
pub const INFO_BACKUP_SEAL: &[u8] = b"brby/v2/backup-seal";

/// HKDF info for the whole-bundle HMAC commitment key of a `.zpbackup` file.
pub const INFO_BACKUP_COMMIT: &[u8] = b"brby/v2/backup-commit";

/// HKDF info for sealing a rotated personal vault key to a peer device.
pub const INFO_PERSONAL_REKEY: &[u8] = b"brby/v2/personal-rekey";

/// HKDF info for sealing a rotated shared vault seed to a remaining member device.
pub const INFO_SHARED_REKEY: &[u8] = b"brby/v3/shared-rekey";

/// HKDF info for deriving a canonical 512-bit personal storage identifier.
pub const INFO_PERSONAL_STORAGE: &[u8] = b"brby/v3/personal-storage";

/// HKDF info for deriving the dedicated personal sync anchor ML-DSA seed.
pub const INFO_ZSYNC_PERSONAL_ROOT: &[u8] = b"brby/v3/zsync-personal-root";

/// HKDF info for deriving a self-certifying personal storage identifier from its anchor VK.
pub const INFO_ZSYNC_PERSONAL_SID: &[u8] = b"brby/v3/zsync-personal-sid";

/// HKDF info for outer-sealing personal sync payloads under the active vault key.
pub const INFO_ZSYNC_VK_ENVELOPE: &[u8] = b"brby/v3/zsync-vk-envelope";

/// HKDF info for sealing the active vault key to the account's recovery seed.
pub const INFO_ZSYNC_MASTER_GRANT: &[u8] = b"brby/v3/zsync-master-grant";

/// HKDF info for deriving a shared repository's self-certifying ML-DSA seed.
pub const INFO_ZSYNC_SHARED_REPO_SIGN: &[u8] = b"brby/v3/zsync-shared-repo-sign";

/// HKDF info for deriving a self-certifying shared storage identifier from its repo VK.
pub const INFO_ZSYNC_SHARED_SID: &[u8] = b"brby/v3/zsync-shared-sid";

/// HKDF info for deriving a canonical 512-bit shared storage identifier.
pub const INFO_SHARED_STORAGE: &[u8] = b"brby/v3/shared-storage";

/// HKDF info for outer-sealing versioned sync payloads across Zebra servers.
pub const INFO_ZSYNC_ENVELOPE: &[u8] = b"brby/v3/zsync-envelope";

/// HKDF info for deterministic zero-storage live P2P relay slots.
pub const INFO_ZSYNC_RELAY_SLOT: &[u8] = b"brby/v3/zsync-relay-slot";

/// HKDF info for authenticating live relay slot reservations.
pub const INFO_ZSYNC_RELAY_AUTH: &[u8] = b"brby/v3/zsync-relay-auth";

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

/// Derive the canonical server-independent 512-bit (`[u8; 64]`) personal
/// storage identifier from the 512-bit root seed.
///
/// Because this identifier does not bind a server origin, all devices and all
/// servers (`ru.zebra.sh`, `eu.zebra.sh`, `zh.zebra.sh`, or custom) address the
/// same encrypted repository.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn storage_id(seed: &[u8; 64]) -> anyhow::Result<[u8; 64]> {
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(INFO_PERSONAL_STORAGE, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// Derive the dedicated 32-byte ML-DSA signing seed for anchoring a personal
/// sync repository, separated from the public contact-card root key.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn zsync_personal_root_seed(master_seed: &[u8; 64]) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(master_seed, &[0u8; 16], INFO_ZSYNC_PERSONAL_ROOT)
}

/// Derive the self-certifying 512-bit personal storage identifier directly
/// from the personal repository anchor's ML-DSA verifying key.
///
/// # Errors
///
/// `kdf parameters rejected` when `anchor_vk` is empty or HKDF-Expand fails.
pub fn personal_storage_id_from_vk(anchor_vk: &[u8]) -> anyhow::Result<[u8; 64]> {
    if anchor_vk.is_empty() {
        anyhow::bail!("kdf parameters rejected");
    }
    let hk = Hkdf::<Sha512>::new(None, anchor_vk);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(INFO_ZSYNC_PERSONAL_SID, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// Derive the outer-envelope cascade key for personal sync payloads from the
/// active vault key `vk` and `storage_id` so revoked devices cannot open
/// post-rotation heads or frames.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn zsync_vk_envelope_key(
    vk: &[u8; 32],
    storage_id: &[u8; 64],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_ZSYNC_VK_ENVELOPE, &[storage_id])?;
    hkdf_sha512(vk, &[0u8; 16], &info)
}

/// Derive the recovery-phrase key that seals the current personal vault key
/// inside `SignedHead` so BIP39 phrase restores can recover without any peer.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn zsync_master_grant_key(
    master_seed: &[u8; 64],
    storage_id: &[u8; 64],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_ZSYNC_MASTER_GRANT, &[storage_id])?;
    hkdf_sha512(master_seed, &[0u8; 16], &info)
}

/// Derive the 32-byte ML-DSA signing seed proving possession of `shared_seed`
/// when initializing a shared sync repository for `vault_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_repo_sign_seed(
    shared_seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(shared_seed, vault_id, INFO_ZSYNC_SHARED_REPO_SIGN)
}

/// Derive the self-certifying 512-bit shared storage identifier from its
/// ML-DSA verifying key `repo_vk` and `vault_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when `repo_vk` is empty or HKDF-Expand fails.
pub fn shared_storage_id_from_vk(repo_vk: &[u8], vault_id: &[u8; 16]) -> anyhow::Result<[u8; 64]> {
    if repo_vk.is_empty() {
        anyhow::bail!("kdf parameters rejected");
    }
    let hk = Hkdf::<Sha512>::new(Some(vault_id.as_slice()), repo_vk);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(INFO_ZSYNC_SHARED_SID, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// Derive the canonical server-independent 512-bit (`[u8; 64]`) shared
/// storage identifier from `shared_seed` and `vault_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_storage_id(shared_seed: &[u8; 64], vault_id: &[u8; 16]) -> anyhow::Result<[u8; 64]> {
    let hk = Hkdf::<Sha512>::new(Some(vault_id.as_slice()), shared_seed);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(INFO_SHARED_STORAGE, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// Derive the outer-envelope cascade key for personal sync payloads under
/// `storage_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn personal_envelope_key(
    account_gate: &[u8; 32],
    storage_id: &[u8; 64],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_ZSYNC_ENVELOPE, &[b"personal", storage_id])?;
    hkdf_sha512(account_gate, &[0u8; 16], &info)
}

/// Derive the outer-envelope cascade key for shared sync payloads under
/// `storage_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_envelope_key(
    shared_seed: &[u8; 64],
    storage_id: &[u8; 64],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_ZSYNC_ENVELOPE, &[b"shared", storage_id])?;
    hkdf_sha512(shared_seed, &[0u8; 16], &info)
}

/// Derive a deterministic 16-byte relay rendezvous slot from `secret_ikm`
/// (`account_gate` or `shared_seed`) and `storage_id`.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn zsync_relay_slot(secret_ikm: &[u8], storage_id: &[u8; 64]) -> anyhow::Result<[u8; 16]> {
    let info = framed_info(INFO_ZSYNC_RELAY_SLOT, &[storage_id])?;
    let okm = hkdf_sha512(secret_ikm, &[0u8; 16], &info)?;
    let (slot, _) = okm
        .expose()
        .split_first_chunk::<16>()
        .ok_or_else(|| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*slot)
}

/// Derive the 32-byte HMAC key proving authorization to reserve `slot` on a
/// live relay hub.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn zsync_relay_auth_key(
    secret_ikm: &[u8],
    slot: &[u8; 16],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let info = framed_info(INFO_ZSYNC_RELAY_AUTH, &[slot])?;
    hkdf_sha512(secret_ikm, &[0u8; 16], &info)
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

/// Derive the hybrid P-256 + ML-KEM-768 key that seals a rotated shared vault
/// seed to one remaining member device.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_rekey_key(
    ss_kem: &Secret<[u8; 32]>,
    ss_ec: &Secret<[u8; 32]>,
    vault_id: &[u8; 16],
    transcript: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    p2p_key(INFO_SHARED_REKEY, ss_kem, ss_ec, vault_id, transcript)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secret::Secret;

    use super::{
        backup_keys, personal_envelope_key, personal_rekey_key, personal_storage_id_from_vk,
        shared_envelope_key, shared_rekey_key, shared_repo_sign_seed, shared_storage_id,
        shared_storage_id_from_vk, storage_id, zsync_master_grant_key, zsync_personal_root_seed,
        zsync_relay_auth_key, zsync_relay_slot, zsync_vk_envelope_key,
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
    fn storage_ids_and_envelope_keys_are_server_independent_and_separated() {
        let root_seed = [0x17; 64];
        let gate = [0x33; 32];
        let shared_seed = [0x44; 64];
        let vault = [0x55; 16];

        let p_id = storage_id(&root_seed).unwrap();
        assert_eq!(p_id, storage_id(&root_seed).unwrap());
        assert_ne!(p_id, storage_id(&[0x18; 64]).unwrap());
        assert_ne!(p_id, crate::client_id(&root_seed).unwrap());

        let s_id = shared_storage_id(&shared_seed, &vault).unwrap();
        assert_eq!(s_id, shared_storage_id(&shared_seed, &vault).unwrap());
        assert_ne!(s_id, shared_storage_id(&shared_seed, &[0x56; 16]).unwrap());
        assert_ne!(s_id, p_id);

        let anchor_seed = zsync_personal_root_seed(&root_seed).unwrap();
        assert_ne!(
            anchor_seed.expose(),
            crate::sync_seed(&root_seed).unwrap().expose()
        );
        let p_vk_sid = personal_storage_id_from_vk(&[0xAB; 1952]).unwrap();
        let s_vk_sid = shared_storage_id_from_vk(&[0xAB; 1952], &vault).unwrap();
        assert_ne!(p_vk_sid, s_vk_sid);
        assert!(personal_storage_id_from_vk(&[]).is_err());
        assert!(shared_storage_id_from_vk(&[], &vault).is_err());

        let env_p = personal_envelope_key(&gate, &p_id).unwrap();
        let env_vk = zsync_vk_envelope_key(&gate, &p_id).unwrap();
        let mg = zsync_master_grant_key(&root_seed, &p_id).unwrap();
        let env_s = shared_envelope_key(&shared_seed, &s_id).unwrap();
        assert_ne!(env_p.expose(), env_s.expose());
        assert_ne!(env_p.expose(), env_vk.expose());
        assert_ne!(env_vk.expose(), mg.expose());
        assert_ne!(env_p.expose(), &p_id[..32]);

        let repo_sign = shared_repo_sign_seed(&shared_seed, &vault).unwrap();
        assert_ne!(repo_sign.expose(), env_s.expose());

        let slot_p = zsync_relay_slot(&gate, &p_id).unwrap();
        let slot_s = zsync_relay_slot(&shared_seed, &s_id).unwrap();
        assert_ne!(slot_p, slot_s);
        assert_eq!(slot_p, zsync_relay_slot(&gate, &p_id).unwrap());
        let auth_p = zsync_relay_auth_key(&gate, &slot_p).unwrap();
        assert_ne!(&auth_p.expose()[..16], &slot_p);
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
        let k4 = shared_rekey_key(&kem, &ec, &vault, &th).unwrap();
        assert_ne!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
        assert_ne!(k1.expose(), k4.expose());
        assert_eq!(
            k1.expose(),
            personal_rekey_key(&kem, &ec, &vault, &th).unwrap().expose()
        );
    }
}
