//! Domain-separated derivations over the vault key and the master seed.
//!
//! These are new uses of the existing HKDF-SHA512 primitive; the KDF
//! parameters, the wraps, and the container format are unchanged. The
//! infos live here next to the derivations that use them.

// Module name shadows the `hkdf` crate.
extern crate hkdf as hkdf_impl;

use hkdf_impl::Hkdf;
use secret::Secret;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::hkdf::hkdf_sha512;

/// HKDF info for a per-record frame key.
pub const INFO_FRAME_KEY: &[u8] = b"brby/v2/frame-key";

/// HKDF info for the per-device local-metadata file key.
pub const INFO_LOCAL_META: &[u8] = b"brby/v2/local-meta";

/// HKDF info for the identity scalar derived from the master seed.
pub const INFO_IDENTITY: &[u8] = b"zebrapass/identity/v1";

/// HKDF info for the opaque 64-byte sync client id. Not a public key.
pub const INFO_CLIENT_ID: &[u8] = b"brby/v2/client-id";

/// HKDF info for the 32-byte ML-DSA signing seed.
pub const INFO_SYNC_SIGN: &[u8] = b"brby/v2/sync-sign";

const OUTPUT_LEN: usize = 32;

/// Per-record frame key: HKDF-SHA512 with the vault key as `ikm`, the
/// vault id as salt, and the record id appended to the info. Two records
/// in one vault derive independent keys.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn frame_key(
    vk: &[u8; 32],
    vault_id: &[u8; 16],
    record_id: u32,
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    let mut info = Vec::with_capacity(INFO_FRAME_KEY.len() + 4);
    info.extend_from_slice(INFO_FRAME_KEY);
    info.extend_from_slice(&record_id.to_le_bytes());
    hkdf_sha512(vk, vault_id, &info)
}

/// Local-metadata file key: HKDF-SHA512 with the vault key as `ikm`, the
/// vault id as salt, and a dedicated info. One file per device; it never
/// leaves the device.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn local_meta_key(
    vk: &[u8; 32],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(vk, vault_id, INFO_LOCAL_META)
}

/// Identity seed: HKDF-SHA512 with the 64-byte master seed as `ikm`, no
/// salt, and a dedicated info. The same seed yields the same scalar on
/// every device.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn identity_seed(seed: &[u8; 64]) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; OUTPUT_LEN]);
    hk.expand(INFO_IDENTITY, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(Secret::new(*okm))
}

/// Opaque 64-byte sync client id. Not a public key and not [`identity_seed`].
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn client_id(seed: &[u8; 64]) -> anyhow::Result<[u8; 64]> {
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(INFO_CLIENT_ID, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// Account id for one server: the per-server HKDF variant.
///
/// `HKDF(seed, INFO_CLIENT_ID || server_origin)` — the same origin always
/// yields the same id; different origins yield unlinkable ids, so a server
/// cannot correlate one account across other servers.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn client_id_for(seed: &[u8; 64], server_origin: &[u8]) -> anyhow::Result<[u8; 64]> {
    if server_origin.is_empty() {
        return Err(anyhow::anyhow!("empty server origin"));
    }
    let info = framed_info(INFO_CLIENT_ID, &[server_origin])?;
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(&info, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(*okm)
}

/// 32-byte ML-DSA signing seed. Wiped on drop.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn sync_seed(seed: &[u8; 64]) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; OUTPUT_LEN]);
    hk.expand(INFO_SYNC_SIGN, okm.as_mut())
        .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
    Ok(Secret::new(*okm))
}

/// Builds `label || u16 len || part` per part, so variable parts can never
/// alias a shorter label or a sibling part.
fn framed_info(label: &[u8], parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let cap = label.len() + parts.iter().map(|part| 2 + part.len()).sum::<usize>();
    let mut info = Vec::with_capacity(cap);
    info.extend_from_slice(label);
    for part in parts {
        let len = u16::try_from(part.len()).map_err(|_| anyhow::anyhow!("info part too long"))?;
        info.extend_from_slice(&len.to_be_bytes());
        info.extend_from_slice(part);
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{client_id, client_id_for, frame_key, identity_seed, local_meta_key, sync_seed};

    #[test]
    fn frame_keys_are_record_separated() {
        let vk = [7u8; 32];
        let vault_id = [9u8; 16];
        let a = frame_key(&vk, &vault_id, 1).unwrap();
        let b = frame_key(&vk, &vault_id, 2).unwrap();
        assert_ne!(a.expose(), b.expose());
        let same = frame_key(&vk, &vault_id, 1).unwrap();
        assert_eq!(a.expose(), same.expose());
        // A different vault derives different keys from the same vk.
        let other_vault = frame_key(&vk, &[8u8; 16], 1).unwrap();
        assert_ne!(a.expose(), other_vault.expose());
    }

    #[test]
    fn local_meta_key_is_deterministic_and_distinct() {
        let vk = [7u8; 32];
        let vault_id = [9u8; 16];
        let meta = local_meta_key(&vk, &vault_id).unwrap();
        let again = local_meta_key(&vk, &vault_id).unwrap();
        assert_eq!(meta.expose(), again.expose());
        let frame = frame_key(&vk, &vault_id, 0).unwrap();
        assert_ne!(meta.expose(), frame.expose());
    }

    #[test]
    fn identity_seed_is_deterministic_and_seed_separated() {
        let seed = [5u8; 64];
        let a = identity_seed(&seed).unwrap();
        let b = identity_seed(&seed).unwrap();
        assert_eq!(a.expose(), b.expose());
        let other = identity_seed(&[6u8; 64]).unwrap();
        assert_ne!(a.expose(), other.expose());
    }

    #[test]
    fn client_id_and_sync_seed_are_seed_separated() {
        let seed = [5u8; 64];
        let id = client_id(&seed).unwrap();
        assert_eq!(id, client_id(&seed).unwrap());
        assert_ne!(id, client_id(&[6u8; 64]).unwrap());
        let signing = sync_seed(&seed).unwrap();
        let again = sync_seed(&seed).unwrap();
        assert_eq!(signing.expose(), again.expose());
        assert_ne!(signing.expose(), sync_seed(&[6u8; 64]).unwrap().expose());
        let ident = identity_seed(&seed).unwrap();
        assert_ne!(signing.expose(), ident.expose());
        assert_ne!(&id[..32], ident.expose());
    }

    #[test]
    fn per_server_client_ids_are_stable_and_unlinkable() {
        let seed = [0x24u8; 64];
        let a = client_id_for(&seed, b"https://vaults.example").unwrap();
        let b = client_id_for(&seed, b"https://vaults.example").unwrap();
        assert_eq!(a, b, "same origin always gives the same id");
        let other = client_id_for(&seed, b"https://other.example").unwrap();
        assert_ne!(a, other, "different origins give unlinkable ids");
        // The plain client id stays a distinct derivation.
        assert_ne!(a, client_id(&seed).unwrap());
    }

    #[test]
    fn empty_server_origin_is_rejected() {
        let seed = [0x24u8; 64];
        assert!(client_id_for(&seed, b"").is_err());
    }

    #[test]
    fn framed_origins_cannot_alias_their_prefixes() {
        let seed = [0x11u8; 64];
        let ab = client_id_for(&seed, b"ab").unwrap();
        assert_ne!(ab, client_id(&seed).unwrap());
        assert_ne!(ab, client_id_for(&seed, b"a").unwrap());
        assert_ne!(ab, client_id_for(&seed, b"abc").unwrap());
    }
}
