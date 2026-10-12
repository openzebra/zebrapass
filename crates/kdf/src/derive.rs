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

/// HKDF info for the inner AEGIS-256 key of a cascade frame.
pub const INFO_CASCADE_AEGIS: &[u8] = b"brby/v2/cascade-aegis";

/// HKDF info for the outer Kuznyechik-CTR key of a cascade frame.
pub const INFO_CASCADE_KUZ: &[u8] = b"brby/v2/cascade-kuz";

/// HKDF info for the outer HMAC-SHA256 key of a cascade frame.
pub const INFO_CASCADE_MAC: &[u8] = b"brby/v2/cascade-mac";

/// HKDF info for the per-device local-metadata file key.
pub const INFO_LOCAL_META: &[u8] = b"brby/v2/local-meta";

/// HKDF info for the key of a shared vault's attestation store.
pub const INFO_SHARED_ATTEST: &[u8] = b"brby/v2/shared-attest";

/// HKDF info for the key of a shared vault's stored peer addresses.
pub const INFO_SHARED_PEERS: &[u8] = b"brby/v2/shared-peers";

/// HKDF info for the gate key of a shared vault's peer-to-peer hello.
pub const INFO_SHARED_GATE: &[u8] = b"brby/v2/shared-gate";

/// HKDF info for the key of a shared vault's member log file.
pub const INFO_SHARED_MEMBERS: &[u8] = b"brby/v2/shared-members";

/// HKDF info for the key of a shared vault's local state file.
pub const INFO_SHARED_STATE: &[u8] = b"brby/v2/shared-state";

/// HKDF info for the key of this device's sealed sync identity file.
pub const INFO_SYNC_IDENTITY: &[u8] = b"brby/v2/sync-identity";

/// HKDF info for the identity scalar derived from the master seed.
pub const INFO_IDENTITY: &[u8] = b"zebrapass/identity/v1";

/// HKDF info for the opaque 64-byte sync client id. Not a public key.
pub const INFO_CLIENT_ID: &[u8] = b"brby/v2/client-id";

/// HKDF info for the 32-byte ML-DSA signing seed.
pub const INFO_SYNC_SIGN: &[u8] = b"brby/v2/sync-sign";

/// HKDF info for the PIN-sealed device key file on this device.
pub const INFO_DEVICE_KEY_FILE: &[u8] = b"brby/v2/device-key-file";

const OUTPUT_LEN: usize = 32;

/// Device key file key.
///
/// HKDF-SHA512 with the Argon2id output of the device PIN as `ikm`, the
/// vault id as salt, and the length-framed file header appended to the
/// info, so every header byte is bound into the key.
///
/// # Errors
///
/// `info part too long` when `file_header` exceeds `u16::MAX` bytes;
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn device_key_file_key(
    pin_key: &[u8; 32],
    vault_id: &[u8; 16],
    file_header: &[u8],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    let info = framed_info(INFO_DEVICE_KEY_FILE, &[file_header])?;
    hkdf_sha512(pin_key, vault_id, &info)
}

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

/// Three independent layer keys `(k_aegis, k_kuz, k_mac)` for one cascade frame.
///
/// HKDF-SHA512 with the frame key as `ikm`, no salt, and one info per
/// layer. A break of one cipher reveals nothing about the other key.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
#[allow(
    clippy::type_complexity,
    reason = "the cross-crate signature is the three layer keys"
)]
pub fn cascade_keys(
    frame_key: &[u8; 32],
) -> anyhow::Result<(
    Secret<[u8; OUTPUT_LEN]>,
    Secret<[u8; OUTPUT_LEN]>,
    Secret<[u8; OUTPUT_LEN]>,
)> {
    let hk = Hkdf::<Sha512>::new(None, frame_key);
    let expand = |info: &[u8]| -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
        let mut okm = Secret::new([0u8; OUTPUT_LEN]);
        hk.expand(info, okm.expose_mut())
            .map_err(|_| anyhow::anyhow!("kdf parameters rejected"))?;
        Ok(okm)
    };
    Ok((
        expand(INFO_CASCADE_AEGIS)?,
        expand(INFO_CASCADE_KUZ)?,
        expand(INFO_CASCADE_MAC)?,
    ))
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

/// Sync-identity file key: HKDF-SHA512 with the vault key as `ikm`, the
/// vault id as salt, and a dedicated info. It never leaves the device.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn sync_identity_key(
    vk: &[u8; 32],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(vk, vault_id, INFO_SYNC_IDENTITY)
}

/// Key of a shared vault's attestation store, from the shared seed.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_attest_key(
    seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(seed, vault_id, INFO_SHARED_ATTEST)
}

/// Key of a shared vault's stored peer addresses, from the shared seed.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_peers_key(
    seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(seed, vault_id, INFO_SHARED_PEERS)
}

/// The key that gates a hello for a shared vault: only holders of the shared
/// seed, which every member has, can compute it.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_gate_key(
    seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(seed, vault_id, INFO_SHARED_GATE)
}

/// Key of a shared vault's member log file, from the shared seed. It needs no
/// vault key, so a device that joined but has not yet received the vault
/// file can already store the log.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_members_key(
    seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(seed, vault_id, INFO_SHARED_MEMBERS)
}

/// Key of a shared vault's local state file (last-seen revisions and
/// revocations), from the shared seed.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn shared_state_key(
    seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<Secret<[u8; OUTPUT_LEN]>> {
    hkdf_sha512(seed, vault_id, INFO_SHARED_STATE)
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

    use super::{
        cascade_keys, client_id, client_id_for, frame_key, identity_seed, local_meta_key,
        sync_identity_key, sync_seed,
    };

    #[test]
    fn cascade_layer_keys_are_distinct_and_deterministic() {
        let (a, k, m) = cascade_keys(&[3u8; 32]).unwrap();
        assert_ne!(a.expose(), k.expose());
        assert_ne!(a.expose(), m.expose());
        assert_ne!(k.expose(), m.expose());
        let (again, _, _) = cascade_keys(&[3u8; 32]).unwrap();
        assert_eq!(a.expose(), again.expose());
        let (other, _, _) = cascade_keys(&[4u8; 32]).unwrap();
        assert_ne!(a.expose(), other.expose());
    }

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
    fn sync_identity_key_is_deterministic_and_domain_separated() {
        let vk = [7u8; 32];
        let vault_id = [9u8; 16];
        let key = sync_identity_key(&vk, &vault_id).unwrap();
        assert_eq!(
            key.expose(),
            sync_identity_key(&vk, &vault_id).unwrap().expose()
        );
        assert_ne!(
            key.expose(),
            local_meta_key(&vk, &vault_id).unwrap().expose()
        );
        assert_ne!(key.expose(), frame_key(&vk, &vault_id, 0).unwrap().expose());
        assert_ne!(
            key.expose(),
            sync_identity_key(&[8u8; 32], &vault_id).unwrap().expose()
        );
    }

    #[test]
    fn shared_keys_are_distinct_from_each_other_and_from_vault_derived_keys() {
        let (seed, vault) = ([3u8; 64], [4u8; 16]);
        let members = super::shared_members_key(&seed, &vault).unwrap();
        let state = super::shared_state_key(&seed, &vault).unwrap();
        let gate = super::shared_gate_key(&seed, &vault).unwrap();
        let attest = super::shared_attest_key(&seed, &vault).unwrap();
        let peers = super::shared_peers_key(&seed, &vault).unwrap();
        for other in [&attest, &gate, &state, &members] {
            assert_ne!(peers.expose(), other.expose());
        }
        assert_ne!(attest.expose(), gate.expose());
        assert_ne!(attest.expose(), state.expose());
        assert_ne!(attest.expose(), members.expose());
        assert_ne!(members.expose(), state.expose());
        assert_ne!(gate.expose(), state.expose());
        assert_ne!(gate.expose(), members.expose());
        assert_ne!(
            members.expose(),
            super::shared_members_key(&[9u8; 64], &vault)
                .unwrap()
                .expose()
        );
        assert_ne!(
            members.expose(),
            super::shared_members_key(&seed, &[9u8; 16])
                .unwrap()
                .expose()
        );
        let vault_derived = local_meta_key(&seed[..32].try_into().unwrap(), &vault).unwrap();
        assert_ne!(members.expose(), vault_derived.expose());
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
