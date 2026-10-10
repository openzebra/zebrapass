//! Keys of the peer-to-peer channel: two handshake keys that protect the
//! certificate exchange and two traffic keys, one per direction.

use secret::Secret;

use crate::hkdf::hkdf_sha512;

/// HKDF info of the key that seals the responder's certificate and proof.
pub const INFO_P2P_HS_R2I: &[u8] = b"brby/v2/p2p-hs-r2i";

/// HKDF info of the key that seals the initiator's certificate and proof.
pub const INFO_P2P_HS_I2R: &[u8] = b"brby/v2/p2p-hs-i2r";

/// HKDF info of the initiator-to-responder traffic key.
pub const INFO_P2P_APP_I2R: &[u8] = b"brby/v2/p2p-app-i2r";

/// HKDF info of the responder-to-initiator traffic key.
pub const INFO_P2P_APP_R2I: &[u8] = b"brby/v2/p2p-app-r2i";

/// HKDF info of the key that gates the first handshake message.
pub const INFO_P2P_GATE: &[u8] = b"brby/v2/p2p-gate";

/// The key that authenticates a hello before any asymmetric work is done.
///
/// `secret` is what only the intended peers know: the vault key of a vault,
/// or the one-time secret of an invitation. Salted with the vault id.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn p2p_gate_key(secret: &[u8; 32], vault_id: &[u8; 16]) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(secret, vault_id, INFO_P2P_GATE)
}

/// HKDF info of the secret every device of one account derives its personal
/// vault's hello gate from.
pub const INFO_P2P_ACCOUNT_GATE: &[u8] = b"brby/v2/p2p-account-gate";

/// HKDF info of the id a personal vault is addressed by before its real
/// vault id is known to the dialing device.
pub const INFO_P2P_ACCOUNT_ROUTE: &[u8] = b"brby/v2/p2p-account-route";

/// HKDF info of the key that seals a LAN beacon.
pub const INFO_P2P_BEACON: &[u8] = b"brby/v2/p2p-beacon";

/// HKDF info of the key that seals a personal vault's stored peer addresses.
pub const INFO_PERSONAL_PEERS: &[u8] = b"brby/v2/personal-peers";

/// The secret behind the hello gate of an account's personal vault, from the
/// 64-byte seed. Every device that was enrolled with the phrase keeps it in
/// its sealed identity; the seed itself is never kept.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn account_gate_secret(seed: &[u8; 64]) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(seed, &[0u8; 16], INFO_P2P_ACCOUNT_GATE)
}

/// The key that seals the LAN beacons of one account, from its gate secret.
/// Only a device that holds the account's phrase can open or make one.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn p2p_beacon_key(gate_secret: &Secret<[u8; 32]>) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(gate_secret.expose(), &[0u8; 16], INFO_P2P_BEACON)
}

/// The id a personal vault is addressed by in the handshake.
///
/// A device that only holds the phrase does not know the vault's own id yet,
/// so both sides salt the handshake with this one, which they derive from the
/// gate secret.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn account_route_id(gate_secret: &Secret<[u8; 32]>) -> anyhow::Result<[u8; 16]> {
    let okm = hkdf_sha512(gate_secret.expose(), &[0u8; 16], INFO_P2P_ACCOUNT_ROUTE)?;
    okm.expose()
        .first_chunk::<16>()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("kdf parameters rejected"))
}

/// Key of a personal vault's stored peer addresses, from the vault key.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn personal_peers_key(vk: &[u8; 32], vault_id: &[u8; 16]) -> anyhow::Result<Secret<[u8; 32]>> {
    hkdf_sha512(vk, vault_id, INFO_PERSONAL_PEERS)
}

/// HKDF info of the key that wraps a shared-vault seed for one invitee.
pub const INFO_SHARE_GRANT: &[u8] = b"brby/v2/share-grant";

/// The key that seals a shared-vault seed to one invitee's device, from both
/// shared secrets of the hybrid exchange and a transcript that binds the
/// vault, its member log and the invitee's card.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn share_grant_key(
    ss_kem: &Secret<[u8; 32]>,
    ss_ec: &Secret<[u8; 32]>,
    vault_id: &[u8; 16],
    transcript: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    p2p_key(INFO_SHARE_GRANT, ss_kem, ss_ec, vault_id, transcript)
}

/// A channel key from both shared secrets of the hybrid exchange.
///
/// HKDF-SHA512 over the ML-KEM secret then the ECDH secret, so breaking one
/// half is not enough, salted with the vault id, with the `label` and the
/// 32-byte transcript hash framed into the info. The transcript covers every
/// public key and ciphertext, so the key binds the whole exchange.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF-Expand rejects the output length.
pub fn p2p_key(
    label: &[u8],
    ss_kem: &Secret<[u8; 32]>,
    ss_ec: &Secret<[u8; 32]>,
    vault_id: &[u8; 16],
    transcript: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let mut ikm = Secret::new([0u8; 64]);
    let (kem_half, ec_half) = ikm.expose_mut().split_at_mut(32);
    kem_half.copy_from_slice(ss_kem.expose());
    ec_half.copy_from_slice(ss_ec.expose());
    let mut info = Vec::with_capacity(label.len() + 2 + transcript.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&32u16.to_be_bytes());
    info.extend_from_slice(transcript);
    hkdf_sha512(ikm.expose(), vault_id, &info)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secret::Secret;

    use super::{
        p2p_gate_key, p2p_key, INFO_P2P_APP_I2R, INFO_P2P_APP_R2I, INFO_P2P_HS_I2R, INFO_P2P_HS_R2I,
    };

    #[test]
    fn grant_key_is_bound_to_every_input_and_not_a_channel_key() {
        let grant = |kem: u8, ec: u8, vault: u8, transcript: u8| {
            *super::share_grant_key(
                &Secret::new([kem; 32]),
                &Secret::new([ec; 32]),
                &[vault; 16],
                &[transcript; 32],
            )
            .unwrap()
            .expose()
        };
        let base = grant(1, 2, 3, 4);
        assert_eq!(base, grant(1, 2, 3, 4));
        for other in [
            grant(9, 2, 3, 4),
            grant(1, 9, 3, 4),
            grant(1, 2, 9, 4),
            grant(1, 2, 3, 9),
        ] {
            assert_ne!(base, other);
        }
        assert_ne!(base, key(INFO_P2P_APP_I2R, 1, 2, 3, 4));
    }

    #[test]
    fn account_secrets_follow_the_seed_and_stay_apart() {
        let gate = super::account_gate_secret(&[1; 64]).unwrap();
        assert_eq!(
            gate.expose(),
            super::account_gate_secret(&[1; 64]).unwrap().expose()
        );
        assert_ne!(
            gate.expose(),
            super::account_gate_secret(&[2; 64]).unwrap().expose()
        );
        let route = super::account_route_id(&gate).unwrap();
        assert_eq!(route, super::account_route_id(&gate).unwrap());
        assert_ne!(
            route,
            super::account_route_id(&super::account_gate_secret(&[2; 64]).unwrap()).unwrap()
        );
        assert_ne!(&route[..], &gate.expose()[..16]);
        let peers = super::personal_peers_key(gate.expose(), &route).unwrap();
        assert_ne!(peers.expose(), gate.expose());
    }

    #[test]
    fn the_beacon_key_follows_the_gate_and_is_its_own() {
        let gate = super::account_gate_secret(&[1; 64]).unwrap();
        let other = super::account_gate_secret(&[2; 64]).unwrap();
        let key = super::p2p_beacon_key(&gate).unwrap();
        assert_eq!(key.expose(), super::p2p_beacon_key(&gate).unwrap().expose());
        assert_ne!(
            key.expose(),
            super::p2p_beacon_key(&other).unwrap().expose()
        );
        assert_ne!(key.expose(), gate.expose());
        let route = super::account_route_id(&gate).unwrap();
        assert_ne!(
            key.expose(),
            super::p2p_gate_key(gate.expose(), &route).unwrap().expose(),
            "not the key of the hello gate"
        );
    }

    #[test]
    fn gate_key_depends_on_secret_and_vault_and_is_not_a_channel_key() {
        let base = *p2p_gate_key(&[1; 32], &[2; 16]).unwrap().expose();
        assert_eq!(base, *p2p_gate_key(&[1; 32], &[2; 16]).unwrap().expose());
        assert_ne!(base, *p2p_gate_key(&[9; 32], &[2; 16]).unwrap().expose());
        assert_ne!(base, *p2p_gate_key(&[1; 32], &[9; 16]).unwrap().expose());
        assert_ne!(base, key(INFO_P2P_APP_I2R, 1, 1, 2, 3));
    }

    fn key(label: &[u8], kem: u8, ec: u8, vault: u8, transcript: u8) -> [u8; 32] {
        *p2p_key(
            label,
            &Secret::new([kem; 32]),
            &Secret::new([ec; 32]),
            &[vault; 16],
            &[transcript; 32],
        )
        .unwrap()
        .expose()
    }

    #[test]
    fn every_input_changes_the_key() {
        let base = key(INFO_P2P_APP_I2R, 1, 2, 3, 4);
        assert_eq!(base, key(INFO_P2P_APP_I2R, 1, 2, 3, 4));
        assert_ne!(base, key(INFO_P2P_APP_R2I, 1, 2, 3, 4));
        assert_ne!(base, key(INFO_P2P_APP_I2R, 9, 2, 3, 4));
        assert_ne!(base, key(INFO_P2P_APP_I2R, 1, 9, 3, 4));
        assert_ne!(base, key(INFO_P2P_APP_I2R, 1, 2, 9, 4));
        assert_ne!(base, key(INFO_P2P_APP_I2R, 1, 2, 3, 9));
    }

    #[test]
    fn the_four_labels_are_distinct() {
        let keys = [
            key(INFO_P2P_HS_R2I, 1, 2, 3, 4),
            key(INFO_P2P_HS_I2R, 1, 2, 3, 4),
            key(INFO_P2P_APP_I2R, 1, 2, 3, 4),
            key(INFO_P2P_APP_R2I, 1, 2, 3, 4),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in keys.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn swapping_the_two_secrets_changes_the_key() {
        assert_ne!(
            key(INFO_P2P_APP_I2R, 1, 2, 3, 4),
            key(INFO_P2P_APP_I2R, 2, 1, 3, 4)
        );
    }
}
