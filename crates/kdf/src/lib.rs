//! Argon2id profiles and HKDF domain separation.

mod argon2;
mod derive;
mod hkdf;
mod p2p;
mod profile;
mod sync_https;

pub use argon2::argon2id;
pub use derive::{
    INFO_CASCADE_AEGIS, INFO_CASCADE_KUZ, INFO_CASCADE_MAC, INFO_CLIENT_ID, INFO_DEVICE_KEY_FILE,
    INFO_FRAME_KEY, INFO_IDENTITY, INFO_LOCAL_META, INFO_SHARED_ATTEST, INFO_SHARED_GATE,
    INFO_SHARED_MEMBERS, INFO_SHARED_PEERS, INFO_SHARED_STATE, INFO_SYNC_IDENTITY, INFO_SYNC_SIGN,
    cascade_keys, client_id, client_id_for, device_key_file_key, frame_key, identity_seed,
    local_meta_key, shared_attest_key, shared_gate_key, shared_members_key, shared_peers_key,
    shared_state_key, sync_identity_key, sync_seed,
};
pub use hkdf::{INFO_CHIP_WRAP, INFO_PRF_WRAP, derive_vault_keys, hkdf_sha512};
pub use p2p::{
    INFO_P2P_ACCOUNT_GATE, INFO_P2P_ACCOUNT_ROUTE, INFO_P2P_APP_I2R, INFO_P2P_APP_R2I,
    INFO_P2P_BEACON, INFO_P2P_GATE, INFO_P2P_HS_I2R, INFO_P2P_HS_R2I, INFO_P2P_RELAY_SLOT,
    INFO_PERSONAL_PEERS, INFO_SHARE_GRANT, INFO_SHARED_BEACON, account_gate_secret,
    account_route_id, p2p_beacon_key, p2p_gate_key, p2p_key, p2p_relay_slot, personal_peers_key,
    share_grant_key, shared_beacon_key,
};
pub use profile::KdfProfile;
pub use sync_https::{
    INFO_BACKUP_COMMIT, INFO_BACKUP_SEAL, INFO_CLOUD_BACKUP, INFO_PERSONAL_REKEY,
    INFO_SYNC_ENVELOPE, INFO_SYNC_MAILBOX, backup_keys, cloud_backup_key, personal_envelope_key,
    personal_mailbox_id, personal_rekey_key, shared_envelope_key, shared_mailbox_id,
};
