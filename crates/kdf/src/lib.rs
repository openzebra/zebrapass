//! Argon2id profiles and HKDF domain separation.

mod argon2;
mod derive;
mod hkdf;
mod p2p;
mod profile;

pub use argon2::argon2id;
pub use derive::{
    cascade_keys, client_id, client_id_for, device_key_file_key, frame_key, identity_seed,
    local_meta_key, shared_attest_key, shared_gate_key, shared_members_key, shared_peers_key,
    shared_state_key, sync_identity_key, sync_seed, INFO_CASCADE_AEGIS, INFO_CASCADE_KUZ,
    INFO_CASCADE_MAC, INFO_CLIENT_ID, INFO_DEVICE_KEY_FILE, INFO_FRAME_KEY, INFO_IDENTITY,
    INFO_LOCAL_META, INFO_SHARED_ATTEST, INFO_SHARED_GATE, INFO_SHARED_MEMBERS, INFO_SHARED_PEERS,
    INFO_SHARED_STATE, INFO_SYNC_IDENTITY, INFO_SYNC_SIGN,
};
pub use hkdf::{derive_vault_keys, hkdf_sha512, INFO_CHIP_WRAP, INFO_PRF_WRAP};
pub use p2p::{
    p2p_gate_key, p2p_key, share_grant_key, INFO_P2P_APP_I2R, INFO_P2P_APP_R2I, INFO_P2P_GATE,
    INFO_P2P_HS_I2R, INFO_P2P_HS_R2I, INFO_SHARE_GRANT,
};
pub use profile::KdfProfile;
