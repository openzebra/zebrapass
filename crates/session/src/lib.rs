//! Vault create, unlock, and mutation session.
//!
//! This crate is the public API of the zebrapass workspace: depend only on
//! `session`. All other workspace crates are internal (`publish = false`);
//! types that appear in the API signatures (`VaultFile`, `KdfProfile`,
//! `BodyAlg`, chip wrap types) are re-exported here so no internal crate
//! is required.

mod attest;
pub(crate) mod create;
mod devices;
mod directory;
mod error;
mod peer_frame;
mod peers;
mod records;
mod revocation;
mod rewrap;
mod rotate;
mod sync_export;
mod sync_import;
mod sync_msg;
mod sync_sig;
mod unlock;
mod wraps_rot;

pub use aead::BodyAlg;
pub use attest::{
    Attestation, FrontierEntry, MAX_ATTESTED_FRAME, MAX_PEER_REVISION_JUMP, MAX_SAFE_REVISION,
    Reconcile, Trust, TrustedAccount, accept_revision, attest_latest, frontier, latest_frame,
    plain_digest, reconcile, verify_snapshot,
};
pub use container::VaultFile;
pub use create::{Session, create, fresh_device_id};
pub use devices::{
    add_chip_unlock, add_human_password, add_prf_unlock, drop_recovery_wrap, remove_chip_unlock,
    remove_human_password, remove_prf_unlock, replace_human_password,
};
pub use directory::{ChipFactor, Factor, WrapDirectory, wrap_directory};
pub use error::{Seen, SessionError};
pub use kdf::KdfProfile;
pub use peer_frame::{accept_peer_frame, accept_peer_frame_seen};
pub use peers::{MAX_HINT_LEN, MAX_HINTS, PEER_MAX_AGE_MS, PeerRecord};
pub use pq::{
    DEVICE_CERT_CTX, PEER_CTX, REVISION_CTX, REVOKE_CTX, SYNC_CTX, SYNC_SEED_LEN, SYNC_SIG_LEN,
    SYNC_VK_LEN,
};
pub use records::{
    MAX_BATCH, RecordSummary, RevisionInfo, clear_history, delete_record, fresh_record_id, history,
    list_records, open_record, open_revision, restore_revision, vault_meta, write_record,
    write_records_batch, write_vault_meta,
};
pub use revocation::{Revocation, issue_revocation};
pub use rotate::{
    Revoke, RotateCreds, change_master, reencrypt_body, revoke, rewrite_body, rotate_vault_key,
    write_records,
};
pub use sync_export::{check_fresh, export_record, newer, verify_sync_record};
pub use sync_import::{Accepted, TrustedKeys, accept_record};
pub use sync_msg::{MSG_VERSION, MSG_VERSION_V1, frame_parts, record_message};
pub use sync_sig::{
    DeviceCert, DeviceSignKey, SyncRecord, ct_len_prefix, issue_device_cert, sign_record,
    sync_verifying_key, verify_record,
};
pub use unlock::{UnlockCreds, check_seen, unlock, unlock_with_key};
pub use wraps::{ChipGrant, ChipKeys, ChipPublics, HumanPasswordPublics, PrfPublics};
