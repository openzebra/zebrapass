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
    accept_revision, attest_latest, frontier, latest_frame, plain_digest, reconcile, Attestation,
    FrontierEntry, Reconcile, TrustedAccount, MAX_ATTESTED_FRAME,
};
pub use container::VaultFile;
pub use create::{create, fresh_device_id, Session};
pub use devices::{
    add_chip_unlock, add_human_password, add_prf_unlock, drop_recovery_wrap, remove_chip_unlock,
    remove_human_password, remove_prf_unlock, replace_human_password,
};
pub use directory::{wrap_directory, ChipFactor, Factor, WrapDirectory};
pub use error::{Seen, SessionError};
pub use kdf::KdfProfile;
pub use peers::{PeerRecord, MAX_HINTS, MAX_HINT_LEN, PEER_MAX_AGE_MS};
pub use pq::{
    DEVICE_CERT_CTX, PEER_CTX, REVISION_CTX, REVOKE_CTX, SYNC_CTX, SYNC_SEED_LEN, SYNC_SIG_LEN,
    SYNC_VK_LEN,
};
pub use records::{
    clear_history, delete_record, history, list_records, open_record, open_revision,
    restore_revision, vault_meta, write_record, write_records_batch, write_vault_meta,
    RecordSummary, RevisionInfo, MAX_BATCH,
};
pub use revocation::{issue_revocation, Revocation};
pub use rotate::{
    change_master, reencrypt_body, revoke, rewrite_body, rotate_vault_key, write_records, Revoke,
    RotateCreds,
};
pub use sync_export::{check_fresh, export_record, newer, verify_sync_record};
pub use sync_import::{accept_record, Accepted, TrustedKeys};
pub use sync_msg::{frame_parts, record_message, MSG_VERSION, MSG_VERSION_V1};
pub use sync_sig::{
    ct_len_prefix, issue_device_cert, sign_record, sync_verifying_key, verify_record, DeviceCert,
    DeviceSignKey, SyncRecord,
};
pub use unlock::{check_seen, unlock, UnlockCreds};
pub use wraps::{ChipGrant, ChipKeys, ChipPublics, HumanPasswordPublics, PrfPublics};
