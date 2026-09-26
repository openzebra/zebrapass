//! Vault create, unlock, and mutation session.
//!
//! This crate is the public API of the zebrapass workspace: depend only on
//! `session`. All other workspace crates are internal (`publish = false`);
//! types that appear in the API signatures (`VaultFile`, `KdfProfile`,
//! `BodyAlg`, device wrap types) are re-exported here so no internal crate
//! is required.

mod create;
mod devices;
mod error;
mod records;
mod rewrap;
mod rotate;
mod sync_export;
mod sync_sig;
mod unlock;

pub use aead::BodyAlg;
pub use container::VaultFile;
pub use create::{create, Session};
pub use devices::{
    add_chip_unlock, add_device, add_prf_unlock, remove_chip_unlock, remove_device,
    remove_prf_unlock,
};
pub use error::Seen;
pub use kdf::KdfProfile;
pub use records::{
    clear_history, delete_record, history, list_records, open_record, open_revision,
    restore_revision, vault_meta, write_record, write_vault_meta, RecordSummary, RevisionInfo,
};
pub use rotate::{change_master, reencrypt_body, revoke, write_records, Revoke, RotateCreds};
pub use sync_export::{export_record, newer, verify_sync_record, SyncRecord};
pub use sync_sig::{record_message, sign_record, sync_verifying_key, verify_record};
pub use unlock::{unlock, UnlockCreds};
pub use wraps::{ChipGrant, ChipKeys, ChipPublics, DeviceGrant, DeviceKeys, DevicePublics};
