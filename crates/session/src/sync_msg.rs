//! Exact byte layouts signed over one sync record.
//!
//! Version 2 binds `domain ‖ server_origin ‖ client_id ‖ device_id ‖
//! vault_id ‖ record_id ‖ revision ‖ prev_hash ‖ SHA-256(frame) ‖
//! msg_version ‖ key_generation`, every part framed as `u16 BE len ‖ bytes`.
//! Version 1 (vault, record, revision, content hash, frame) stays verifiable
//! but is never produced.

use sha2::{Digest, Sha256};

use crate::sync_sig::SyncRecord;

/// Wire format version this build signs.
pub const MSG_VERSION: u16 = 2;

/// Legacy layout without origin, account, device, or chain binding.
pub const MSG_VERSION_V1: u16 = 1;

/// Domain prefix of every version-2 record message.
const DOMAIN_SYNC_RECORD: &[u8] = b"brby/v2/sync-record";

/// Rebuild the signed bytes for `record` under its own `msg_version`.
///
/// # Errors
///
/// `unsupported sync message version` for any version but 1 and 2;
/// `content hash mismatch` when `content_hash` is not SHA-256 of the frame;
/// `sync field too long` when a part does not fit a `u16` length.
pub fn record_message(record: &SyncRecord) -> anyhow::Result<Vec<u8>> {
    let frame_hash: [u8; 32] = Sha256::digest(&record.frame).into();
    if !secret::ct_eq_32(&frame_hash, &record.content_hash) {
        anyhow::bail!("content hash mismatch");
    }
    match record.msg_version {
        MSG_VERSION => message_v2(record),
        MSG_VERSION_V1 => message_v1(record),
        _ => Err(anyhow::anyhow!("unsupported sync message version")),
    }
}

fn message_v2(record: &SyncRecord) -> anyhow::Result<Vec<u8>> {
    let parts: [&[u8]; 11] = [
        DOMAIN_SYNC_RECORD,
        &record.server_origin,
        &record.client_id,
        &record.device_id,
        &record.vault_id,
        &record.record_id.to_be_bytes(),
        &record.revision.to_be_bytes(),
        &record.prev_hash,
        &record.content_hash,
        &record.msg_version.to_be_bytes(),
        &record.key_generation.to_be_bytes(),
    ];
    frame_parts(&parts)
}

/// Concatenate `parts`, each framed as `u16 BE len ‖ bytes`.
///
/// # Errors
///
/// `sync field too long` when a part does not fit a `u16` length.
pub fn frame_parts(parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let capacity = parts.iter().map(|part| 2 + part.len()).sum();
    parts
        .iter()
        .try_fold(Vec::with_capacity(capacity), |mut msg, part| {
            let len =
                u16::try_from(part.len()).map_err(|_| anyhow::anyhow!("sync field too long"))?;
            msg.extend_from_slice(&len.to_be_bytes());
            msg.extend_from_slice(part);
            Ok(msg)
        })
}

fn message_v1(record: &SyncRecord) -> anyhow::Result<Vec<u8>> {
    let ct_len =
        u32::try_from(record.frame.len()).map_err(|_| anyhow::anyhow!("ciphertext too large"))?;
    let fields: [(u16, &[u8]); 7] = [
        (16, &record.vault_id),
        (4, &record.record_id.to_le_bytes()),
        (8, &record.revision.to_le_bytes()),
        (32, &record.content_hash),
        (4, &ct_len.to_le_bytes()),
        (2, &MSG_VERSION_V1.to_le_bytes()),
        (4, &record.key_generation.to_le_bytes()),
    ];
    let mut msg = Vec::with_capacity(record.frame.len() + 84);
    for (len, bytes) in fields {
        msg.extend_from_slice(&len.to_le_bytes());
        msg.extend_from_slice(bytes);
    }
    msg.extend_from_slice(&record.frame);
    Ok(msg)
}
