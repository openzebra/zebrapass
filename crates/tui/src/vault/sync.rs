//! File-based sync through `session::export_record` / `accept_record`.
//!
//! The server transport is not built yet (`TODO(sync-server)`); until then a
//! bundle file carries signed frames between devices. Device signing keys
//! have no keychain home yet either, so each export draws a one-off ML-DSA
//! key and certifies it with the account root key derived from the recovery
//! phrase. Import re-derives the root verifying key from the phrase and lets
//! `accept_record` run every check.

use std::path::{Path, PathBuf};

use seed::SeedPhrase;
use session::{
    accept_record, export_record, issue_device_cert, verify_sync_record, DeviceSignKey,
    TrustedKeys, SYNC_SEED_LEN,
};
use zeroize::Zeroizing;

use crate::vault::create::unix_ms;
use crate::vault::error::describe;
use crate::vault::limits::MAX_SYNC_FILE;
use crate::vault::open::Vault;
use crate::vault::sync_file::{decode, encode, SyncBundle};

/// Export certificates live this long.
const CERT_LIFETIME_MS: u64 = 30 * 24 * 3600 * 1000;

/// Outer fields of the last exported record, after a self-verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedPreview {
    /// Record id.
    pub record_id: u32,
    /// Revision.
    pub revision: u64,
    /// SHA-256 of the sealed frame.
    pub content_hash: [u8; 32],
    /// Vault-key generation bound into the signature.
    pub key_generation: u32,
    /// Message layout version.
    pub msg_version: u16,
    /// Device id stamped in the frame.
    pub origin: [u8; 16],
    /// The signature verified under the exporting key.
    pub verified: bool,
}

/// Result of an export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReport {
    /// Where the bundle was written.
    pub path: PathBuf,
    /// Records written.
    pub count: usize,
    /// The last record's signed fields.
    pub preview: Option<SignedPreview>,
}

/// Per-record import result: the stored revision, or why it was rejected.
pub type ImportOutcome = (u32, Result<u64, String>);

/// Result of an import.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// One entry per record in the bundle.
    pub outcomes: Vec<ImportOutcome>,
}

/// Sign `ids` and write them to `path`.
///
/// # Errors
///
/// `phrase does not match this vault`; signing, frame, and storage errors.
pub fn export(
    vault: &Vault,
    phrase: &SeedPhrase,
    ids: &[u32],
    path: &Path,
) -> anyhow::Result<ExportReport> {
    vault.check_phrase(phrase)?;
    let root = kdf::sync_seed(phrase.seed())?;
    let mut device_seed = Zeroizing::new([0u8; SYNC_SEED_LEN]);
    getrandom::fill(device_seed.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let device = DeviceSignKey::from_seed(&device_seed);
    let device_vk = device.verifying_key()?;
    let mut serial = [0u8; 8];
    getrandom::fill(&mut serial).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    let cert = issue_device_cert(
        root.expose(),
        &vault.meta.client_id,
        &device_vk,
        unix_ms().saturating_add(CERT_LIFETIME_MS),
        u64::from_be_bytes(serial),
    )?;
    drop(root);
    let mut records = Vec::with_capacity(ids.len());
    let mut preview = None;
    for id in ids {
        let record = export_record(&vault.session, &device, *id)?;
        let origin = frame::parse(&record.frame)?.origin_device;
        preview = Some(SignedPreview {
            record_id: record.record_id,
            revision: record.revision,
            content_hash: record.content_hash,
            key_generation: record.key_generation,
            msg_version: record.msg_version,
            origin,
            verified: verify_sync_record(&record, &device_vk, vault.session.vault_id()).is_ok(),
        });
        records.push((origin, record));
    }
    let bytes = encode(&SyncBundle { cert, records })?;
    local::write_atomic(path, &bytes)?;
    Ok(ExportReport {
        path: path.to_path_buf(),
        count: ids.len(),
        preview,
    })
}

/// Verify and apply every record in the bundle at `path`. Rejected records
/// are reported with their reason and do not stop the others.
///
/// # Errors
///
/// `phrase does not match this vault`; file and bundle-format errors;
/// storage errors when persisting accepted records.
pub fn import(vault: &mut Vault, phrase: &SeedPhrase, path: &Path) -> anyhow::Result<ImportReport> {
    vault.check_phrase(phrase)?;
    let root = kdf::sync_seed(phrase.seed())?;
    let root_vk = DeviceSignKey::from_seed(root.expose()).verifying_key()?;
    drop(root);
    let len = std::fs::metadata(path)
        .map_err(|_| anyhow::anyhow!("cannot read {}", path.display()))?
        .len();
    if len > MAX_SYNC_FILE {
        anyhow::bail!("sync bundle too large");
    }
    let bytes =
        std::fs::read(path).map_err(|_| anyhow::anyhow!("cannot read {}", path.display()))?;
    let bundle = decode(&bytes)?;
    let mut origins: Vec<[u8; 16]> = bundle.records.iter().map(|(origin, _)| *origin).collect();
    origins.sort_unstable();
    origins.dedup();
    let devices: Vec<([u8; 16], session::DeviceCert)> = origins
        .into_iter()
        .map(|origin| (origin, bundle.cert.clone()))
        .collect();
    let trust = TrustedKeys {
        client_id: vault.meta.client_id,
        root_vk,
        devices: &devices,
        now_ms: unix_ms(),
    };
    let mut report = ImportReport::default();
    for (_, record) in &bundle.records {
        let outcome = accept_record(&mut vault.session, &mut vault.file, record, &trust, |_| {
            None
        })
        .map(|accepted| accepted.revision)
        .map_err(|error| describe(&error));
        report.outcomes.push((record.record_id, outcome));
    }
    if report.outcomes.iter().any(|(_, outcome)| outcome.is_ok()) {
        vault.persist()?;
    }
    Ok(report)
}
