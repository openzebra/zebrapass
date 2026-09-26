//! Sync signatures: export → verify round trip, tamper rejection, and
//! revision freshness ([`session::newer`], [`session::check_fresh`]).
//!
//! Every device signs with its own ML-DSA key certified by the account
//! root, so revoking a device also revokes its write access.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use aead::BodyAlg;
use kdf::{client_id, KdfProfile};
use session::{
    check_fresh, create, export_record, issue_device_cert, newer, verify_sync_record,
    write_record, DeviceSignKey, VaultFile, DEVICE_CERT_CTX, SYNC_VK_LEN,
};

const SEED: [u8; 64] = [0x42; 64];
const ROOT_SEED: [u8; 32] = [0x07; 32];

fn round_trip() -> (VaultFile, session::Session) {
    create(&SEED, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap()
}

/// Fixed "now" in milliseconds; certificates are valid far in the future.
const NOW_MS: u64 = 1_700_000_000_000;
const NOT_AFTER_MS: u64 = NOW_MS + 10 * 365 * 24 * 3600 * 1000;

fn device_key(byte: u8) -> DeviceSignKey {
    let mut seed = [byte; 32];
    let key = DeviceSignKey::from_seed(&seed);
    seed.fill(0);
    key
}

fn certified_device(byte: u8) -> (DeviceSignKey, [u8; SYNC_VK_LEN]) {
    let device = device_key(byte);
    let vk = device.verifying_key().unwrap();
    (device, vk)
}

#[test]
fn export_verify_round_trip() {
    let (mut file, mut session) = round_trip();
    let record_id = write_record(&mut session, &mut file, None, &demo_doc()).unwrap();
    let (device, device_vk) = certified_device(0x21);
    let record = export_record(&session, &device, record_id).unwrap();

    assert_eq!(record.record_id, record_id);
    assert_eq!(record.revision, 1);
    assert_eq!(u32::try_from(session.generation()), Ok(record.key_generation));
    let vault_id = file.parse().unwrap().header.vault_id;
    verify_sync_record(&record, &device_vk, &vault_id).unwrap();
    record.verify(&device_vk, &vault_id).unwrap();
}

#[test]
fn tampered_record_is_rejected() {
    let (mut file, mut session) = round_trip();
    let record_id = write_record(&mut session, &mut file, None, &demo_doc()).unwrap();
    let (device, device_vk) = certified_device(0x22);
    let vault_id = file.parse().unwrap().header.vault_id;

    // One flipped ciphertext bit.
    let mut record = export_record(&session, &device, record_id).unwrap();
    let last = record.frame.len() - 1;
    *record.frame.get_mut(last).unwrap() ^= 0x01;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());

    // A forged revision.
    let mut record = export_record(&session, &device, record_id).unwrap();
    record.revision += 1;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());

    // A foreign vault id.
    let record = export_record(&session, &device, record_id).unwrap();
    let mut foreign = [0u8; 16];
    foreign.copy_from_slice(&vault_id);
    foreign[0] ^= 0x80;
    assert!(verify_sync_record(&record, &device_vk, &foreign).is_err());

    // A swapped record id.
    let mut record = export_record(&session, &device, record_id).unwrap();

    record.record_id = record_id + 1;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let (mut file, mut session) = round_trip();
    let record_id = write_record(&mut session, &mut file, None, &demo_doc()).unwrap();
    let (device, _) = certified_device(0x23);
    let record = export_record(&session, &device, record_id).unwrap();
    let (_, other_vk) = certified_device(0x24);
    let vault_id = file.parse().unwrap().header.vault_id;
    assert!(verify_sync_record(&record, &other_vk, &vault_id).is_err());
}

#[test]
fn expired_cert_is_rejected() {
    let device_vk = certified_device(0x25).1;
    // Expired yesterday.
    let cert = issue_device_cert(
        &ROOT_SEED,
        &client_id(&SEED).unwrap(),
        &device_vk,
        NOW_MS - 1,
        1,
    )
    .unwrap();
    let (_, root_vk) = root_key();
    assert!(cert.verify(&root_vk, NOW_MS).is_err());
    assert!(cert.verify(&root_vk, NOW_MS - 2).is_ok());
}

#[test]
fn cert_tampering_is_rejected() {
    let (_, device_vk) = certified_device(0x26);
    let cert = issue_device_cert(
        &ROOT_SEED,
        &client_id(&SEED).unwrap(),
        &device_vk,
        NOT_AFTER_MS,
        7,
    )
    .unwrap();
    let (_, root_vk) = root_key();

    // The device key was swapped after issuance.
    let (_, other_vk) = certified_device(0x27);
    let mut forged = cert;
    forged.device_vk = other_vk;
    assert!(forged.verify(&root_vk, NOW_MS).is_err());

    // A different root rejects outright.
    let alt_root = [0x08u8; 32];
    let alt_vk = issue_device_cert(&alt_root, &client_id(&SEED).unwrap(), &device_vk, NOT_AFTER_MS, 7)
        .unwrap()
        .verify(&root_vk, NOW_MS);
    assert!(alt_vk.is_err());

    // The honest pair still verifies.
    let cert = issue_device_cert(&ROOT_SEED, &client_id(&SEED).unwrap(), &device_vk, NOT_AFTER_MS, 7)
        .unwrap();
    cert.verify(&root_vk, NOW_MS).unwrap();
    let _ = device_vk;
}

#[test]
fn revision_ordering() {
    assert!(newer(1, 2));
    assert!(!newer(2, 2));
    assert!(!newer(2, 1));

    assert!(check_fresh(None, 1).is_ok());
    assert!(check_fresh(Some(1), 2).is_ok());
    assert!(check_fresh(Some(2), 2).is_err());
    assert!(check_fresh(Some(3), 2).is_err());
}

#[test]
fn record_message_rejects_oversize_ciphertext() {
    // u32::MAX + 1 cannot be a length prefix.
    let err = session::ct_len_prefix(u32::MAX as usize + 1).unwrap_err();
    assert!(err.to_string().contains("ciphertext too large"));
    assert_eq!(session::ct_len_prefix(u32::MAX as usize).unwrap(), [0xFF; 4]);
}

#[test]
fn export_of_unknown_record_fails() {
    let (file, session) = round_trip();
    let (device, _) = certified_device(0x28);
    let _ = file;
    assert!(export_record(&session, &device, 999).is_err());
}

/// A certificate must fail against a message type it was not issued for:
/// the record context and the certificate context are distinct constants.
#[test]
fn contexts_are_distinct() {
    assert_ne!(session::SYNC_CTX, DEVICE_CERT_CTX);
}

fn root_key() -> (DeviceSignKey, [u8; SYNC_VK_LEN]) {
    let root = DeviceSignKey::from_seed(&ROOT_SEED);
    let vk = root.verifying_key().unwrap();
    (root, vk)
}

fn demo_doc() -> record::Document {
    let mut doc = record::Document::new();
    doc.set_text(record::TAG_TITLE, "sync demo");
    doc
}
