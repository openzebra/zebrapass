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
    add_device, check_fresh, create, export_record, issue_device_cert, newer, sign_record, unlock,
    verify_sync_record, write_record, DeviceCert, DeviceSignKey, SyncRecord, UnlockCreds,
    VaultFile, DEVICE_CERT_CTX, SYNC_VK_LEN,
};

const SEED: [u8; 64] = [0x42; 64];
const ORIGIN: &[u8] = b"https://sync.example";

fn export(
    session: &session::Session,
    device: &DeviceSignKey,
    id: u32,
) -> anyhow::Result<SyncRecord> {
    export_record(session, device, id, &client_id(&SEED).unwrap(), ORIGIN)
}
const ROOT_SEED: [u8; 32] = [0x07; 32];

fn round_trip() -> (VaultFile, session::Session) {
    // Unlocked through a device wrap so every written frame carries a
    // certified-device origin; `export_record` refuses the zero origin
    // that seed/password unlocks stamp.
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (ntru_bytes, kem_secret) = pq::keypair().unwrap();
    let ntru_pk: [u8; pq::PQ_PK_LEN] = ntru_bytes.as_slice().try_into().unwrap();
    let mut scalar = [0u8; 32];
    getrandom::fill(&mut scalar).unwrap();
    let x_pk = x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES);
    let id = [0xA1u8; 16];
    add_device(
        &mut session,
        &mut file,
        &wraps::DevicePublics {
            id,
            x_pk,
            pq_pk: ntru_pk,
        },
    )
    .unwrap();
    let keys = wraps::DeviceKeys {
        id,
        x_sk: secret::Secret::new(scalar),
        pq_sk: kem_secret,
    };
    let session = unlock(&file, &UnlockCreds::master(&SEED).with_device(&keys), None).unwrap();
    (file, session)
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
    let record = export(&session, &device, record_id).unwrap();

    assert_eq!(record.record_id, record_id);
    assert_eq!(record.revision, 1);
    assert_eq!(
        u32::try_from(session.generation()),
        Ok(record.key_generation)
    );
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
    let mut record = export(&session, &device, record_id).unwrap();
    let last = record.frame.len() - 1;
    *record.frame.get_mut(last).unwrap() ^= 0x01;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());

    // A forged revision.
    let mut record = export(&session, &device, record_id).unwrap();
    record.revision += 1;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());

    // A foreign vault id.
    let record = export(&session, &device, record_id).unwrap();
    let mut foreign = [0u8; 16];
    foreign.copy_from_slice(&vault_id);
    foreign[0] ^= 0x80;
    assert!(verify_sync_record(&record, &device_vk, &foreign).is_err());

    // A swapped record id.
    let mut record = export(&session, &device, record_id).unwrap();

    record.record_id = record_id + 1;
    assert!(verify_sync_record(&record, &device_vk, &vault_id).is_err());
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let (mut file, mut session) = round_trip();
    let record_id = write_record(&mut session, &mut file, None, &demo_doc()).unwrap();
    let (device, _) = certified_device(0x23);
    let record = export(&session, &device, record_id).unwrap();
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
    let alt_vk = issue_device_cert(
        &alt_root,
        &client_id(&SEED).unwrap(),
        &device_vk,
        NOT_AFTER_MS,
        7,
    )
    .unwrap()
    .verify(&root_vk, NOW_MS);
    assert!(alt_vk.is_err());

    // The honest pair still verifies.
    let cert = issue_device_cert(
        &ROOT_SEED,
        &client_id(&SEED).unwrap(),
        &device_vk,
        NOT_AFTER_MS,
        7,
    )
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
    assert_eq!(
        session::ct_len_prefix(u32::MAX as usize).unwrap(),
        [0xFF; 4]
    );
}

#[test]
fn export_of_unknown_record_fails() {
    let (file, session) = round_trip();
    let (device, _) = certified_device(0x28);
    let _ = file;
    assert!(export(&session, &device, 999).is_err());
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

// ---- Phase 5: the receive/apply side -------------------------------------

use session::{accept_record, open_record, Accepted, TrustedKeys};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "wall clock fits u64 until year 586M"
    )]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

fn trust<'a>(
    client: &'a [u8; 64],
    root_vk: &'a [u8; SYNC_VK_LEN],
    devices: &'a [([u8; 16], DeviceCert)],
) -> TrustedKeys<'a> {
    TrustedKeys {
        client_id: *client,
        server_origin: ORIGIN,
        root_vk: *root_vk,
        devices,
        now_ms: now_ms(),
    }
}

fn enroll(
    root_seed: &[u8; 32],
    client: &[u8; 64],
    device: &DeviceSignKey,
    origin: [u8; 16],
    serial: u64,
) -> ([u8; 16], DeviceCert) {
    let vk = device.verifying_key().unwrap();
    let cert = issue_device_cert(root_seed, client, &vk, u64::MAX / 2, serial).unwrap();
    (origin, cert)
}

/// The origin id the sender's frames actually carry: tests enroll the
/// device under the id its frame headers use.
fn origin_of(record: &SyncRecord) -> [u8; 16] {
    let header = frame::parse(&record.frame).unwrap();
    header.origin_device
}

#[test]
fn valid_record_is_applied() {
    let client = client_id(&SEED).unwrap();
    let (device, _) = certified_device(0x31);
    let (root, root_vk) = root_key();
    // Sender writes and exports.
    let (mut sfile, mut sender) = round_trip();
    // Receiver snapshot before the write: same vault, no record yet.
    let rfile = VaultFile::new(sfile.as_bytes().to_vec());
    let record_id = write_record(&mut sender, &mut sfile, None, &demo_doc()).unwrap();
    let sync_rec = export(&sender, &device, record_id).unwrap();
    let enrolled = [enroll(
        &root.seed(),
        &client,
        &device,
        origin_of(&sync_rec),
        1,
    )];

    let mut receiver = unlock(&rfile, &UnlockCreds::master(&SEED), None).unwrap();
    let mut rfile = rfile;

    let accepted = accept_record(
        &mut receiver,
        &mut rfile,
        &sync_rec,
        &trust(&client, &root_vk, &enrolled),
        |_| None,
    )
    .unwrap();
    assert_eq!(accepted.record_id, record_id);
    assert_eq!(accepted.revision, 1);

    // Applied through the same path as local writes: the record reads back.
    let doc = open_record(&receiver, record_id).unwrap();
    assert_eq!(doc.text(record::TAG_TITLE).unwrap().unwrap(), "sync demo");
}

#[test]
fn replayed_revision_is_rejected() {
    let client = client_id(&SEED).unwrap();
    let (device, _) = certified_device(0x32);
    let (root, root_vk) = root_key();
    let (mut sfile, mut sender) = round_trip();
    let rfile = VaultFile::new(sfile.as_bytes().to_vec());
    let record_id = write_record(&mut sender, &mut sfile, None, &demo_doc()).unwrap();
    let sync_rec = export(&sender, &device, record_id).unwrap();
    let enrolled = [enroll(
        &root.seed(),
        &client,
        &device,
        origin_of(&sync_rec),
        1,
    )];

    let mut receiver = unlock(&rfile, &UnlockCreds::master(&SEED), None).unwrap();
    let mut rfile = rfile;
    let keys = trust(&client, &root_vk, &enrolled);
    accept_record(&mut receiver, &mut rfile, &sync_rec, &keys, |_| None).unwrap();

    // The exact same frame a second time: not strictly newer.
    let err = accept_record(&mut receiver, &mut rfile, &sync_rec, &keys, |_| None).unwrap_err();
    assert_eq!(err.to_string(), "stale revision");

    // A local write raced ahead: the stale remote copy still loses.
    let _ = write_record(&mut receiver, &mut rfile, Some(record_id), &demo_doc()).unwrap();
    assert_eq!(
        accept_record(&mut receiver, &mut rfile, &sync_rec, &keys, |_| None)
            .unwrap_err()
            .to_string(),
        "stale revision"
    );
}

#[test]
fn revoked_and_foreign_devices_are_rejected() {
    let client = client_id(&SEED).unwrap();
    let (device, _) = certified_device(0x33);
    let (root, root_vk) = root_key();

    let (mut sfile, mut sender) = round_trip();
    let rfile = VaultFile::new(sfile.as_bytes().to_vec());
    let record_id = write_record(&mut sender, &mut sfile, None, &demo_doc()).unwrap();
    let sync_rec = export(&sender, &device, record_id).unwrap();

    let mut receiver = unlock(&rfile, &UnlockCreds::master(&SEED), None).unwrap();
    let mut rfile = rfile;

    // Revoked: the device is no longer in the cert table.
    let empty: [([u8; 16], DeviceCert); 0] = [];
    assert_eq!(
        accept_record(
            &mut receiver,
            &mut rfile,
            &sync_rec,
            &trust(&client, &root_vk, &empty),
            |_| None
        )
        .unwrap_err()
        .to_string(),
        "device not enrolled"
    );

    // Enrolled under a different account: rejected.
    let other_client = [9u8; 64];
    let wrong_account = [enroll(
        &root.seed(),
        &other_client,
        &device,
        origin_of(&sync_rec),
        1,
    )];
    assert_eq!(
        accept_record(
            &mut receiver,
            &mut rfile,
            &sync_rec,
            &trust(&client, &root_vk, &wrong_account),
            |_| None,
        )
        .unwrap_err()
        .to_string(),
        "device cert rejected"
    );

    // A certificate that expired between issue and check.
    let expired = {
        let vk = device.verifying_key().unwrap();
        let cert = issue_device_cert(&root.seed(), &client, &vk, 0, 1).unwrap();
        (origin_of(&sync_rec), cert)
    };
    let expired_list = [expired];
    let mut keys = trust(&client, &root_vk, &expired_list);
    keys.now_ms = now_ms();
    assert_eq!(
        accept_record(&mut receiver, &mut rfile, &sync_rec, &keys, |_| None)
            .unwrap_err()
            .to_string(),
        "device cert expired"
    );

    // Honest enrollment still passes the trust gate and applies.
    let good = [enroll(
        &root.seed(),
        &client,
        &device,
        origin_of(&sync_rec),
        1,
    )];
    assert!(accept_record(
        &mut receiver,
        &mut rfile,
        &sync_rec,
        &trust(&client, &root_vk, &good),
        |_| None
    )
    .is_ok());
}

#[test]
fn forged_outer_fields_are_rejected() {
    // A malicious server can sign (or forward a valid signature over) outer
    // fields that do not describe the carried frame. The header check must
    // catch what the signature alone cannot.
    let client = client_id(&SEED).unwrap();
    let (device, _) = certified_device(0x34);
    let (root, root_vk) = root_key();
    let (mut sfile, mut sender) = round_trip();
    let record_id = write_record(&mut sender, &mut sfile, None, &demo_doc()).unwrap();
    let honest = export(&sender, &device, record_id).unwrap();
    let enrolled = [enroll(
        &root.seed(),
        &client,
        &device,
        origin_of(&honest),
        1,
    )];

    // The frame is record 1's; the outer claim says record 2, revision 9.
    let forged = SyncRecord {
        record_id: 2,
        revision: 9,
        signature: Vec::new(),
        ..honest.clone()
    };
    // Signed by the honest device, so the signature check alone passes.
    let sig = sign_record(&device, &forged).unwrap();
    let forged = SyncRecord {
        signature: sig,
        ..forged
    };

    let rfile = VaultFile::new(sfile.as_bytes().to_vec());
    let mut receiver = unlock(&rfile, &UnlockCreds::master(&SEED), None).unwrap();
    let mut rfile = rfile;
    assert_eq!(
        accept_record(
            &mut receiver,
            &mut rfile,
            &forged,
            &trust(&client, &root_vk, &enrolled),
            |_| None,
        )
        .unwrap_err()
        .to_string(),
        "header mismatch"
    );

    // A foreign vault id is refused even with a valid signature.
    let mut foreign = honest;
    foreign.vault_id = [0xEE; 16];
    let sig = sign_record(&device, &foreign).unwrap();
    let foreign = SyncRecord {
        signature: sig,
        ..foreign
    };
    assert_eq!(
        accept_record(
            &mut receiver,
            &mut rfile,
            &foreign,
            &trust(&client, &root_vk, &enrolled),
            |_| None,
        )
        .unwrap_err()
        .to_string(),
        "vault id mismatch"
    );

    // `key_generation` is signed bookkeeping; the frame AEAD carries the
    // real epoch check, so no outer-field assertion covers it here.
}

#[test]
fn accepted_type_round_trips() {
    let a = Accepted {
        record_id: 1,
        revision: 2,
        origin_device: [3; 16],
    };
    let b = a;
    assert_eq!(a, b);
    let _ = format!("{a:?}");
}

fn accept_err(sync_rec: &SyncRecord, keys: &TrustedKeys<'_>, rfile: &VaultFile) -> String {
    let mut receiver = unlock(rfile, &UnlockCreds::master(&SEED), None).unwrap();
    let mut rfile = VaultFile::new(rfile.as_bytes().to_vec());
    accept_record(&mut receiver, &mut rfile, sync_rec, keys, |_| None)
        .unwrap_err()
        .to_string()
}

#[test]
fn addressing_and_downgrade_are_rejected() {
    let client = client_id(&SEED).unwrap();
    let (device, _) = certified_device(0x35);
    let (root, root_vk) = root_key();
    let (mut sfile, mut sender) = round_trip();
    let rfile = VaultFile::new(sfile.as_bytes().to_vec());
    let record_id = write_record(&mut sender, &mut sfile, None, &demo_doc()).unwrap();
    let honest = export(&sender, &device, record_id).unwrap();
    let enrolled = [enroll(
        &root.seed(),
        &client,
        &device,
        origin_of(&honest),
        1,
    )];
    let keys = trust(&client, &root_vk, &enrolled);
    let resign = |rec: SyncRecord| SyncRecord {
        signature: sign_record(&device, &rec).unwrap(),
        ..rec
    };

    let other_server = resign(SyncRecord {
        server_origin: Box::from(&b"https://other.example"[..]),
        ..honest.clone()
    });
    assert_eq!(
        accept_err(&other_server, &keys, &rfile),
        "device cert rejected"
    );

    let other_account = resign(SyncRecord {
        client_id: [9u8; 64],
        ..honest.clone()
    });
    assert_eq!(
        accept_err(&other_account, &keys, &rfile),
        "device cert rejected"
    );

    let other_device = resign(SyncRecord {
        device_id: [0x77; 16],
        ..honest.clone()
    });
    assert_eq!(accept_err(&other_device, &keys, &rfile), "header mismatch");

    let mut legacy = SyncRecord {
        msg_version: session::MSG_VERSION_V1,
        ..honest
    };
    let msg = session::record_message(&legacy).unwrap();
    legacy.signature = pq::sync_sign(&device.seed(), session::SYNC_CTX, &msg).unwrap();
    verify_sync_record(&legacy, &device.verifying_key().unwrap(), &legacy.vault_id).unwrap();
    assert_eq!(
        accept_err(&legacy, &keys, &rfile),
        "unsupported sync message version"
    );
}

#[test]
fn prev_hash_chains_to_the_superseded_frame() {
    use sha2::{Digest, Sha256};
    let (mut file, mut session) = round_trip();
    let (device, _) = certified_device(0x36);
    let record_id = write_record(&mut session, &mut file, None, &demo_doc()).unwrap();
    let first = export(&session, &device, record_id).unwrap();
    assert_eq!(first.prev_hash, [0u8; 32]);
    write_record(&mut session, &mut file, Some(record_id), &demo_doc()).unwrap();
    let second = export(&session, &device, record_id).unwrap();
    assert_eq!(
        second.prev_hash,
        <[u8; 32]>::from(Sha256::digest(&first.frame))
    );
    assert_eq!(second.device_id, origin_of(&second));
    assert_eq!(second.msg_version, session::MSG_VERSION);
}
