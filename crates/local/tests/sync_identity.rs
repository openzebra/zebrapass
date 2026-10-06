#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use kdf::sync_identity_key;
use local::SyncIdentity;
use session::{issue_device_cert, sign_record, DeviceSignKey, SyncRecord, MSG_VERSION};
use sha2::{Digest, Sha256};

const MASTER: [u8; 64] = [0x42; 64];
const CLIENT: [u8; 64] = [0x11; 64];
const OWN: [u8; 16] = [0xA1; 16];
const PEER: [u8; 16] = [0xB2; 16];

fn temp_dir() -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = String::from("zp-syncid-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn enrolled() -> SyncIdentity {
    SyncIdentity::enroll(&MASTER, &CLIENT, OWN, u64::MAX).unwrap()
}

fn peer_cert(
    master: &[u8; 64],
    client: &[u8; 64],
    id: [u8; 16],
    seed: u8,
    not_after: u64,
) -> session::DeviceCert {
    let root = kdf::sync_seed(master).unwrap();
    let vk = DeviceSignKey::from_seed(&[seed; 32])
        .verifying_key()
        .unwrap();
    issue_device_cert(root.expose(), client, &id, &vk, not_after, 5).unwrap()
}

#[test]
fn enroll_certifies_this_device_under_the_root_key() {
    let id = enrolled();
    let cert = &id.devices()[0];
    assert_eq!(cert.device_id, OWN);
    assert_eq!(id.device_id(), Some(OWN));
    cert.verify(id.root_vk(), 1_000).unwrap();
    assert_eq!(cert.device_vk, id.sign_key().verifying_key().unwrap());
    let root_seed = kdf::sync_seed(&MASTER).unwrap();
    let expected = session::sync_verifying_key(root_seed.expose()).unwrap();
    assert_eq!(id.root_vk().as_slice(), expected.as_slice());
    assert_ne!(id.sign_key().seed(), root_seed.expose());
}

#[test]
fn signing_with_the_device_key_verifies_under_its_certificate() {
    let id = enrolled();
    let frame = vec![3u8; 64];
    let base = SyncRecord {
        client_id: CLIENT,
        prev_hash: [0; 32],
        content_hash: Sha256::digest(&frame).into(),
        vault_id: [1; 16],
        device_id: OWN,
        record_id: 1,
        revision: 1,
        msg_version: MSG_VERSION,
        key_generation: 1,
        server_origin: Box::from(&b""[..]),
        frame,
        signature: Vec::new(),
    };
    let signature = sign_record(&id.sign_key(), &base).unwrap();
    let record = SyncRecord { signature, ..base };
    record.verify(&id.devices()[0].device_vk, &[1; 16]).unwrap();
}

#[test]
fn round_trip_keeps_peers_and_last_seen_and_the_same_key() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    let mut id = enrolled();
    id.add_peer(peer_cert(&MASTER, &CLIENT, PEER, 8, u64::MAX), 10)
        .unwrap();
    id.last_seen_mut().note(4, 9).unwrap();
    id.save(&path, &key).unwrap();
    let loaded = SyncIdentity::load(&path, &key).unwrap();
    assert_eq!(loaded.devices(), id.devices());
    assert_eq!(loaded.root_vk(), id.root_vk());
    assert_eq!(loaded.last_seen().get(4), Some(9));
    assert_eq!(loaded.sign_key().seed(), id.sign_key().seed());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_root_seed_is_never_written_to_disk() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    enrolled().save(&path, &key).unwrap();
    let plaintext = frame::open(&key, &fs::read(&path).unwrap()).unwrap();
    let root_seed = kdf::sync_seed(&MASTER).unwrap();
    assert!(!plaintext
        .expose()
        .windows(32)
        .any(|window| window == root_seed.expose().as_slice()));
    assert!(!plaintext
        .expose()
        .windows(64)
        .any(|window| window == MASTER.as_slice()));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wrong_key_and_tampered_bytes_do_not_open() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    enrolled().save(&path, &key).unwrap();
    let other = sync_identity_key(&[8; 32], &[7; 16]).unwrap();
    assert!(SyncIdentity::load(&path, &other).is_err());
    let meta_key = kdf::local_meta_key(&[9; 32], &[7; 16]).unwrap();
    assert!(SyncIdentity::load(&path, &meta_key).is_err());
    let mut bytes = fs::read(&path).unwrap();
    for at in [0, bytes.len() / 2, bytes.len() - 1] {
        bytes[at] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(SyncIdentity::load(&path, &key).is_err(), "byte {at}");
        bytes[at] ^= 1;
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn only_certificates_from_this_account_root_are_accepted() {
    let mut id = enrolled();
    let foreign_root = peer_cert(&[0x43; 64], &CLIENT, PEER, 8, u64::MAX);
    assert!(id.add_peer(foreign_root, 10).is_err());
    let other_account = peer_cert(&MASTER, &[0x12; 64], PEER, 8, u64::MAX);
    assert!(id.add_peer(other_account, 10).is_err());
    let expired = peer_cert(&MASTER, &CLIENT, PEER, 8, 5);
    assert!(id.add_peer(expired, 10).is_err());
    let good = peer_cert(&MASTER, &CLIENT, PEER, 8, u64::MAX);
    id.add_peer(good.clone(), 10).unwrap();
    id.add_peer(good, 10).unwrap();
    assert_eq!(id.devices().len(), 2);
}

#[test]
fn a_known_device_id_cannot_be_rebound_to_another_key() {
    let mut id = enrolled();
    id.add_peer(peer_cert(&MASTER, &CLIENT, PEER, 8, u64::MAX), 10)
        .unwrap();
    assert!(id
        .add_peer(peer_cert(&MASTER, &CLIENT, PEER, 9, u64::MAX), 10)
        .is_err());
    assert!(id
        .add_peer(peer_cert(&MASTER, &CLIENT, OWN, 9, u64::MAX), 10)
        .is_err());
}

#[test]
fn a_full_device_list_refuses_more_and_still_reloads() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    let mut id = enrolled();
    for n in 0..local::PEERS_MAX {
        let mut peer = [0xC0; 16];
        peer[0] = u8::try_from(n).unwrap();
        id.add_peer(peer_cert(&MASTER, &CLIENT, peer, 20, u64::MAX), 10)
            .unwrap();
    }
    assert!(id
        .add_peer(peer_cert(&MASTER, &CLIENT, [0xD0; 16], 21, u64::MAX), 10)
        .is_err());
    id.save(&path, &key).unwrap();
    let loaded = SyncIdentity::load(&path, &key).unwrap();
    assert_eq!(loaded.devices().len(), local::PEERS_MAX + 1);
    fs::remove_dir_all(&dir).unwrap();
}

fn certs_for(master: &[u8; 64], id: u8) -> session::DeviceCert {
    peer_cert(master, &CLIENT, [id; 16], id, u64::MAX)
}

#[test]
fn a_revoked_device_is_remembered_across_reload_and_cannot_rejoin() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    let mut id = enrolled();
    let lost = certs_for(&MASTER, 0x31);
    id.add_peer(lost.clone(), 10).unwrap();
    let revocation = id.revoke_device(&lost, 20).unwrap();
    assert!(id.revocations().is_revoked(&lost));
    assert!(id.add_peer(lost.clone(), 30).is_err());
    id.save(&path, &key).unwrap();
    let loaded = SyncIdentity::load(&path, &key).unwrap();
    assert!(loaded.revocations().is_revoked(&lost));
    assert_eq!(loaded.revocations().all()[0], revocation);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_foreign_or_forged_revocation_is_refused() {
    let mut id = enrolled();
    let victim = certs_for(&MASTER, 0x32);
    id.add_peer(victim.clone(), 10).unwrap();

    let foreign_master = [0x43; 64];
    let outsider_key = DeviceSignKey::from_seed(&[0x61; 32]);
    let outsider = issue_device_cert(
        kdf::sync_seed(&foreign_master).unwrap().expose(),
        &CLIENT,
        &[0x61; 16],
        &outsider_key.verifying_key().unwrap(),
        u64::MAX,
        1,
    )
    .unwrap();
    let forged = session::issue_revocation(&outsider_key, &outsider, &victim, 20).unwrap();
    assert!(id.add_revocation(forged, 20).is_err());
    assert!(!id.revocations().is_revoked(&victim));
}

#[test]
fn a_revoked_device_cannot_revoke_anyone_else() {
    let mut id = enrolled();
    let mallory_key = DeviceSignKey::from_seed(&[0x62; 32]);
    let mallory = issue_device_cert(
        kdf::sync_seed(&MASTER).unwrap().expose(),
        &CLIENT,
        &[0x62; 16],
        &mallory_key.verifying_key().unwrap(),
        u64::MAX,
        2,
    )
    .unwrap();
    id.add_peer(mallory.clone(), 10).unwrap();
    id.revoke_device(&mallory, 20).unwrap();
    let own = id.devices()[0].clone();
    let late = session::issue_revocation(&mallory_key, &mallory, &own, 30).unwrap();
    assert!(id.add_revocation(late, 30).is_err());
    assert!(!id.revocations().is_revoked(&own));
}

#[test]
fn the_worst_case_identity_still_fits_one_sealed_document() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    let mut id = enrolled();
    for n in 0..local::PEERS_MAX {
        let tag = u8::try_from(n).unwrap();
        id.add_peer(certs_for(&MASTER, 0x80 + tag), 10).unwrap();
    }
    let revoker_cert = id.devices()[0].clone();
    for n in 0..local::REVOKED_MAX {
        let tag = u8::try_from(n).unwrap();
        let target = certs_for(&MASTER, 0x40 + tag);
        let revocation =
            session::issue_revocation(&id.sign_key(), &revoker_cert, &target, 20).unwrap();
        id.add_revocation(revocation, 20).unwrap();
    }
    for record in 0..u32::try_from(local::LAST_SEEN_MAX).unwrap() {
        id.last_seen_mut().note(record, 1).unwrap();
    }
    let extra = certs_for(&MASTER, 0x3F);
    let overflow = session::issue_revocation(&id.sign_key(), &revoker_cert, &extra, 20).unwrap();
    assert!(id.add_revocation(overflow, 20).is_err());
    id.save(&path, &key).unwrap();
    let loaded = SyncIdentity::load(&path, &key).unwrap();
    assert_eq!(loaded.revocations().all().len(), local::REVOKED_MAX);
    assert_eq!(loaded.devices().len(), local::PEERS_MAX + 1);
    assert_eq!(loaded.last_seen().len(), local::LAST_SEEN_MAX);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_invitation_keys_survive_a_reload_and_differ_per_device() {
    let dir = temp_dir();
    let path = dir.join("sync.id");
    let key = sync_identity_key(&[9; 32], &[7; 16]).unwrap();
    let id = enrolled();
    let publics = id.share_publics().unwrap();
    assert_eq!(publics.ec_pub[0], 0x04);
    assert_eq!(publics.kem_ek.len(), pq::PQ_PK_LEN);
    id.save(&path, &key).unwrap();
    let loaded = SyncIdentity::load(&path, &key).unwrap();
    assert_eq!(loaded.share_publics().unwrap(), publics);
    assert_eq!(
        loaded.share_keys().kem_seed().expose(),
        id.share_keys().kem_seed().expose()
    );
    let other = SyncIdentity::enroll(&MASTER, &CLIENT, [0xA2; 16], u64::MAX).unwrap();
    assert_ne!(other.share_publics().unwrap(), publics);
    let secret = id.share_keys().ec_secret().unwrap();
    assert_eq!(
        ec::encode_pub(&secret.public_key()).unwrap(),
        publics.ec_pub
    );
    fs::remove_dir_all(&dir).unwrap();
}
