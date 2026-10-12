#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use session::{
    issue_device_cert, sync_verifying_key, DeviceCert, DeviceSignKey, PeerRecord, MAX_HINTS,
    SYNC_VK_LEN,
};

const NOW: u64 = 1_700_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

struct Person {
    key: DeviceSignKey,
    cert: DeviceCert,
    root_vk: [u8; SYNC_VK_LEN],
}

fn person(n: u8) -> Person {
    let root_seed = [n; 32];
    let key = DeviceSignKey::from_seed(&[n ^ 0x80; 32]);
    let cert = issue_device_cert(
        &root_seed,
        &[n; 64],
        &[n ^ 0x40; 16],
        &key.verifying_key().unwrap(),
        u64::MAX,
        u64::from(n),
    )
    .unwrap();
    Person {
        key,
        cert,
        root_vk: sync_verifying_key(&root_seed).unwrap().try_into().unwrap(),
    }
}

fn record(who: &Person, hints: &[&str], at: u64) -> PeerRecord {
    PeerRecord::sign(
        &who.key,
        &who.cert,
        [9; 16],
        hints.iter().map(|hint| (*hint).to_owned()).collect(),
        at,
    )
    .unwrap()
}

#[test]
fn a_fresh_record_from_its_account_verifies() {
    let bob = person(2);
    record(&bob, &["10.0.0.2:7447"], NOW)
        .verify(&bob.root_vk, NOW + 1000)
        .unwrap();
}

#[test]
fn another_accounts_root_does_not_vouch_for_it() {
    let (bob, carol) = (person(2), person(3));
    assert!(record(&bob, &["10.0.0.2:7447"], NOW)
        .verify(&carol.root_vk, NOW)
        .is_err());
}

#[test]
fn a_changed_address_breaks_the_signature() {
    let bob = person(2);
    let mut forged = record(&bob, &["10.0.0.2:7447"], NOW);
    forged.hints[0] = "10.6.6.6:7447".to_owned();
    assert!(forged.verify(&bob.root_vk, NOW).is_err());
}

#[test]
fn a_record_moved_to_another_vault_or_time_is_rejected() {
    let bob = person(2);
    let mut moved = record(&bob, &["10.0.0.2:7447"], NOW);
    moved.vault_id = [8; 16];
    assert!(moved.verify(&bob.root_vk, NOW).is_err());
    let mut later = record(&bob, &["10.0.0.2:7447"], NOW);
    later.issued_ms += 1;
    assert!(later.verify(&bob.root_vk, NOW + 5).is_err());
}

#[test]
fn old_and_future_records_are_not_believed() {
    let bob = person(2);
    let old = record(&bob, &["10.0.0.2:7447"], NOW);
    assert!(old.verify(&bob.root_vk, NOW + 4 * DAY).is_err());
    let future = record(&bob, &["10.0.0.2:7447"], NOW + DAY);
    assert!(future.verify(&bob.root_vk, NOW).is_err());
}

#[test]
fn too_many_or_empty_addresses_are_not_signed() {
    let bob = person(2);
    let many = vec!["10.0.0.2:1"; MAX_HINTS + 1];
    assert!(PeerRecord::sign(
        &bob.key,
        &bob.cert,
        [9; 16],
        many.into_iter().map(str::to_owned).collect(),
        NOW
    )
    .is_err());
    assert!(PeerRecord::sign(&bob.key, &bob.cert, [9; 16], vec![String::new()], NOW).is_err());
}
