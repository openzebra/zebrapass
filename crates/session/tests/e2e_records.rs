//! End-to-end flow: seed phrase → local storage → records, history,
//! restore, deletion, master change, and device factors.
//!
//! Covers the six verification steps: files on disk, per-demand
//! decryption of records, revision history with restore and clear,
//! master rotation, identity determinism, and a device-factor unlock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

mod common;

use aead::BodyAlg;
use kdf::KdfProfile;
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE};
use seed::SeedPhrase;
use session::{
    change_master, clear_history, delete_record, history, list_records, open_record,
    restore_revision, unlock, vault_meta, write_record, Seen, UnlockCreds, VaultFile,
};

/// A fresh directory under the system temp dir; caller removes it.
fn temp_base(tag: &str) -> std::path::PathBuf {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-e2e-{tag}-");
    for byte in suffix {
        // Both indexes are masked into 0..=15 before the lookup.
        name.push_str(HEX.get(usize::from(byte >> 4)).copied().unwrap_or("0"));
        name.push_str(HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or("0"));
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn login_doc(title: &str, password: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc.set_data(TAG_PASSWORD, ValueType::Secret, password.as_bytes());
    doc
}

#[test]
fn seed_vault_storage_and_records_end_to_end() {
    // -- 1. Seed phrase → files on disk; local.meta readable with the
    //       device id and the identity point.
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();
    let base = temp_base("storage");
    let (paths, mut session, mut file, meta) =
        local::create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    assert!(paths.vault_file.exists(), "vault.brby must exist");
    assert!(paths.local_meta.exists(), "local.meta must exist");

    let meta_key = session.local_meta_key().unwrap();
    let reloaded = local::load_local_meta(&paths.local_meta, &meta_key).unwrap();
    assert_eq!(reloaded.device_id, meta.device_id);
    assert_eq!(reloaded.client_id, meta.client_id);
    assert_eq!(reloaded.client_id, kdf::client_id(&seed).unwrap());
    assert_ne!(meta.device_id, [0u8; 16]);

    // -- 2. One write, then a cold open: the body is decrypted once at
    //       unlock, single records materialize on demand.
    let id = write_record(&mut session, &mut file, None, &login_doc("Blog", "hunter2")).unwrap();
    assert_eq!(list_records(&session).unwrap().len(), 1);
    let bytes = file.as_bytes().to_vec();
    drop(session);
    let mut file = VaultFile::new(bytes);
    let mut session = unlock(&file, &UnlockCreds::master(&seed), None).unwrap();
    let doc = open_record(&session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap().unwrap(), "Blog");
    assert_eq!(
        doc.data(TAG_PASSWORD).unwrap().unwrap(),
        b"hunter2".as_slice()
    );

    // -- 3. History: second revision, restore, clear, delete, clear.
    write_record(&mut session, &mut file, Some(id), &login_doc("Blog", "n3w")).unwrap();
    assert_eq!(history(&session, id).unwrap().len(), 2);

    let restored = restore_revision(&mut session, &mut file, id, 1).unwrap();
    assert_eq!(restored, 3);
    assert_eq!(
        open_record(&session, id)
            .unwrap()
            .data(TAG_PASSWORD)
            .unwrap()
            .unwrap(),
        b"hunter2".as_slice()
    );

    clear_history(&mut session, &mut file).unwrap();
    assert_eq!(history(&session, id).unwrap().len(), 1);
    assert_eq!(
        open_record(&session, id)
            .unwrap()
            .data(TAG_PASSWORD)
            .unwrap()
            .unwrap(),
        b"hunter2".as_slice()
    );

    let seen_now = Seen {
        generation: session.generation(),
        commit_tag: *session.commit_tag(),
    };
    // The mutated file unlocks against its own Seen.
    unlock(&file, &UnlockCreds::master(&seed), Some(seen_now)).unwrap();

    delete_record(&mut session, &mut file, id).unwrap();
    assert!(list_records(&session).unwrap().is_empty());
    assert_eq!(
        open_record(&session, id).unwrap_err().to_string(),
        "record deleted"
    );

    clear_history(&mut session, &mut file).unwrap();
    // No frames at all remain: no records, no history, no vault meta.
    assert!(list_records(&session).unwrap().is_empty());
    assert!(history(&session, id).unwrap().is_empty());
    assert!(vault_meta(&session).unwrap().fields().is_empty());
    assert_eq!(
        open_record(&session, id).unwrap_err().to_string(),
        "record not found"
    );

    // -- 4. Master change: the old seed stops opening, the new one works.
    let phrase2 = SeedPhrase::generate_24().unwrap();
    let seed2 = *phrase2.seed();
    let bytes_before = file.as_bytes().to_vec();
    change_master(&mut session, &mut file, &seed2, &[]).unwrap();
    // The rotated file rejects the old seed and accepts the new one.
    assert_eq!(
        unlock(&file, &UnlockCreds::master(&seed), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    unlock(&file, &UnlockCreds::master(&seed2), None).unwrap();
    // The pre-change file still opens with the old seed.
    let old = VaultFile::new(bytes_before);
    unlock(&old, &UnlockCreds::master(&seed), None).unwrap();
    // Records survive the master change byte for byte.
    let reopened = unlock(&file, &UnlockCreds::master(&seed2), None).unwrap();
    assert!(list_records(&reopened).unwrap().is_empty());

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn identity_is_deterministic_and_devices_differ() {
    let seed = [0x42u8; 64];
    assert_eq!(
        kdf::client_id(&seed).unwrap(),
        kdf::client_id(&seed).unwrap()
    );
    assert_ne!(
        kdf::client_id(&seed).unwrap(),
        kdf::client_id(&[0x43u8; 64]).unwrap()
    );
    // The per-server ids differ from each other and from the global one.
    let a = kdf::client_id_for(&seed, b"https://a.example").unwrap();
    let b = kdf::client_id_for(&seed, b"https://b.example").unwrap();
    assert_ne!(a, b);
    assert_ne!(a, kdf::client_id(&seed).unwrap());

    let base = temp_base("identity");
    let (_p1, _s1, _f1, meta1) =
        local::create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (_p2, _s2, _f2, meta2) =
        local::create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    assert_ne!(meta1.device_id, meta2.device_id);
    assert_eq!(meta1.client_id, meta2.client_id);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn device_factor_opens_without_master() {
    let seed = [0x77u8; 64];
    let base = temp_base("device");
    let (_paths, mut session, mut file, _meta) =
        local::create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();

    write_record(&mut session, &mut file, None, &login_doc("Wifi", "pw")).unwrap();
    let key = common::enroll(&mut session, &mut file);
    drop(session);

    // Device factor only: no master seed presented.
    let opened = common::unlock_device(&file, &key).unwrap();
    let listed = list_records(&opened).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        open_record(&opened, listed[0].id)
            .unwrap()
            .text(TAG_TITLE)
            .unwrap()
            .unwrap(),
        "Wifi"
    );
    std::fs::remove_dir_all(&base).unwrap();
}
