#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use aead::BodyAlg;
use local::{
    BackupContents, DeviceKey, Edit, SyncIdentity, build_backup_bundle, create_shared_vault,
    create_vault, export_backup_file, list_shared_refs, open_backup_bundle, open_shared_vault,
    restore_shared_entries, save_local_meta, seal_device_key, write_atomic, write_rolling_backup,
};
use record::{Document, TAG_PASSWORD, TAG_TITLE, ValueType};
use seed::SeedPhrase;
use session::{
    KdfProfile, UnlockCreds, add_chip_unlock, drop_recovery_wrap, list_records, open_record,
    write_record,
};

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-backup-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn login(title: &str, pass: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc.set_data(TAG_PASSWORD, ValueType::Secret, pass.as_bytes());
    doc
}

#[test]
fn round_trip_personal_and_two_shared_vaults_and_excludes_device_secrets() {
    let src_base = temp_dir("src");
    let dst_base = temp_dir("dst");
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();

    let (paths, mut session, mut file, mut meta) =
        create_vault(&src_base, &seed, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    meta.name = "Main Vault".to_owned();
    save_local_meta(&paths.local_meta, &meta, &session.local_meta_key().unwrap()).unwrap();

    let id = SyncIdentity::enroll(&seed, &meta.client_id, meta.device_id, u64::MAX).unwrap();
    id.save(
        &paths.sync_identity(),
        &session.sync_identity_key().unwrap(),
    )
    .unwrap();

    // Enroll a device.key so we can prove its private material is never copied into backups.
    let dev_key = DeviceKey::generate().unwrap();
    let publics = dev_key.publics().unwrap();
    add_chip_unlock(&mut session, &mut file, &publics).unwrap();
    seal_device_key(
        &paths.device_key,
        session.vault_id(),
        &dev_key,
        b"123456",
        KdfProfile::Fast,
    )
    .unwrap();

    let personal_rec = write_record(&mut session, &mut file, None, &login("Bank", "p@ss")).unwrap();

    // Create two shared vaults and link them via SharedRef records inside the personal vault.
    let (mut shared_a, ref_a) =
        create_shared_vault(&src_base, &id, "Team Alpha", KdfProfile::Fast).unwrap();
    shared_a
        .edit(
            &ref_a,
            &id,
            Edit::Create(Box::new(login("Alpha API", "ak-111"))),
        )
        .unwrap();
    write_record(&mut session, &mut file, None, &ref_a.to_document()).unwrap();

    let (mut shared_b, ref_b) =
        create_shared_vault(&src_base, &id, "Team Beta", KdfProfile::Fast).unwrap();
    shared_b
        .edit(
            &ref_b,
            &id,
            Edit::Create(Box::new(login("Beta Key", "bk-222"))),
        )
        .unwrap();
    write_record(&mut session, &mut file, None, &ref_b.to_document()).unwrap();
    write_atomic(&paths.vault_file, file.as_bytes()).unwrap();

    let backup_path = src_base.join("export.zpbackup");
    export_backup_file(&backup_path, &src_base, &session, &file, &meta.name).unwrap();
    let raw_backup = fs::read(&backup_path).unwrap();

    // Device-bound signing seed and device.key material must never appear in backups.
    assert!(
        !raw_backup
            .windows(id.sign_key().seed().len())
            .any(|w| w == id.sign_key().seed()),
        "sync.id signing seed must never leak into backups"
    );
    let dk_bytes = fs::read(&paths.device_key).unwrap();
    assert!(
        !raw_backup
            .windows(64)
            .any(|w| dk_bytes.windows(64).any(|d| d == w)),
        "device.key material must never leak into backups"
    );

    // Restore onto a clean destination directory with a brand-new device identity.
    let opened = open_backup_bundle(&raw_backup, &UnlockCreds::master(&seed)).unwrap();
    let BackupContents::Bundle(bundle) = opened else {
        panic!("expected ZPBK bundle");
    };
    assert_eq!(bundle.name, "Main Vault");
    assert_eq!(bundle.shared.len(), 2);
    assert_eq!(
        open_record(&bundle.session, personal_rec)
            .unwrap()
            .text(TAG_TITLE)
            .unwrap(),
        Some("Bank")
    );

    let dst_device = session::fresh_device_id().unwrap();
    let dst_id = SyncIdentity::enroll(&seed, &meta.client_id, dst_device, u64::MAX).unwrap();
    let count =
        restore_shared_entries(&dst_base, &dst_id, &bundle.session, &bundle.shared, false).unwrap();
    assert_eq!(count, 2);

    let restored_refs = list_shared_refs(&bundle.session);
    assert_eq!(restored_refs.len(), 2);
    for r in &restored_refs {
        let opened = open_shared_vault(&dst_base, r, &dst_id).unwrap();
        assert_eq!(list_records(&opened.session).unwrap().len(), 1);
    }

    // Legacy BRBY files also open cleanly via open_backup_bundle.
    let legacy = open_backup_bundle(file.as_bytes(), &UnlockCreds::master(&seed)).unwrap();
    assert!(matches!(legacy, BackupContents::LegacyVault(_)));

    fs::remove_dir_all(&src_base).unwrap();
    fs::remove_dir_all(&dst_base).unwrap();
}

#[test]
fn tamper_in_any_section_and_missing_portable_wrap_are_rejected() {
    let base = temp_dir("tamper");
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();

    let (paths, mut session, mut file, meta) =
        create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let id = SyncIdentity::enroll(&seed, &meta.client_id, meta.device_id, u64::MAX).unwrap();
    let (mut shared_a, ref_a) = create_shared_vault(&base, &id, "Alpha", KdfProfile::Fast).unwrap();
    shared_a
        .edit(&ref_a, &id, Edit::Create(Box::new(login("Secret", "pw"))))
        .unwrap();
    write_record(&mut session, &mut file, None, &ref_a.to_document()).unwrap();

    let bundle = build_backup_bundle(&base, &session, &file, "Vault").unwrap();

    // Flip bytes in header (offset 10), personal length/payload (offset 80),
    // aux section, and tail HMAC (last byte).
    let personal_len = u32::from_be_bytes(bundle[70..74].try_into().unwrap()) as usize;
    let aux_off = 74 + personal_len + 8;
    for offset in [10, 80, aux_off, bundle.len() - 1] {
        let mut tampered = bundle.clone();
        tampered[offset] ^= 0x01;
        assert!(
            open_backup_bundle(&tampered, &UnlockCreds::master(&seed)).is_err(),
            "tamper at offset {offset} must fail"
        );
    }
    // Truncated and extended bundles fail.
    assert!(open_backup_bundle(&bundle[..bundle.len() - 1], &UnlockCreds::master(&seed)).is_err());
    let mut extended = bundle.clone();
    extended.push(0);
    assert!(open_backup_bundle(&extended, &UnlockCreds::master(&seed)).is_err());

    // Wrong credentials fail.
    assert!(open_backup_bundle(&bundle, &UnlockCreds::master(&[9u8; 64])).is_err());

    // Vault with only a device wrap (no recovery or password wrap) fails closed on export.
    let dev = DeviceKey::generate().unwrap();
    let publics = dev.publics().unwrap();
    add_chip_unlock(&mut session, &mut file, &publics).unwrap();
    drop_recovery_wrap(&mut session, &mut file).unwrap();
    assert!(build_backup_bundle(&base, &session, &file, "Vault").is_err());
    let _ = paths;

    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn rollback_shared_restore_rejected_and_rolling_backups_prune() {
    let base = temp_dir("roll");
    let roll_dir = base.join("rolling");
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();

    let (_paths, mut session, mut file, meta) =
        create_vault(&base, &seed, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let id = SyncIdentity::enroll(&seed, &meta.client_id, meta.device_id, u64::MAX).unwrap();
    let (mut shared_a, ref_a) = create_shared_vault(&base, &id, "Alpha", KdfProfile::Fast).unwrap();
    shared_a
        .edit(&ref_a, &id, Edit::Create(Box::new(login("One", "1"))))
        .unwrap();
    write_record(&mut session, &mut file, None, &ref_a.to_document()).unwrap();

    // Export an older backup at gen 1 of shared vault.
    let old_bundle = build_backup_bundle(&base, &session, &file, "V").unwrap();
    // Advance shared vault generation on disk.
    shared_a
        .edit(&ref_a, &id, Edit::Create(Box::new(login("Two", "2"))))
        .unwrap();

    let BackupContents::Bundle(old_parsed) =
        open_backup_bundle(&old_bundle, &UnlockCreds::master(&seed)).unwrap()
    else {
        panic!("expected bundle");
    };
    assert!(
        restore_shared_entries(&base, &id, &old_parsed.session, &old_parsed.shared, false).is_err(),
        "restoring older shared vault without override must fail"
    );
    assert_eq!(
        restore_shared_entries(&base, &id, &old_parsed.session, &old_parsed.shared, true).unwrap(),
        1
    );

    // Rolling backups keep only the newest 3 files across 7 generations.
    for n in 0..7 {
        write_record(
            &mut session,
            &mut file,
            None,
            &login(&format!("Item {n}"), "pw"),
        )
        .unwrap();
        write_rolling_backup(&base, &session, &file, "V", &roll_dir, 3).unwrap();
    }
    let kept: Vec<_> = fs::read_dir(&roll_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("zpbackup"))
        .collect();
    assert_eq!(kept.len(), 3);

    fs::remove_dir_all(&base).unwrap();
}
