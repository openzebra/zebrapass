//! The sync bundle format: golden bytes, strict parsing, and a full
//! export → import between two devices of one vault.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use record::{Document, TAG_TITLE};
use session::{BodyAlg, DeviceCert, KdfProfile, SyncRecord, SYNC_VK_LEN};
use tui::vault::chip::Chips;
use tui::vault::create::{restore, Enrollment, RestoreVault};
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, Op, Outcome};
use tui::vault::sync_file::{decode, encode, SyncBundle};
use zeroize::Zeroizing;

use common::{make_vault, phrase, temp_dir, PASSWORD};

fn sample() -> SyncBundle {
    SyncBundle {
        cert: DeviceCert {
            client_id: [1; 64],
            device_vk: [2; SYNC_VK_LEN],
            not_after_ms: 3,
            serial: 4,
            signature: vec![5; 3],
        },
        records: vec![(
            [6; 16],
            SyncRecord {
                vault_id: [7; 16],
                record_id: 8,
                revision: 9,
                content_hash: [10; 32],
                msg_version: 1,
                key_generation: 11,
                frame: vec![12; 5],
                signature: vec![13; 2],
            },
        )],
    }
}

fn golden() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ZPSX");
    bytes.extend_from_slice(&[0, 1]);
    bytes.extend_from_slice(&[1; 64]);
    bytes.extend_from_slice(&[2; SYNC_VK_LEN]);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
    bytes.extend_from_slice(&[0, 3, 5, 5, 5]);
    bytes.extend_from_slice(&[0, 0, 0, 1]);
    bytes.extend_from_slice(&[6; 16]);
    bytes.extend_from_slice(&[7; 16]);
    bytes.extend_from_slice(&[0, 0, 0, 8]);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9]);
    bytes.extend_from_slice(&[10; 32]);
    bytes.extend_from_slice(&[0, 1]);
    bytes.extend_from_slice(&[0, 0, 0, 11]);
    bytes.extend_from_slice(&[0, 0, 0, 5]);
    bytes.extend_from_slice(&[12; 5]);
    bytes.extend_from_slice(&[0, 2, 13, 13]);
    bytes
}

#[test]
fn encoding_matches_the_golden_bytes() {
    assert_eq!(encode(&sample()).unwrap(), golden());
    assert_eq!(decode(&golden()).unwrap(), sample());
}

#[test]
fn parsing_is_strict() {
    let bytes = golden();
    for cut in [0, 3, 6, 70, bytes.len() / 2, bytes.len() - 1] {
        assert!(decode(&bytes[..cut]).is_err(), "truncated at {cut} parsed");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[0] = b'X';
    assert_eq!(decode(&magic).unwrap_err().to_string(), "not a sync bundle");
    let mut version = bytes.clone();
    version[5] = 2;
    assert_eq!(
        decode(&version).unwrap_err().to_string(),
        "unsupported sync bundle version"
    );
    let count_at = 6 + 64 + SYNC_VK_LEN + 16 + 5;
    let mut many = bytes.clone();
    many[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        decode(&many).is_err(),
        "a huge count must fail before allocating"
    );
    let mut long_sig = bytes;
    long_sig[6 + 64 + SYNC_VK_LEN + 16] = 0xFF;
    assert!(
        decode(&long_sig).is_err(),
        "a signature longer than ML-DSA-65 must fail"
    );
}

#[test]
fn export_on_one_device_imports_on_another() {
    let chips = Chips::default();
    let sender_base = temp_dir("sync-sender");
    let words = make_vault(&sender_base, BodyAlg::Aegis256);
    let sender_paths = discover(&sender_base).first().unwrap().paths.clone();
    let snapshot = temp_dir("sync-copy").join("vault.brby");
    std::fs::copy(&sender_paths.vault_file, &snapshot).unwrap();

    let receiver_base = temp_dir("sync-receiver");
    let mut receiver = restore(
        RestoreVault {
            phrase: Box::new(phrase(&words)),
            name: String::from("Laptop"),
            base: receiver_base,
            source: snapshot,
            profile: KdfProfile::Mobile,
            factor: Enrollment::KeepExisting,
        },
        &chips,
    )
    .unwrap();

    let mut sender = unlock_vault(
        sender_paths,
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
        &chips,
    )
    .unwrap();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "synced");
    let Outcome::Saved(id) = apply(
        &mut sender,
        Op::Write {
            id: None,
            doc: Box::new(doc),
        },
        &chips,
    )
    .unwrap() else {
        panic!("not saved")
    };
    let bundle = temp_dir("sync-bundle").join("frames.zpsx");
    let exported = apply(
        &mut sender,
        Op::Export(Box::new(phrase(&words)), Box::new([id]), bundle.clone()),
        &chips,
    )
    .unwrap();
    let Outcome::Exported(report) = exported else {
        panic!("not exported")
    };
    assert!(report.preview.unwrap().verified, "the export self-verifies");

    let imported = apply(
        &mut receiver,
        Op::Import(Box::new(phrase(&words)), bundle.clone()),
        &chips,
    )
    .unwrap();
    let Outcome::Imported(report) = imported else {
        panic!("not imported")
    };
    assert_eq!(report.outcomes, vec![(id, Ok(1))]);
    let doc = session::open_record(&receiver.session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("synced"));

    // Replaying the same bundle is rejected as stale.
    let Outcome::Imported(again) = apply(
        &mut receiver,
        Op::Import(Box::new(phrase(&words)), bundle.clone()),
        &chips,
    )
    .unwrap() else {
        panic!("not imported")
    };
    assert!(again.outcomes[0].1.is_err(), "a replay must be rejected");

    // A flipped frame byte is rejected by the signature check.
    let mut bytes = std::fs::read(&bundle).unwrap();
    let at = bytes.len() - 3400;
    bytes[at] ^= 1;
    std::fs::write(&bundle, bytes).unwrap();
    let Outcome::Imported(tampered) = apply(
        &mut receiver,
        Op::Import(Box::new(phrase(&words)), bundle),
        &chips,
    )
    .unwrap() else {
        panic!("not imported")
    };
    assert!(
        tampered.outcomes[0].1.is_err(),
        "a tampered frame must be rejected"
    );

    // Another phrase is refused before anything is read.
    let stranger = seed::SeedPhrase::generate_24().unwrap();
    let error = apply(
        &mut receiver,
        Op::Import(Box::new(stranger), std::path::PathBuf::from("/nonexistent")),
        &chips,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "phrase does not match this vault");
}
