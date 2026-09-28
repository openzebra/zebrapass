#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use aead::BodyAlg;
use kdf::KdfProfile;
use record::{Document, ValueType, TAG_NAME, TAG_PASSWORD, TAG_TITLE};

use super::{
    delete_record, history, list_records, open_record, open_revision, restore_revision, vault_meta,
    RecordSummary,
};
use crate::{
    create, unlock, write_record, write_records_batch, write_vault_meta, UnlockCreds, MAX_BATCH,
};

fn sample_doc(title: &str, password: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc.set_data(TAG_PASSWORD, ValueType::Secret, password.as_bytes());
    doc
}

fn fresh_vault() -> (container::VaultFile, crate::Session) {
    let master = [1u8; 64];
    create(&master, KdfProfile::Fast, BodyAlg::Aegis256).unwrap()
}

#[test]
fn record_lifecycle() {
    let (mut file, mut session) = fresh_vault();
    let id = write_record(&mut session, &mut file, None, &sample_doc("Blog", "p1")).unwrap();
    assert_eq!(id, 1);
    let listed = list_records(&session).unwrap();
    assert_eq!(
        listed,
        vec![RecordSummary {
            id: 1,
            revision: 1,
            timestamp_ms: listed[0].timestamp_ms
        }]
    );
    let doc = open_record(&session, 1).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap().unwrap(), "Blog");

    write_record(&mut session, &mut file, Some(1), &sample_doc("Blog", "p2")).unwrap();
    assert_eq!(history(&session, 1).unwrap().len(), 2);

    let restored_rev = restore_revision(&mut session, &mut file, 1, 1).unwrap();
    assert_eq!(restored_rev, 3);
    assert_eq!(
        open_record(&session, 1)
            .unwrap()
            .data(TAG_PASSWORD)
            .unwrap()
            .unwrap(),
        b"p1".as_slice()
    );
    assert_eq!(history(&session, 1).unwrap().len(), 3);

    let tomb = delete_record(&mut session, &mut file, 1).unwrap();
    assert_eq!(tomb, 4);
    assert!(list_records(&session).unwrap().is_empty());
    assert_eq!(
        open_record(&session, 1).unwrap_err().to_string(),
        "record deleted"
    );
    assert_eq!(
        open_revision(&session, 1, 1)
            .unwrap()
            .text(TAG_TITLE)
            .unwrap()
            .unwrap(),
        "Blog"
    );
}

#[test]
fn missing_and_deleted_records() {
    let (mut file, mut session) = fresh_vault();
    assert_eq!(
        open_record(&session, 9).unwrap_err().to_string(),
        "record not found"
    );
    assert_eq!(
        delete_record(&mut session, &mut file, 9)
            .unwrap_err()
            .to_string(),
        "record not found"
    );
    write_record(&mut session, &mut file, Some(9), &sample_doc("Nine", "")).unwrap();
    delete_record(&mut session, &mut file, 9).unwrap();
    assert_eq!(
        delete_record(&mut session, &mut file, 9)
            .unwrap_err()
            .to_string(),
        "record deleted"
    );
}

#[test]
fn ids_are_allocated_from_the_highest() {
    let (mut file, mut session) = fresh_vault();
    let a = write_record(&mut session, &mut file, Some(5), &sample_doc("A", "")).unwrap();
    let b = write_record(&mut session, &mut file, None, &sample_doc("B", "")).unwrap();
    assert_eq!((a, b), (5, 6));
    // Explicit ids can be sparse; allocation follows the maximum.
    let listed = list_records(&session).unwrap();
    assert_eq!(listed.len(), 2);
}

#[test]
fn vault_meta_round_trip() {
    let (mut file, mut session) = fresh_vault();
    assert!(vault_meta(&session).unwrap().fields().is_empty());
    let mut doc = Document::new();
    doc.set_text(TAG_NAME, "Personal");
    let rev = write_vault_meta(&mut session, &mut file, &doc).unwrap();
    assert_eq!(rev, 1);
    let meta = vault_meta(&session).unwrap();
    assert_eq!(meta.text(TAG_NAME).unwrap().unwrap(), "Personal");
    // Vault meta is hidden from the record list.
    assert!(list_records(&session).unwrap().is_empty());
    // Unknown frames and vault meta survive record writes.
    write_record(&mut session, &mut file, Some(1), &sample_doc("R", "")).unwrap();
    assert_eq!(
        vault_meta(&session)
            .unwrap()
            .text(TAG_NAME)
            .unwrap()
            .unwrap(),
        "Personal"
    );
}

#[test]
fn batch_writes_every_record_in_one_generation() {
    let (mut file, mut session) = fresh_vault();
    let before = session.generation();
    let docs = [
        sample_doc("A", "pa"),
        sample_doc("B", "pb"),
        sample_doc("C", "pc"),
    ];
    let ids = write_records_batch(&mut session, &mut file, &docs).unwrap();
    assert_eq!(ids, [1, 2, 3]);
    assert_eq!(session.generation(), before + 1);
    assert_eq!(list_records(&session).unwrap().len(), 3);
    for (id, password) in ids.iter().zip(["pa", "pb", "pc"]) {
        let doc = open_record(&session, *id).unwrap();
        assert_eq!(
            doc.data(TAG_PASSWORD).unwrap().unwrap(),
            password.as_bytes()
        );
    }
    let reopened = unlock(&file, &UnlockCreds::master(&[1u8; 64]), None).unwrap();
    assert_eq!(list_records(&reopened).unwrap().len(), 3);
}

#[test]
fn batch_ids_continue_after_the_highest() {
    let (mut file, mut session) = fresh_vault();
    write_record(&mut session, &mut file, Some(7), &sample_doc("Seven", "")).unwrap();
    let ids = write_records_batch(
        &mut session,
        &mut file,
        &[sample_doc("X", ""), sample_doc("Y", "")],
    )
    .unwrap();
    assert_eq!(ids, [8, 9]);
}

#[test]
fn batch_tamper_fails_unlock() {
    let (mut file, mut session) = fresh_vault();
    write_records_batch(&mut session, &mut file, &[sample_doc("A", "pa")]).unwrap();
    let mut bytes = file.as_bytes().to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let tampered = container::VaultFile::new(bytes);
    assert!(unlock(&tampered, &UnlockCreds::master(&[1u8; 64]), None).is_err());
}

#[test]
fn batch_over_limit_leaves_the_vault_unchanged() {
    let (mut file, mut session) = fresh_vault();
    let before = file.as_bytes().to_vec();
    let docs: Vec<Document> = (0..=MAX_BATCH).map(|_| Document::new()).collect();
    assert_eq!(
        write_records_batch(&mut session, &mut file, &docs)
            .unwrap_err()
            .to_string(),
        "batch too large"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
    assert!(write_records_batch(&mut session, &mut file, &[])
        .unwrap()
        .is_empty());
    assert_eq!(file.as_bytes(), before.as_slice());
}
