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
    // An id given by the caller is kept, as in a vault written by an older
    // binary, which numbered its records from 1.
    let id = write_record(&mut session, &mut file, Some(1), &sample_doc("Blog", "p1")).unwrap();
    assert_eq!(id, 1);
    let listed = list_records(&session).unwrap();
    assert_eq!(
        listed,
        vec![RecordSummary {
            id,
            revision: 1,
            timestamp_ms: listed[0].timestamp_ms
        }]
    );
    let doc = open_record(&session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap().unwrap(), "Blog");

    write_record(&mut session, &mut file, Some(id), &sample_doc("Blog", "p2")).unwrap();
    assert_eq!(history(&session, id).unwrap().len(), 2);

    let restored_rev = restore_revision(&mut session, &mut file, id, 1).unwrap();
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
fn new_records_get_random_ids_that_are_never_zero_and_never_held() {
    let (mut file, mut session) = fresh_vault();
    // Records numbered the old way stay valid and are never reused.
    write_record(&mut session, &mut file, Some(1), &sample_doc("old", "")).unwrap();
    write_record(&mut session, &mut file, Some(2), &sample_doc("older", "")).unwrap();
    delete_record(&mut session, &mut file, 2).unwrap();
    let mut seen = std::collections::HashSet::from([1u32, 2]);
    for n in 0..300 {
        let id = write_record(
            &mut session,
            &mut file,
            None,
            &sample_doc(&format!("r{n}"), ""),
        )
        .unwrap();
        assert_ne!(id, 0);
        assert!(seen.insert(id), "id {id} was handed out twice");
    }
    assert_eq!(list_records(&session).unwrap().len(), 301);
    let beyond_a_counter = seen.iter().filter(|id| **id > 1_000).count();
    assert!(
        beyond_a_counter > 290,
        "ids are spread over the whole range, not counted up"
    );
}

#[test]
fn the_batch_draws_distinct_random_ids_too() {
    let (mut file, mut session) = fresh_vault();
    write_record(&mut session, &mut file, Some(7), &sample_doc("Seven", "")).unwrap();
    let docs: Vec<Document> = (0..200).map(|n| sample_doc(&format!("b{n}"), "")).collect();
    let ids = write_records_batch(&mut session, &mut file, &docs).unwrap();
    let distinct: std::collections::HashSet<u32> = ids.iter().copied().collect();
    assert_eq!(distinct.len(), 200);
    assert!(!distinct.contains(&0) && !distinct.contains(&7));
    assert_eq!(list_records(&session).unwrap().len(), 201);
}

#[test]
fn a_draw_that_is_zero_or_taken_is_drawn_again_and_the_tries_are_bounded() {
    use super::ids::pick;
    use anyhow::anyhow;
    let mut draws = [0u32, 5, 5, 9].into_iter();
    let id = pick(|| Ok(draws.next().unwrap()), |id| id == 5).unwrap();
    assert_eq!(id, 9, "zero and the taken id are skipped");

    let mut tries = 0;
    let error = pick(
        || {
            tries += 1;
            Ok(5)
        },
        |_| true,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "no free record id");
    assert_eq!(tries, 32, "bounded, and no fallback to counting");

    let mut tries = 0;
    let error = pick(
        || {
            tries += 1;
            Err(anyhow!("os entropy failed"))
        },
        |_| false,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "os entropy failed");
    assert_eq!(tries, 1, "a failing generator is an error, never retried");
}

#[test]
fn with_every_other_id_of_the_wire_taken_the_only_free_one_is_found_or_the_search_stops() {
    use super::ids::pick;
    // The vault "holds" every id the wire allows except `free`.
    let free = 4_000_000_000u32;
    let taken = |id: u32| id != free;
    let mut near = (free - 20..).map(Ok);
    assert_eq!(pick(|| near.next().unwrap(), taken).unwrap(), free);
    let mut far = (free - 40..).map(Ok);
    assert!(
        pick(|| far.next().unwrap(), taken).is_err(),
        "32 draws that miss end the search with an error"
    );
    let mut all = 1..=u32::MAX;
    assert!(pick(|| Ok(all.next().unwrap()), |_| true).is_err());
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
    assert_eq!(ids.len(), 3);
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
