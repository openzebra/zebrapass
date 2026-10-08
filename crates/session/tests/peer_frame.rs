//! A record frame from another device of the same account, and reopening a
//! vault with a key already held.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use frame::{seal, FrameMeta, ALG_CASCADE, KIND_REVISION};
use kdf::frame_key;
use record::{Document, TAG_TITLE};
use session::{
    accept_peer_frame, create, frontier, latest_frame, list_records, open_record, unlock,
    unlock_with_key, write_record, write_vault_meta, BodyAlg, KdfProfile, SessionError,
    UnlockCreds, VaultFile,
};

const SEED: [u8; 64] = [5; 64];

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

fn vault() -> (session::Session, VaultFile) {
    let (file, session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    (session, file)
}

/// The same vault as two devices hold it: a copy taken now.
fn copy_of(file: &VaultFile) -> (session::Session, VaultFile) {
    let copy = VaultFile::new(file.as_bytes().to_vec());
    let mut session = unlock(&copy, &UnlockCreds::master(&SEED), None).unwrap();
    session.set_origin_device([2; 16]).unwrap();
    (session, copy)
}

fn title(session: &session::Session, id: u32) -> String {
    open_record(session, id)
        .unwrap()
        .text(TAG_TITLE)
        .unwrap()
        .unwrap()
        .to_owned()
}

#[test]
fn a_newer_frame_is_kept_and_the_same_one_again_is_stale() {
    let (mut first, mut first_file) = vault();
    first.set_origin_device([1; 16]).unwrap();
    let id = write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let (mut second, mut second_file) = copy_of(&first_file);
    write_record(&mut first, &mut first_file, Some(id), &titled("two")).unwrap();

    let frame = latest_frame(&first, id).unwrap();
    let accepted = accept_peer_frame(&mut second, &mut second_file, &frame).unwrap();
    assert_eq!((accepted.record_id, accepted.revision), (id, 2));
    assert_eq!(title(&second, id), "two");
    assert_eq!(frontier(&second).unwrap(), frontier(&first).unwrap());

    let again = accept_peer_frame(&mut second, &mut second_file, &frame).unwrap_err();
    assert_eq!(
        again.downcast_ref::<SessionError>(),
        Some(&SessionError::StaleRevision)
    );
}

#[test]
fn a_frame_sealed_under_another_vault_key_is_refused_and_changes_nothing() {
    let (mut first, mut first_file) = vault();
    first.set_origin_device([1; 16]).unwrap();
    write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let (mut second, mut second_file) = copy_of(&first_file);
    let before = second_file.as_bytes().to_vec();

    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: 1,
        revision: 9,
        origin_device: [1; 16],
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    let foreign = frame_key(&[0xEE; 32], second.vault_id(), 1).unwrap();
    let forged = seal(&foreign, &meta, b"forged").unwrap();
    assert!(accept_peer_frame(&mut second, &mut second_file, &forged).is_err());
    assert_eq!(second_file.as_bytes(), before.as_slice());
    assert_eq!(title(&second, 1), "one");
}

#[test]
fn a_frame_with_a_flipped_byte_is_refused() {
    let (mut first, mut first_file) = vault();
    first.set_origin_device([1; 16]).unwrap();
    let id = write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let (mut second, mut second_file) = copy_of(&first_file);
    write_record(&mut first, &mut first_file, Some(id), &titled("two")).unwrap();
    let frame = latest_frame(&first, id).unwrap();
    for at in [0, frame.len() / 2, frame.len() - 1] {
        let mut bad = frame.clone();
        bad[at] ^= 1;
        assert!(
            accept_peer_frame(&mut second, &mut second_file, &bad).is_err(),
            "byte {at}"
        );
    }
    assert_eq!(title(&second, id), "one");
}

#[test]
fn the_vaults_own_record_zero_is_never_taken_from_a_peer() {
    let (mut first, mut first_file) = vault();
    first.set_origin_device([1; 16]).unwrap();
    write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let (mut second, mut second_file) = copy_of(&first_file);
    write_vault_meta(&mut first, &mut first_file, &titled("renamed")).unwrap();
    let meta_frame = latest_frame(&first, 0).unwrap();
    let refused = accept_peer_frame(&mut second, &mut second_file, &meta_frame).unwrap_err();
    assert_eq!(
        refused.downcast_ref::<SessionError>(),
        Some(&SessionError::HeaderMismatch)
    );
    assert!(frontier(&first)
        .unwrap()
        .iter()
        .all(|row| row.record_id != 0));
    assert_eq!(list_records(&second).unwrap().len(), 1);
}

#[test]
fn a_frame_from_the_zero_origin_or_an_oversized_one_is_refused() {
    let (mut first, mut first_file) = vault();
    let id = write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let (mut second, mut second_file) = copy_of(&first_file);
    let key = frame_key(first.reopen_key().expose(), second.vault_id(), id).unwrap();
    let meta = |origin: [u8; 16]| FrameMeta {
        kind: KIND_REVISION,
        record_id: id,
        revision: 9,
        origin_device: origin,
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    let zero = seal(&key, &meta([0; 16]), b"x").unwrap();
    let refused = accept_peer_frame(&mut second, &mut second_file, &zero).unwrap_err();
    assert_eq!(
        refused.downcast_ref::<SessionError>(),
        Some(&SessionError::ZeroOrigin)
    );
    let ok = seal(&key, &meta([3; 16]), b"x").unwrap();
    let mut huge = ok;
    huge.resize(huge.len() + 2_000_000, 0);
    assert!(accept_peer_frame(&mut second, &mut second_file, &huge).is_err());
    assert!(accept_peer_frame(&mut second, &mut second_file, &[0u8; 5]).is_err());
}

#[test]
fn a_vault_reopens_with_its_key_and_only_with_the_right_one() {
    let (mut first, mut first_file) = vault();
    write_record(&mut first, &mut first_file, None, &titled("one")).unwrap();
    let key = first.reopen_key();
    let reopened = unlock_with_key(&first_file, &key, [4; 16]).unwrap();
    assert_eq!(title(&reopened, 1), "one");
    assert_eq!(reopened.generation(), first.generation());
    assert_eq!(reopened.origin_device(), [4; 16]);

    let wrong = secret::Secret::new([0x77; 32]);
    assert!(unlock_with_key(&first_file, &wrong, [4; 16]).is_err());
    let mut flipped = first_file.as_bytes().to_vec();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 1;
    assert!(
        unlock_with_key(&VaultFile::new(flipped), &key, [4; 16]).is_err(),
        "the commitment is checked before the body is opened"
    );
}
