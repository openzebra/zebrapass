//! What a placeholder checks before it makes a fetched file its vault: the
//! file is the one the peer announced, it opens with the held password and
//! its commitment intact, and it is not older than what is held.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::path::Path;
use std::sync::Arc;

use local::SyncIdentity;
use p2p_net::{Announce, PersonalFetch};
use record::{Document, TAG_TITLE};
use session::{list_records, write_record, VaultFile};
use tui::vault::adopt::{adopt_fetched, AdoptRequest};
use tui::vault::discover::discover;
use tui::vault::error::UnlockError;
use tui::vault::open::{unlock_vault, Credential, Vault};
use zeroize::Zeroizing;

use common::{make_vault, phrase, temp_dir, PASSWORD};

/// A password the first device's file does not open with.
const OTHER_PASSWORD: &str = "the-second-devices-own-password-9";

struct Origin {
    words: String,
    file: Vec<u8>,
    announce: Announce,
}

fn origin(tag: &str, records: usize) -> Origin {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    let paths = discover(&base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(
        paths.clone(),
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    for n in 0..records {
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, &format!("entry {n}"));
        write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    }
    vault.persist().unwrap();
    let file = std::fs::read(&paths.vault_file).unwrap();
    let announce = announce_of(&file);
    Origin {
        words,
        file,
        announce,
    }
}

fn announce_of(file: &[u8]) -> Announce {
    let file = VaultFile::new(file.to_vec());
    let parsed = file.parse().unwrap();
    Announce {
        vault_id: parsed.header.vault_id,
        generation: parsed.generation,
        commit_tag: parsed.commit,
    }
}

fn identity(words: &str) -> SyncIdentity {
    let phrase = phrase(words);
    let client_id = kdf::client_id(phrase.seed()).unwrap();
    SyncIdentity::enroll(phrase.seed(), &client_id, [9; 16], u64::MAX).unwrap()
}

fn request(words: &str, base: &Path, password: &str) -> AdoptRequest {
    let phrase = phrase(words);
    AdoptRequest {
        placeholder: local::paths_for(base, &[0xAA; 16]),
        identity: Arc::new(identity(words)),
        client_id: kdf::client_id(phrase.seed()).unwrap(),
        name: String::from("Personal"),
        password: Zeroizing::new(password.as_bytes().to_vec()),
        addresses: Vec::new(),
        loopback: true,
    }
}

fn fetched(file: Vec<u8>, announce: Announce, words: &str) -> PersonalFetch {
    PersonalFetch {
        announce,
        file,
        peer: identity(words).devices()[0].clone(),
    }
}

fn adopt(
    words: &str,
    base: &Path,
    file: Vec<u8>,
    announce: Announce,
) -> Result<Box<Vault>, UnlockError> {
    adopt_with(words, base, PASSWORD, file, announce)
}

fn adopt_with(
    words: &str,
    base: &Path,
    password: &str,
    file: Vec<u8>,
    announce: Announce,
) -> Result<Box<Vault>, UnlockError> {
    adopt_fetched(
        &request(words, base, password),
        fetched(file, announce, words),
        "127.0.0.1:1",
    )
}

fn nothing_on_disk(base: &Path) {
    assert!(discover(base).is_empty());
    assert!(
        !base.join("vaults").exists()
            || std::fs::read_dir(base.join("vaults"))
                .unwrap()
                .next()
                .is_none(),
        "a refused file leaves no directory behind"
    );
}

#[test]
fn a_file_that_is_the_announced_vault_is_adopted_with_its_records() {
    let first = origin("adopt-good", 3);
    let base = temp_dir("adopt-good-b");
    let vault = adopt(&first.words, &base, first.file.clone(), first.announce).unwrap();
    assert_eq!(list_records(&vault.session).unwrap().len(), 3);
    assert_eq!(vault.session.vault_id(), &first.announce.vault_id);
    assert!(vault.meta.seen.is_some());
    assert!(vault.paths.sync_identity().is_file());
    let password = |text: &str| Credential::Password(Zeroizing::new(text.as_bytes().to_vec()));
    let reopened = unlock_vault(vault.paths.clone(), password(PASSWORD)).unwrap();
    assert_eq!(list_records(&reopened.session).unwrap().len(), 3);
    assert!(
        unlock_vault(vault.paths.clone(), password(OTHER_PASSWORD)).is_err(),
        "the vault keeps the password it was sealed with"
    );
}

#[test]
fn a_password_that_does_not_open_the_file_is_refused_and_leaves_nothing() {
    let first = origin("adopt-wrong-password", 2);
    let base = temp_dir("adopt-wrong-password-b");
    let outcome = adopt_with(
        &first.words,
        &base,
        OTHER_PASSWORD,
        first.file.clone(),
        first.announce,
    );
    assert_eq!(outcome.unwrap_err(), UnlockError::Denied);
    nothing_on_disk(&base);
}

#[test]
fn a_flipped_byte_anywhere_in_the_file_is_refused_and_leaves_nothing() {
    let first = origin("adopt-flip", 2);
    let base = temp_dir("adopt-flip-b");
    for at in [
        first.file.len() / 2,
        first.file.len() - 1,
        first.file.len() - 40,
        40,
    ] {
        let mut file = first.file.clone();
        file[at] ^= 0x01;
        let outcome = adopt(&first.words, &base, file, first.announce);
        assert!(
            matches!(
                outcome,
                Err(UnlockError::WrongVault | UnlockError::NotAVault | UnlockError::Denied)
            ),
            "byte {at}: {outcome:?}"
        );
        nothing_on_disk(&base);
    }
}

#[test]
fn a_file_of_another_vault_is_not_the_one_announced() {
    let first = origin("adopt-other-a", 1);
    let other = origin("adopt-other-b", 1);
    let base = temp_dir("adopt-other-c");
    let outcome = adopt(&first.words, &base, other.file, first.announce);
    assert_eq!(outcome.unwrap_err(), UnlockError::WrongVault);
    nothing_on_disk(&base);
}

#[test]
fn an_announcement_that_disagrees_with_the_file_is_refused() {
    let first = origin("adopt-announce", 1);
    let base = temp_dir("adopt-announce-b");
    for lie in [
        Announce {
            generation: first.announce.generation + 1,
            ..first.announce
        },
        Announce {
            commit_tag: [0; 32],
            ..first.announce
        },
        Announce {
            vault_id: [7; 16],
            ..first.announce
        },
    ] {
        let outcome = adopt(&first.words, &base, first.file.clone(), lie);
        assert_eq!(outcome.unwrap_err(), UnlockError::WrongVault);
        nothing_on_disk(&base);
    }
}

#[test]
fn a_second_restore_with_an_older_file_is_refused_as_a_rollback() {
    let first = origin("adopt-rollback", 2);
    let base = temp_dir("adopt-rollback-b");
    let mut vault = adopt(&first.words, &base, first.file.clone(), first.announce).unwrap();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "written on the second device");
    write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    vault.persist().unwrap();
    let held = std::fs::read(&vault.paths.vault_file).unwrap();
    drop(vault);

    let outcome = adopt(&first.words, &base, first.file.clone(), first.announce);
    assert!(
        matches!(outcome, Err(UnlockError::Rollback { .. })),
        "{outcome:?}"
    );
    assert_eq!(
        std::fs::read(discover(&base)[0].paths.vault_file.clone()).unwrap(),
        held,
        "the newer file on disk is untouched"
    );
    let reopened = unlock_vault(
        discover(&base)[0].paths.clone(),
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    assert_eq!(list_records(&reopened.session).unwrap().len(), 3);
}
