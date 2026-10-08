//! Restore with the phrase alone: the second device types the phrase and the
//! address of the first, and the vault arrives over the peer-to-peer
//! transport. Driven with real keystrokes against two apps on one machine.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::net::TcpListener;
use std::path::Path;

use crossterm::event::KeyCode;
use record::{Document, TAG_TITLE};
use session::{write_record, KdfProfile};
use tui::app::flows::restore::RestoreField;
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::App;
use zeroize::Zeroizing;

use common::{
    app, ctrl, keep_to_this_device, keep_to_this_device_with, make_vault, press, render, temp_dir,
    type_text, unlock, wait, PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

/// Put records into the vault under `base` while no app has it open.
fn add_records(base: &Path, titles: &[&str]) {
    let paths = discover(base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(
        paths,
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    for title in titles {
        write_record(&mut vault.session, &mut vault.file, None, &titled(title)).unwrap();
    }
    vault.persist().unwrap();
}

/// The first device: a vault with records, its node on this device only, and
/// the app unlocked so the node runs. Returns the app, the phrase and the
/// address the node listens at.
fn first_device(tag: &str) -> (App, String, String) {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    keep_to_this_device(&base);
    add_records(&base, &["wifi", "bank"]);
    let mut first = app(&base);
    unlock(&mut first, PASSWORD);
    let address = listening(&first);
    (first, words, address)
}

fn listening(app: &App) -> String {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
        .p2p
        .as_ref()
        .expect("the node runs without a shared vault")
        .service
        .local_addr()
        .expect("the node listens")
        .to_string()
}

fn titles_of(app: &App) -> Vec<String> {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    let mut titles: Vec<String> = state
        .cache
        .iter()
        .map(|row| row.title.to_string())
        .collect();
    titles.sort();
    titles
}

/// Welcome → restore chooser → the phrase restore.
fn open_restore(app: &mut App) {
    press(app, KeyCode::Right);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
}

fn type_phrase(app: &mut App, words: &str) {
    for word in words.split(' ') {
        type_text(app, word);
        press(app, KeyCode::Char(' '));
    }
}

fn restore_state(app: &App) -> &tui::app::flows::restore::RestoreState {
    let Screen::Restore(state) = &app.screen else {
        panic!("not restore: {}", app.screen.name())
    };
    state
}

/// Put `address` in the network source and press Continue.
fn set_address_and_continue(app: &mut App, address: &str) {
    while restore_state(app).field != RestoreField::Phrase {
        press(app, KeyCode::BackTab);
    }
    if !restore_state(app).network {
        app.on_key(&ctrl('n'));
    }
    press(app, KeyCode::Tab);
    assert_eq!(restore_state(app).field, RestoreField::Source);
    for _ in 0..restore_state(app).address.value().len() {
        press(app, KeyCode::Backspace);
    }
    type_text(app, address);
    press(app, KeyCode::Enter);
}

/// Phrase, then the network source with `address`, then Continue.
fn enter_phrase_and_address(app: &mut App, words: &str, address: &str) {
    assert_eq!(restore_state(app).field, RestoreField::Phrase);
    type_phrase(app, words);
    set_address_and_continue(app, address);
}

fn enroll_password(app: &mut App) {
    type_text(app, SECOND_PASSWORD);
    press(app, KeyCode::Tab);
    type_text(app, SECOND_PASSWORD);
    press(app, KeyCode::Enter);
    wait(app);
}

#[test]
fn the_share_screen_shows_the_address_to_type_on_a_new_device() {
    let (mut first, _words, address) = first_device("net-show");
    press(&mut first, KeyCode::Char('S'));
    let screen = render(&first, 140, 50);
    assert!(screen.contains("restore from"), "{screen}");
    assert!(
        screen.contains(&address),
        "the address is the one the node listens at (this device only):\n{screen}"
    );
}

#[test]
fn the_phrase_and_an_address_bring_the_vault_to_a_new_device() {
    let (first, words, address) = first_device("net-first");
    let base = temp_dir("net-second");
    let mut second = app(&base);
    open_restore(&mut second);
    enter_phrase_and_address(&mut second, &words, &address);
    assert_eq!(
        second.screen.name(),
        "restore",
        "the factor step comes next"
    );
    enroll_password(&mut second);

    assert_eq!(second.screen.name(), "unlocked");
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
    assert_eq!(titles_of(&second), titles_of(&first));

    // The second device is a vault of its own now: it locks and unlocks with
    // the password it chose, and finds the first device again by itself.
    let paths = discover(&base).first().unwrap().paths.clone();
    assert!(paths.sync_identity().is_file());
    assert!(paths.peers_store().is_file(), "the address is remembered");
    let Screen::Unlocked(state) = &second.screen else {
        panic!("not unlocked")
    };
    let vault = state.vault.as_ref().unwrap();
    let cursor = vault.meta.seen.unwrap();
    assert_eq!(
        cursor.generation,
        vault.session.generation(),
        "the rollback cursor is the adopted file"
    );
    press(&mut second, KeyCode::Char('L'));
    press(&mut second, KeyCode::Enter);
    assert_eq!(second.screen.name(), "unlock");
    unlock(&mut second, SECOND_PASSWORD);
    eprintln!("{}", render(&second, 120, 40));
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
}

#[test]
fn a_wrong_address_says_so_and_a_second_try_with_the_right_one_works() {
    let (_first, words, address) = first_device("net-retry-first");
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let base = temp_dir("net-retry-second");
    let mut second = app(&base);
    open_restore(&mut second);
    enter_phrase_and_address(&mut second, &words, &closed);
    enroll_password(&mut second);
    assert_eq!(
        second.screen.name(),
        "restore",
        "stays on the restore screen"
    );
    assert!(render(&second, 140, 50).contains("could not be reached"));
    assert!(discover(&base).is_empty(), "nothing was written");

    enter_phrase_and_address(&mut second, &words, &address);
    enroll_password(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
}

#[test]
fn a_phrase_of_another_account_is_turned_away() {
    let (_first, _words, address) = first_device("net-foreign-first");
    let stranger = make_vault(&temp_dir("net-foreign-other"));
    let base = temp_dir("net-foreign-second");
    let mut second = app(&base);
    open_restore(&mut second);
    enter_phrase_and_address(&mut second, &stranger, &address);
    enroll_password(&mut second);
    assert_eq!(second.screen.name(), "restore");
    assert!(render(&second, 140, 50).contains("turned this one away"));
    assert!(discover(&base).is_empty());
}

#[test]
fn an_address_nobody_may_dial_is_refused_on_the_screen() {
    let base = temp_dir("net-bad-address");
    let mut second = app(&base);
    open_restore(&mut second);
    let (_first, words, _address) = first_device("net-bad-first");
    type_phrase(&mut second, &words);
    for refused in [
        "169.254.169.254:80",
        "0.0.0.0:7447",
        "not an address",
        "10.0.0.1",
    ] {
        set_address_and_continue(&mut second, refused);
        assert_eq!(restore_state(&second).field, RestoreField::Source);
        assert_eq!(
            second.screen.name(),
            "restore",
            "{refused} must not reach the factor step"
        );
        assert!(restore_state(&second).error.is_some(), "{refused}");
    }
}

#[test]
fn restoring_from_a_file_still_works_as_before() {
    let first_base = temp_dir("file-first");
    let words = make_vault(&first_base);
    add_records(&first_base, &["wifi", "bank"]);
    let file = discover(&first_base)
        .first()
        .unwrap()
        .paths
        .vault_file
        .clone();

    let base = temp_dir("file-second");
    let mut second = app(&base);
    open_restore(&mut second);
    type_phrase(&mut second, &words);
    press(&mut second, KeyCode::Tab);
    assert_eq!(restore_state(&second).field, RestoreField::Source);
    assert!(!restore_state(&second).network, "a file is the default");
    for _ in 0..restore_state(&second).source.value().len() {
        press(&mut second, KeyCode::Backspace);
    }
    type_text(&mut second, &file.to_string_lossy());
    assert!(restore_state(&second).source_ready());
    press(&mut second, KeyCode::Enter);
    enroll_password(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
}

#[test]
fn ctrl_n_switches_between_the_file_and_the_network_and_keeps_both_entries() {
    let base = temp_dir("net-switch");
    let mut second = app(&base);
    open_restore(&mut second);
    assert!(!restore_state(&second).network);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, "x");
    let file_text = restore_state(&second).source.value().to_owned();
    second.on_key(&ctrl('n'));
    assert!(restore_state(&second).network);
    type_text(&mut second, "192.168.1.5:7447");
    assert!(restore_state(&second).source_ready());
    second.on_key(&ctrl('n'));
    assert!(!restore_state(&second).network);
    assert_eq!(restore_state(&second).source.value(), file_text);
    assert_eq!(restore_state(&second).address.value(), "192.168.1.5:7447");
    let screen = render(&second, 140, 50);
    assert!(screen.contains("over the network") && screen.contains("from a file"));
    let _ = KdfProfile::Fast;
}

#[test]
fn a_record_written_on_the_first_device_reaches_the_second_when_it_checks_in() {
    let (mut first, words, address) = first_device("net-pull-first");
    let base = temp_dir("net-pull-second");
    let mut second = app(&base);
    open_restore(&mut second);
    enter_phrase_and_address(&mut second, &words, &address);
    enroll_password(&mut second);
    assert_eq!(titles_of(&second), ["bank", "wifi"]);

    // The first device gets a new record while the second is locked.
    press(&mut second, KeyCode::Char('L'));
    keep_to_this_device_with(&base, SECOND_PASSWORD);
    press(&mut first, KeyCode::Char('n'));
    type_text(&mut first, "Mail");
    for _ in 0..4 {
        press(&mut first, KeyCode::Tab);
    }
    type_text(&mut first, "S3cure-Pa55!word");
    first.on_key(&ctrl('s'));
    wait(&mut first);
    assert_eq!(titles_of(&first), ["Mail", "bank", "wifi"]);

    // Unlocking the second finds the first at the remembered address and
    // takes the record it lacks, without the address being typed again.
    press(&mut second, KeyCode::Enter);
    unlock(&mut second, SECOND_PASSWORD);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while titles_of(&second).len() < 3 && std::time::Instant::now() < deadline {
        common::settle(&mut second);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(titles_of(&second), ["Mail", "bank", "wifi"]);

    // It was saved: a fresh unlock still has it.
    press(&mut second, KeyCode::Char('L'));
    press(&mut second, KeyCode::Enter);
    unlock(&mut second, SECOND_PASSWORD);
    assert_eq!(titles_of(&second), ["Mail", "bank", "wifi"]);
}
