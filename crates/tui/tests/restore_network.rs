//! Restore with the phrase alone: the new device types the phrase and no
//! vault file, starts an empty vault of its own, and the account's vault
//! arrives over the peer-to-peer transport when the first device is found.
//! Driven with real keystrokes against two apps on one machine.

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

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use tui::app::flows::restore::{RestoreField, RestoreState, RestoreStep};
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::App;

use common::{
    add_records, announcing_device, app, beacon, ctrl, fetch_only_with, free_udp_port,
    keep_to_this_device, make_vault, open_restore, press, render, restore_empty, temp_dir, tick,
    titles_of, type_phrase, type_text, unlock, wait, wait_adopted, PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn restore_state(app: &App) -> &RestoreState {
    let Screen::Restore(state) = &app.screen else {
        panic!("not restore: {}", app.screen.name())
    };
    state
}

fn enroll_password(app: &mut App, password: &str) {
    type_text(app, password);
    press(app, KeyCode::Tab);
    type_text(app, password);
    press(app, KeyCode::Enter);
    wait(app);
}

/// Type `text` into the file field, replacing what was there.
fn set_file(app: &mut App, text: &str) {
    while restore_state(app).field != RestoreField::Phrase {
        press(app, KeyCode::BackTab);
    }
    press(app, KeyCode::Tab);
    assert_eq!(restore_state(app).field, RestoreField::Source);
    for _ in 0..restore_state(app).source.value().len() {
        press(app, KeyCode::Backspace);
    }
    type_text(app, text);
}

#[test]
fn the_share_screen_shows_the_address_to_type_on_a_new_device() {
    let base = temp_dir("net-show");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut first = app(&base);
    unlock(&mut first, PASSWORD);
    let Screen::Unlocked(state) = &first.screen else {
        panic!("not unlocked")
    };
    let address = state
        .p2p
        .as_ref()
        .expect("the node runs")
        .service
        .local_addr()
        .expect("the node listens")
        .to_string();
    press(&mut first, KeyCode::Char('S'));
    let screen = render(&first, 140, 50);
    assert!(screen.contains("restore from"), "{screen}");
    assert!(screen.contains(&address), "{screen}");
}

#[test]
fn the_phrase_alone_brings_the_vault_and_a_later_record_arrives_at_the_next_check_in() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (mut first, words, _) = announcing_device(
        "net-first",
        beacon(first_bind, second_bind),
        &["wifi", "bank"],
    );
    let base = temp_dir("net-second");
    let mut second = restore_empty(&base, &words, PASSWORD, beacon(second_bind, first_bind));
    wait_adopted(&mut second, Duration::from_secs(60));
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
    assert_eq!(titles_of(&second), titles_of(&first));

    // The second device is a vault of its own now, with the first device
    // remembered and a rollback cursor at the adopted file.
    let paths = discover(&base).first().unwrap().paths.clone();
    assert!(paths.sync_identity().is_file());
    assert!(paths.peers_store().is_file(), "the address is remembered");
    let Screen::Unlocked(state) = &second.screen else {
        panic!("not unlocked")
    };
    let vault = state.vault.as_ref().unwrap();
    assert_eq!(
        vault.meta.seen.unwrap().generation,
        vault.session.generation()
    );

    // The first device gets a new record while the second is locked.
    press(&mut second, KeyCode::Char('L'));
    fetch_only_with(&base, PASSWORD);
    press(&mut first, KeyCode::Char('n'));
    type_text(&mut first, "Mail");
    for _ in 0..4 {
        press(&mut first, KeyCode::Tab);
    }
    type_text(&mut first, "S3cure-Pa55!word");
    first.on_key(&ctrl('s'));
    wait(&mut first);
    assert_eq!(titles_of(&first), ["Mail", "bank", "wifi"]);

    // Unlocking the second finds the first at the remembered address.
    press(&mut second, KeyCode::Enter);
    unlock(&mut second, PASSWORD);
    let deadline = Instant::now() + Duration::from_secs(30);
    while titles_of(&second).len() < 3 && Instant::now() < deadline {
        tick(&mut second, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(titles_of(&second), ["Mail", "bank", "wifi"]);
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
    set_file(&mut second, &file.to_string_lossy());
    assert!(!restore_state(&second).file_problem());
    press(&mut second, KeyCode::Enter);
    enroll_password(&mut second, SECOND_PASSWORD);
    assert_eq!(second.screen.name(), "unlocked");
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
}

#[test]
fn an_empty_file_field_is_a_valid_state_and_says_it_syncs_over_the_network() {
    let base = temp_dir("net-empty-file");
    let mut second = app(&base);
    open_restore(&mut second);
    assert_eq!(restore_state(&second).source.value(), "");
    assert!(!restore_state(&second).file_problem());
    let screen = render(&second, 140, 50);
    assert!(screen.contains("Vault file (optional)"), "{screen}");
    assert!(screen.contains("empty → sync over the network"), "{screen}");
    assert!(!screen.contains("no vault file at this path"), "{screen}");
    assert!(!screen.contains("Device address"), "{screen}");
}

#[test]
fn an_empty_file_goes_on_to_the_factor_step_without_a_complaint() {
    let words = make_vault(&temp_dir("net-no-file-other"));
    let base = temp_dir("net-no-file");
    let mut second = app(&base);
    open_restore(&mut second);
    type_phrase(&mut second, &words);
    press(&mut second, KeyCode::Enter);
    assert_eq!(restore_state(&second).step, RestoreStep::Enroll);
    assert!(restore_state(&second).error.is_none());
    assert!(
        discover(&base).is_empty(),
        "nothing is written before the factor"
    );
}

#[test]
fn a_wrong_non_empty_file_path_is_refused_on_the_screen() {
    let words = make_vault(&temp_dir("net-wrong-path-other"));
    let base = temp_dir("net-wrong-path-second");
    let mut second = app(&base);
    open_restore(&mut second);
    type_phrase(&mut second, &words);
    set_file(&mut second, "/nonexistent/vault.zp");
    assert!(restore_state(&second).file_problem());
    assert!(render(&second, 140, 50).contains("no vault file at this path"));
    press(&mut second, KeyCode::Enter);
    assert_eq!(second.screen.name(), "restore");
    assert_eq!(restore_state(&second).step, RestoreStep::Phrase);
    assert_eq!(
        restore_state(&second).error,
        Some("No ZebraPass vault file at that path.")
    );
}
