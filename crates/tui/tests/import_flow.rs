//! Restore or import: the chooser, a Bitwarden export read and reviewed,
//! then a new vault created with the included records.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::flows::create::Step;
use tui::app::flows::import::ImportStep;
use tui::app::screen::Screen;
use tui::App;

use common::{app, pass_verify, press, render, temp_dir, type_text, unlock, wait, PASSWORD};

fn fixture(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../import/tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn step(app: &App) -> ImportStep {
    let Screen::Import(state) = &app.screen else {
        panic!("not import: {}", app.screen.name())
    };
    state.step
}

/// Welcome → "Restore or import" → Bitwarden → file → preview.
fn to_preview(app: &mut App, file: &str) {
    assert_eq!(app.screen.name(), "welcome");
    press(app, KeyCode::Right);
    assert!(render(app, 100, 30).contains("Restore or import"));
    press(app, KeyCode::Enter);
    assert_eq!(step(app), ImportStep::Source);
    let chooser = render(app, 100, 30);
    for option in [
        "ZebraPass recovery phrase",
        "Bitwarden",
        "KeePass",
        "Enpass",
        "CSV",
    ] {
        assert!(chooser.contains(option), "chooser lacks {option}");
    }
    press(app, KeyCode::Down);
    press(app, KeyCode::Enter);
    assert_eq!(step(app), ImportStep::File);
    type_text(app, &fixture(file));
    assert!(render(app, 100, 30).contains("Bitwarden export"));
    press(app, KeyCode::Enter);
    wait(app);
}

#[test]
fn bitwarden_export_becomes_a_new_vault() {
    let base = temp_dir("import");
    let mut app = app(&base);
    to_preview(&mut app, "bitwarden.json");
    assert_eq!(step(&app), ImportStep::Preview);
    let screen = render(&app, 120, 40);
    assert!(screen.contains("5 items"));
    assert!(screen.contains("GitHub"));
    assert!(screen.contains("left out"));
    for secret in [
        "fixture-pw-github",
        "rc-secret-777",
        "4111111111111111",
        "000-00-0000",
    ] {
        assert!(!screen.contains(secret), "the preview shows a secret");
    }

    // Exclude the first item, then create the vault with the other four.
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Enter);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(state.records.len(), 4);
    assert!(render(&app, 120, 40).contains("4 records from Bitwarden"));

    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);
    pass_verify(&mut app, false);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(state.step, Step::Enroll);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    let mut titles: Vec<&str> = state.cache.iter().map(|row| &*row.title).collect();
    titles.sort_unstable();
    assert_eq!(titles, ["Me", "Server key", "Visa", "Wifi"]);

    // The records survive a lock and a password unlock from disk.
    press(&mut app, KeyCode::Char('L'));
    press(&mut app, KeyCode::Enter);
    unlock(&mut app, PASSWORD);
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    assert_eq!(state.cache.len(), 4);
}

#[test]
fn phrase_choice_opens_the_phrase_restore() {
    let base = temp_dir("import-phrase");
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
}

#[test]
fn encrypted_export_is_refused_on_the_file_step() {
    let base = temp_dir("import-encrypted");
    let mut app = app(&base);
    to_preview(&mut app, "bitwarden_encrypted.json");
    assert_eq!(step(&app), ImportStep::File);
    assert!(render(&app, 120, 40).contains("password-protected"));
}

#[test]
fn locking_during_review_drops_the_parsed_export() {
    let base = temp_dir("import-lock");
    let mut app = app(&base);
    to_preview(&mut app, "bitwarden.json");
    app.on_key(&common::ctrl('z'));
    assert_eq!(app.screen.name(), "locked");
    assert!(!render(&app, 120, 40).contains("GitHub"));
}
