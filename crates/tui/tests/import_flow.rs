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
use keepass::{Database, DatabaseKey};
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
    let [me, key, visa, wifi] = titles[..] else {
        panic!("expected four records: {titles:?}")
    };
    assert_eq!((me, visa, wifi), ("Me", "Visa", "Wifi"));
    assert!(key.ends_with(" key"), "{key}");

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

const KDBX_PASSWORD: &str = "kdbx-master-pass";

/// A small `.kdbx` written under `base`; returns its path.
fn kdbx_file(base: &std::path::Path) -> String {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut work = root.add_group();
        work.name = "Work".into();
        let mut entry = work.add_entry();
        entry.set_unprotected("Title", "Router");
        entry.set_unprotected("UserName", "admin");
        entry.set_protected("Password", "kdbx-pw-router");
    }
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(KDBX_PASSWORD))
        .unwrap();
    let path = base.join("vault.kdbx");
    std::fs::write(&path, bytes).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn keepass_database_opens_with_its_password() {
    let base = temp_dir("import-kdbx");
    let file = kdbx_file(&base);
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert!(render(&app, 120, 40).contains("master password and/or key file"));
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, &file);
    assert!(render(&app, 100, 30).contains("KeePass / KeePassXC export"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(step(&app), ImportStep::Unlock);

    type_text(&mut app, "wrong-password");
    assert!(!render(&app, 100, 30).contains("wrong-password"), "masked");
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(step(&app), ImportStep::Unlock);
    assert!(render(&app, 120, 40).contains("wrong password or key file"));

    type_text(&mut app, KDBX_PASSWORD);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(step(&app), ImportStep::Preview);
    let screen = render(&app, 120, 40);
    assert!(screen.contains("Router"));
    assert!(screen.contains("Work"));
    assert!(!screen.contains("kdbx-pw-router"));
    press(&mut app, KeyCode::Enter);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(state.records.len(), 1);
    assert_eq!(state.imported, Some((1, "KeePass / KeePassXC")));
}

/// Chooser row → file → preview for a plain-text export.
fn preview_of(downs: usize, file: &str, label: &str) -> App {
    let base = temp_dir("import-source");
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    for _ in 0..downs {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, &fixture(file));
    assert!(render(&app, 100, 30).contains(&format!("{label} export")));
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(step(&app), ImportStep::Preview);
    app
}

#[test]
fn keepass_xml_and_enpass_reach_the_review() {
    let xml = render(&preview_of(3, "keepass.xml", "KeePass XML"), 120, 40);
    assert!(xml.contains("GitHub") && xml.contains("Wifi"));
    assert!(!xml.contains("xml-pw"));
    let enpass = render(&preview_of(4, "enpass.json", "Enpass"), 120, 40);
    assert!(enpass.contains("GitHub") && enpass.contains("Visa"));
    assert!(!enpass.contains("enpass-pw-github"));
}

fn open_view_step(app: &App) -> Option<ImportStep> {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    match &state.view {
        tui::app::flows::unlocked::View::Import(import) => Some(import.step),
        _ => None,
    }
}

/// Settings → Import records: the only way into the in-vault wizard.
fn open_import_from_settings(app: &mut App) {
    type_text(app, ",/import");
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
}

/// Settings → Bitwarden → file → review → Enter, inside the open vault.
fn import_into_open_vault(app: &mut App) {
    open_import_from_settings(app);
    assert_eq!(open_view_step(app), Some(ImportStep::Source));
    let chooser = render(app, 120, 40);
    assert!(chooser.contains("Import into this vault"));
    assert!(!chooser.contains("ZebraPass recovery phrase"));
    press(app, KeyCode::Enter);
    type_text(app, &fixture("bitwarden.json"));
    press(app, KeyCode::Enter);
    wait(app);
    assert_eq!(open_view_step(app), Some(ImportStep::Preview));
    assert!(render(app, 120, 40).contains("Review · Bitwarden"));
    press(app, KeyCode::Enter);
    wait(app);
    assert_eq!(open_view_step(app), None, "back on home");
}

#[test]
fn importing_into_an_open_vault_skips_duplicates() {
    let base = temp_dir("import-open");
    common::make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    import_into_open_vault(&mut app);
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    assert_eq!(state.cache.len(), 5);
    assert!(render(&app, 140, 40).contains("Imported 5 records"));

    import_into_open_vault(&mut app);
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    assert_eq!(state.cache.len(), 5, "the second import adds nothing");
    assert!(render(&app, 140, 40).contains("5 already here"));
}

#[test]
fn esc_leaves_the_open_vault_import() {
    let base = temp_dir("import-open-esc");
    common::make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    open_import_from_settings(&mut app);
    assert_eq!(open_view_step(&app), Some(ImportStep::Source));
    press(&mut app, KeyCode::Esc);
    assert_eq!(open_view_step(&app), None);
    assert_eq!(app.screen.name(), "unlocked");
}

#[test]
fn home_has_no_import_key_and_a_slim_hint_bar() {
    let base = temp_dir("import-no-home-key");
    common::make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    let home = render(&app, 200, 40);
    for gone in [
        "i import",
        "copy pw",
        "Enter open",
        "Space reveal",
        "move",
        "u user",
        "Tab pane",
    ] {
        assert!(!home.contains(gone), "hint bar still shows {gone}: {home}");
    }
    assert!(home.contains(", settings"), "{home}");
    press(&mut app, KeyCode::Char('i'));
    assert_eq!(open_view_step(&app), None, "i no longer opens the wizard");
}

/// Welcome → import → CSV → `file` → Enter.
fn csv_import(file: &str) -> App {
    let base = temp_dir("import-csv");
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, &fixture(file));
    press(&mut app, KeyCode::Enter);
    app
}

#[test]
fn unknown_csv_columns_are_mapped_before_reading() {
    let mut app = csv_import("generic.csv");
    assert_eq!(step(&app), ImportStep::Mapping);
    let screen = render(&app, 120, 40);
    assert!(screen.contains("CSV columns") && screen.contains("Recovery PIN"));
    assert!(screen.contains("dave"), "a username sample is shown");
    assert!(
        !screen.contains("pw4") && !screen.contains("9999"),
        "secrets stay hidden"
    );

    // Account: Custom field → Custom secret → Bitwarden fields → Skip → Title.
    for _ in 0..4 {
        press(&mut app, KeyCode::Right);
    }
    assert!(
        render(&app, 120, 40).contains("Bank, Inc."),
        "a title sample is shown"
    );
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(step(&app), ImportStep::Preview);
    assert!(render(&app, 120, 40).contains("Bank, Inc."));

    press(&mut app, KeyCode::Char('m'));
    assert_eq!(
        step(&app),
        ImportStep::Mapping,
        "m goes back to the columns"
    );
    press(&mut app, KeyCode::Esc);
    assert_eq!(step(&app), ImportStep::File);
}

#[test]
fn known_csv_exports_skip_the_column_step() {
    let mut app = csv_import("chrome.csv");
    wait(&mut app);
    assert_eq!(step(&app), ImportStep::Preview);
    assert!(render(&app, 120, 40).contains("Chrome export"));
}
