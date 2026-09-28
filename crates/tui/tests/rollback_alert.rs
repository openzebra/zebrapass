//! An older vault file (rollback) or a same-generation fork (conflict) opens
//! the security alert, and no key sequence gets past it to the vault.

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
use record::{Document, TAG_TITLE};
use session::{BodyAlg, UnlockCreds, VaultFile};
use tui::app::ctx::Task;
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::ops::Op;

use common::{app, make_vault, press, render, temp_dir, unlock, wait, PASSWORD};

fn titled(title: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc
}

fn write_one(base: &std::path::Path, title: &str) {
    let mut app = app(base);
    unlock(&mut app, PASSWORD);
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!("not unlocked")
    };
    state.run(
        Op::Write {
            id: None,
            doc: Box::new(titled(title)),
        },
        Task::Save,
        &mut app.ctx,
    );
    wait(&mut app);
}

fn assert_alert_holds(app: &mut tui::App) {
    let screen = render(app, 100, 30);
    assert!(screen.contains("SECURITY ALERT"), "{screen}");
    assert!(
        !screen.contains("Open anyway") && !screen.contains("open anyway"),
        "{screen}"
    );
    for code in [
        KeyCode::Enter,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Esc,
        KeyCode::Tab,
        KeyCode::Char('o'),
        KeyCode::Char('l'),
    ] {
        press(app, code);
        assert_ne!(app.screen.name(), "unlocked", "a key got past the alert");
    }
}

#[test]
fn older_file_opens_the_alert_without_a_bypass() {
    let base = temp_dir("rollback");
    make_vault(&base, BodyAlg::Aegis256);
    let path = discover(&base).first().unwrap().paths.vault_file.clone();
    let old = std::fs::read(&path).unwrap();
    write_one(&base, "newer");
    std::fs::write(&path, old).unwrap();

    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "alert");
    let screen = render(&app, 100, 30);
    assert!(
        screen.contains("OLDER") && screen.contains("last seen") && screen.contains("on disk"),
        "{screen}"
    );
    assert_alert_holds(&mut app);
}

#[test]
fn same_generation_fork_opens_the_alert() {
    let base = temp_dir("conflict");
    make_vault(&base, BodyAlg::Aegis256);
    let path = discover(&base).first().unwrap().paths.vault_file.clone();
    let old = VaultFile::new(std::fs::read(&path).unwrap());
    write_one(&base, "accepted");
    // Fork: the old file plus a different record reaches the same generation.
    let mut forked = old;
    let mut session = session::unlock(
        &forked,
        &UnlockCreds::default().with_human(PASSWORD.as_bytes()),
        None,
    )
    .unwrap();
    session::write_record(&mut session, &mut forked, None, &titled("forged")).unwrap();
    std::fs::write(&path, forked.as_bytes()).unwrap();

    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "alert");
    assert!(render(&app, 100, 30).contains("SAME generation"));
    assert_alert_holds(&mut app);
}
