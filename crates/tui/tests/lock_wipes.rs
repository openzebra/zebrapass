//! Locking drops the session and caches, and clears an armed clipboard:
//! on idle, on `L`, on focus loss, and on quit.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::Duration;

use crossterm::event::KeyCode;
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE};
use tui::app::ctx::Task;
use tui::app::screen::Screen;
use tui::cli::{Config, Flags};
use tui::vault::ops::Op;
use tui::App;

use common::{
    app_with, config, make_vault, press, render, temp_dir, tick, unlock, wait, CAPS, PASSWORD,
};

const CLEAR: &[u8] = b"\x1b]52;c;\x07";
const STORED: &[u8] = b"Stored-Pa55word!";

fn unlocked_with_record(config: &Config, base: &std::path::Path) -> App {
    let mut app = app_with(config, base, CAPS);
    unlock(&mut app, PASSWORD);
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "Bank");
    doc.set_data(TAG_PASSWORD, ValueType::Secret, STORED);
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!("not unlocked")
    };
    state.run(
        Op::Write {
            id: None,
            doc: Box::new(doc),
        },
        Task::Save,
        &mut app.ctx,
    );
    wait(&mut app);
    app
}

fn copy_password(app: &mut App) {
    press(app, KeyCode::Char('c'));
    let out = app.take_outbox();
    assert_eq!(out.len(), 1);
    assert!(
        out[0].starts_with(b"\x1b]52;c;") && out[0].len() > CLEAR.len(),
        "a copy writes OSC 52"
    );
    assert!(
        !out[0].windows(STORED.len()).any(|window| window == STORED),
        "the payload is base64, not raw"
    );
}

#[test]
fn idle_lock_drops_the_session_and_clears_the_clipboard() {
    let base = temp_dir("lock-idle");
    make_vault(&base);
    let config = Config {
        lock_after: Duration::from_secs(30),
        ..config(&base)
    };
    let mut app = unlocked_with_record(&config, &base);
    copy_password(&mut app);
    tick(&mut app, Duration::from_secs(31));
    assert!(matches!(app.screen, Screen::Locked(_)), "idle must lock");
    let out = app.take_outbox();
    assert!(
        out.iter().any(|sequence| sequence.as_slice() == CLEAR),
        "lock clears the clipboard"
    );
    assert!(render(&app, 100, 30).contains("keys wiped from memory"));
    assert!(
        !format!("{app:?}").contains("Bank"),
        "no record data survives the lock"
    );
    // Any key returns to unlock; the vault opens again.
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(app.screen.name(), "unlock");
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "unlocked");
}

#[test]
fn manual_focus_and_quit_locks() {
    let base = temp_dir("lock-manual");
    make_vault(&base);
    let focus = Config {
        flags: Flags::default().with(Flags::FOCUS_LOCK, true),
        ..config(&base)
    };
    let mut app = unlocked_with_record(&focus, &base);
    copy_password(&mut app);
    press(&mut app, KeyCode::Char('L'));
    assert!(matches!(app.screen, Screen::Locked(_)));
    assert!(app
        .take_outbox()
        .iter()
        .any(|sequence| sequence.as_slice() == CLEAR));

    press(&mut app, KeyCode::Enter);
    unlock(&mut app, PASSWORD);
    app.on_focus_lost();
    assert!(
        matches!(app.screen, Screen::Locked(_)),
        "focus loss locks when enabled"
    );

    press(&mut app, KeyCode::Enter);
    unlock(&mut app, PASSWORD);
    copy_password(&mut app);
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());
    assert!(matches!(app.screen, Screen::Locked(_)), "quit locks first");
    assert!(
        app.take_outbox()
            .iter()
            .any(|sequence| sequence.as_slice() == CLEAR),
        "quit clears the clipboard"
    );
}

#[test]
fn clipboard_clears_on_its_own_timer() {
    let base = temp_dir("lock-clip");
    make_vault(&base);
    let mut app = unlocked_with_record(&config(&base), &base);
    copy_password(&mut app);
    tick(&mut app, Duration::from_secs(21));
    assert_eq!(app.screen.name(), "unlocked");
    assert!(app
        .take_outbox()
        .iter()
        .any(|sequence| sequence.as_slice() == CLEAR));
}
