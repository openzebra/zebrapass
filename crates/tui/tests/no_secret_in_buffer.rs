//! A masked secret never reaches the terminal buffer: not on the unlock
//! screen, not in the editor, not in the detail pane, not in the restore
//! grid. A reveal shows it; the end of a reveal removes it and forces a full
//! redraw. `Debug` of the whole app never prints it either.

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

use common::{
    app, ctrl, make_vault, press, render_all, temp_dir, tick, type_text, unlock, wait, PASSWORD,
};

const SECRET: &str = "Zq9-hunter2-sekret";

fn assert_absent(screens: &[String], secret: &str, context: &str) {
    for screen in screens {
        assert!(
            !screen.contains(secret),
            "{context}: secret visible:\n{screen}"
        );
        for piece in secret.as_bytes().windows(6) {
            let piece = std::str::from_utf8(piece).unwrap();
            assert!(
                !screen.contains(piece),
                "{context}: fragment {piece:?} visible:\n{screen}"
            );
        }
    }
}

#[test]
fn unlock_password_is_never_rendered_or_debug_printed() {
    let base = temp_dir("mask-unlock");
    make_vault(&base);
    let mut app = app(&base);
    type_text(&mut app, SECRET);
    let screens = render_all(&app);
    assert_absent(&screens, SECRET, "unlock");
    assert!(
        screens[0].contains('▚'),
        "the typed password shows as stripes"
    );
    assert!(
        !format!("{app:?}").contains("hunter2"),
        "Debug leaks the password"
    );
}

#[test]
fn editor_detail_and_reveal_lifecycle() {
    let base = temp_dir("mask-editor");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Mail");
    for _ in 0..4 {
        press(&mut app, KeyCode::Tab);
    }
    type_text(&mut app, SECRET);
    assert_absent(&render_all(&app), SECRET, "editor");
    app.on_key(&ctrl('r'));
    assert!(
        render_all(&app)[0].contains(SECRET),
        "Ctrl-R reveals the focused secret"
    );
    app.on_key(&ctrl('r'));
    assert!(
        app.take_full_redraw(),
        "hiding a secret forces a full redraw"
    );
    assert_absent(&render_all(&app), SECRET, "editor after hide");
    assert!(
        !format!("{app:?}").contains("hunter2"),
        "Debug leaks the editor secret"
    );

    app.on_key(&ctrl('s'));
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
    let _ = app.take_full_redraw();
    assert_absent(&render_all(&app), SECRET, "detail");
    press(&mut app, KeyCode::Char(' '));
    assert!(
        render_all(&app)[2].contains(SECRET),
        "Space reveals the password"
    );
    tick(&mut app, Duration::from_secs(6));
    assert!(app.take_full_redraw(), "the auto-hide forces a full redraw");
    assert_absent(&render_all(&app), SECRET, "detail after auto-hide");
}

#[test]
fn restore_grid_masks_finished_words() {
    let base = temp_dir("mask-restore");
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
    type_text(&mut app, "zebra");
    press(&mut app, KeyCode::Char(' '));
    type_text(&mut app, "wrist");
    press(&mut app, KeyCode::Char(' '));
    for screen in render_all(&app) {
        assert!(
            !screen.contains("zebra") && !screen.contains("wrist"),
            "finished words must be masked:\n{screen}"
        );
    }
    type_text(&mut app, "abo");
    let screen = &render_all(&app)[0];
    assert!(
        screen.contains("03 abo") && screen.contains("about"),
        "the word being typed shows with suggestions:\n{screen}"
    );
    type_text(&mut app, "u");
    let screen = &render_all(&app)[0];
    assert!(
        screen.contains("3 / 24") && !screen.contains("about"),
        "a unique prefix commits and masks:\n{screen}"
    );
}
