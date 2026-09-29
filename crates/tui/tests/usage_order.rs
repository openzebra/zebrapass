//! Copying from a record moves it to the top of the list, keeps it
//! selected, and the order survives a lock and unlock.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE};
use tui::app::ctx::Task;
use tui::app::flows::unlocked::Unlocked;
use tui::app::screen::Screen;
use tui::vault::ops::Op;
use tui::App;

use common::{app, make_vault, press, temp_dir, unlock, wait, PASSWORD};

fn unlocked(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn titles(app: &App) -> Vec<String> {
    let state = unlocked(app);
    state
        .visible()
        .iter()
        .map(|index| state.cache[*index].display_title().to_owned())
        .collect()
}

fn selected_title(app: &App) -> String {
    unlocked(app).selected().unwrap().display_title().to_owned()
}

fn write(app: &mut App, title: &str) {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc.set_data(TAG_PASSWORD, ValueType::Secret, b"pw");
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
    wait(app);
}

#[test]
fn copied_record_rises_stays_selected_and_persists() {
    let base = temp_dir("usage-order");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    for title in ["alpha", "bravo", "charlie"] {
        write(&mut app, title);
    }
    assert_eq!(titles(&app), ["alpha", "bravo", "charlie"]);

    press(&mut app, KeyCode::End);
    assert_eq!(selected_title(&app), "charlie");
    let _ = app.take_outbox();
    press(&mut app, KeyCode::Char('c'));
    assert_eq!(app.take_outbox().len(), 1, "password copied");
    assert_eq!(titles(&app), ["charlie", "alpha", "bravo"]);
    assert_eq!(unlocked(&app).home.selected, 0);
    assert_eq!(selected_title(&app), "charlie", "selection follows");

    press(&mut app, KeyCode::Char('L'));
    assert!(matches!(app.screen, Screen::Locked(_)));
    press(&mut app, KeyCode::Enter);
    unlock(&mut app, PASSWORD);
    assert_eq!(titles(&app), ["charlie", "alpha", "bravo"]);
}
