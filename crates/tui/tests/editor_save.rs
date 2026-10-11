//! Enter saves the record editor; the Save button follows the dirty state.

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
use tui::app::flows::editor::{EditorState, Part, Value};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::App;

use common::{
    add_records, app, make_vault, press, render, temp_dir, titles_of, type_text, unlock, wait,
    PASSWORD,
};

fn unlocked(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn editor(app: &App) -> &EditorState {
    let View::Editor(editor) = &unlocked(app).view else {
        panic!("not in the editor")
    };
    editor
}

fn revision_of(app: &App, title: &str) -> u64 {
    unlocked(app)
        .cache
        .iter()
        .find(|row| &*row.title == title)
        .unwrap()
        .revision
}

#[test]
fn enter_saves_a_dirty_editor() {
    let base = temp_dir("editor-enter-save");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Router");
    assert!(editor(&app).dirty);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
    assert!(!matches!(unlocked(&app).view, View::Editor(_)));
    assert_eq!(titles_of(&app), vec!["Router".to_owned()]);
}

#[test]
fn enter_on_a_clean_editor_writes_no_revision() {
    let base = temp_dir("editor-enter-clean");
    make_vault(&base);
    add_records(&base, &["Mail"]);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    let before = revision_of(&app, "Mail");
    press(&mut app, KeyCode::Char('E'));
    assert!(!editor(&app).dirty);
    press(&mut app, KeyCode::Enter);
    assert!(!matches!(unlocked(&app).view, View::Editor(_)));
    assert_eq!(revision_of(&app, "Mail"), before);
    assert_eq!(titles_of(&app), vec!["Mail".to_owned()]);
}

#[test]
fn enter_on_a_toggle_toggles_instead_of_saving() {
    let base = temp_dir("editor-enter-toggle");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('n'));
    let stops = editor(&app).stops().len();
    let mut on_toggle = false;
    for _ in 0..stops {
        let e = editor(&app);
        on_toggle = matches!(
            e.focused(),
            Some((i, Part::Value)) if matches!(e.fields[i].value, Value::Toggle(_))
        );
        if on_toggle {
            break;
        }
        press(&mut app, KeyCode::Tab);
    }
    assert!(on_toggle, "a new record has a toggle field");
    press(&mut app, KeyCode::Enter);
    let e = editor(&app);
    assert!(e.dirty, "the toggle flipped");
    assert!(e
        .fields
        .iter()
        .any(|f| matches!(f.value, Value::Toggle(true))));
}

#[test]
fn the_save_button_is_primary_only_while_dirty() {
    let base = temp_dir("editor-save-button");
    make_vault(&base);
    add_records(&base, &["Mail"]);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('E'));
    let clean = render(&app, 100, 30);
    assert!(clean.contains("Save →"));
    assert!(!clean.contains('┏'), "clean: muted button\n{clean}");
    type_text(&mut app, "x");
    let dirty = render(&app, 100, 30);
    assert!(dirty.contains("Save →"));
    assert!(dirty.contains('┏'), "dirty: primary button\n{dirty}");
}
