//! Search is ready on unlock, and Enter opens the record chosen with arrows.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap and panic; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::flows::home::Pane;

use common::{
    add_records, app, make_vault, press, temp_dir, type_text, unlocked_state, wait, PASSWORD,
};

#[test]
fn unlock_starts_search_and_enter_opens_the_selected_match() {
    let base = temp_dir("home-search");
    make_vault(&base);
    add_records(&base, &["bearbry-EKB", "EKB backup", "other"]);
    let mut app = app(&base);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);

    let state = unlocked_state(&app);
    assert!(state.home.searching);
    assert_eq!(state.home.pane, Pane::List);

    type_text(&mut app, "ekb");
    let state = unlocked_state(&app);
    assert_eq!(state.home.query.value(), "ekb");
    assert_eq!(state.visible().len(), 2);
    let first = state.selected().unwrap().id;

    press(&mut app, KeyCode::Down);
    let state = unlocked_state(&app);
    let expected = state.selected().unwrap().id;
    assert_ne!(expected, first);
    assert_eq!(state.home.detail.as_ref().unwrap().id, expected);

    press(&mut app, KeyCode::Up);
    assert_eq!(unlocked_state(&app).selected().unwrap().id, first);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);

    let state = unlocked_state(&app);
    assert!(!state.home.searching);
    assert_eq!(state.home.pane, Pane::Detail);
    assert_eq!(state.home.query.value(), "ekb");
    assert_eq!(state.selected().unwrap().id, expected);
    assert_eq!(state.home.detail.as_ref().unwrap().id, expected);
}
