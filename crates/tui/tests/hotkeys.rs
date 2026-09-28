//! Keys that used to do nothing: arrows on the setup step, Tab and Space on
//! the phrase step, and hiding the typed restore word (Ctrl-E: legacy
//! terminals send Ctrl-H as Backspace, so it cannot be a binding).

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::flows::ceremony::CeremonyFocus;
use tui::app::flows::create::{SetupField, Step, DEFAULT_PROFILE};
use tui::app::flows::restore::RestoreField;
use tui::app::keymap::{Scope, KEYMAP};
use tui::app::screen::Screen;

use common::{app, ctrl, press, temp_dir, type_text};

fn create_state(app: &tui::App) -> &tui::app::flows::create::CreateState {
    let Screen::Create(state) = &app.screen else {
        panic!("not create: {}", app.screen.name())
    };
    state
}

#[test]
fn setup_arrows_pick_the_unlock_time_from_any_field() {
    let mut app = app(&temp_dir("keys-setup"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(create_state(&app).field, SetupField::Name);
    press(&mut app, KeyCode::Down);
    let state = create_state(&app);
    assert_eq!(state.field, SetupField::Profile);
    assert_eq!(state.profile, DEFAULT_PROFILE + 1);
}

#[test]
fn phrase_step_tabs_to_the_checkbox_and_space_ticks_it() {
    let mut app = app(&temp_dir("keys-ceremony"));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(create_state(&app).step, Step::Ceremony);

    press(&mut app, KeyCode::Enter);
    let state = create_state(&app);
    assert_eq!(state.step, Step::Ceremony, "cannot continue unticked");
    assert_eq!(state.ceremony.focus, CeremonyFocus::Written);

    press(&mut app, KeyCode::Char(' '));
    assert!(create_state(&app).ceremony.written);
    press(&mut app, KeyCode::Tab);
    assert_eq!(create_state(&app).ceremony.focus, CeremonyFocus::Continue);
    press(&mut app, KeyCode::Tab);
    assert_eq!(create_state(&app).ceremony.focus, CeremonyFocus::Grid);
    press(&mut app, KeyCode::Enter);
    assert_eq!(create_state(&app).step, Step::Verify);
}

#[test]
fn restore_hides_the_typed_word_with_ctrl_e() {
    let mut app = app(&temp_dir("keys-restore"));
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, "zo");
    app.on_key(&ctrl('e'));
    let Screen::Restore(state) = &app.screen else {
        panic!("not restore: {}", app.screen.name())
    };
    assert!(state.hide_current);
    assert!(
        !KEYMAP
            .iter()
            .any(|binding| binding.key.ctrl && binding.key.code == KeyCode::Char('h')),
        "Ctrl-H arrives as Backspace in legacy terminals"
    );
    assert!(KEYMAP
        .iter()
        .any(|binding| binding.scope == Scope::Ceremony && binding.key.code == KeyCode::Tab));
}

#[test]
fn restore_tab_leaves_a_finished_phrase_and_shift_tab_returns() {
    let mut app = app(&temp_dir("keys-restore-tab"));
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    let field = |app: &tui::App| {
        let Screen::Restore(state) = &app.screen else {
            panic!("not restore: {}", app.screen.name())
        };
        state.field
    };
    type_text(&mut app, "ab");
    press(&mut app, KeyCode::Tab);
    assert_eq!(field(&app), RestoreField::Phrase, "Tab completes a prefix");
    press(&mut app, KeyCode::Tab);
    assert_eq!(
        field(&app),
        RestoreField::Source,
        "nothing to complete: next field"
    );
    press(&mut app, KeyCode::Tab);
    assert_eq!(field(&app), RestoreField::Name);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(field(&app), RestoreField::Source);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(field(&app), RestoreField::Phrase);
}
