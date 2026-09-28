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
use tui::app::flows::enroll::{EnrollFactor, EnrollFocus};
use tui::app::flows::restore::RestoreField;
use tui::app::keymap::{Scope, KEYMAP};
use tui::app::screen::Screen;

use common::{app, ctrl, press, temp_dir, type_text, wait, PASSWORD};

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

/// Walk create → ceremony → verify: tick the box and continue.
fn reach_verify(app: &mut tui::App) {
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter); // unticked: focus moves to the checkbox
    press(app, KeyCode::Char(' '));
    press(app, KeyCode::Tab);
    press(app, KeyCode::Enter);
    assert_eq!(create_state(app).step, Step::Verify);
}

#[test]
fn verify_step_skips_with_s() {
    let mut app = app(&temp_dir("keys-verify-skip"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(create_state(&app).step, Step::Enroll);
}

#[test]
fn verify_step_tabs_to_the_skip_button_and_confirms() {
    let mut app = app(&temp_dir("keys-verify-skip-tab"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Tab);
    assert!(create_state(&app).verify.as_ref().is_some_and(|v| v.skip));
    press(&mut app, KeyCode::Enter);
    assert_eq!(create_state(&app).step, Step::Enroll);
}

#[test]
fn enroll_tab_on_cards_cycles_the_factor() {
    let mut app = app(&temp_dir("keys-enroll-cards"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Cards);
    for _ in 0..EnrollFactor::ALL.len() {
        press(&mut app, KeyCode::Tab);
    }
    let enroll = &create_state(&app).enroll;
    assert_eq!(enroll.focus, EnrollFocus::Cards);
    assert_eq!(enroll.factor, EnrollFactor::Password);
}

#[test]
fn enroll_tab_tours_password_repeat_and_wraps_to_cards() {
    let mut app = app(&temp_dir("keys-enroll-tab-tour"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
    press(&mut app, KeyCode::Tab);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Repeat);
    press(&mut app, KeyCode::Tab);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Cards);
    press(&mut app, KeyCode::Tab);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Cards);
    assert_eq!(create_state(&app).enroll.factor, EnrollFactor::Device);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(create_state(&app).enroll.factor, EnrollFactor::Password);
    press(&mut app, KeyCode::Down);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
}

#[test]
fn enroll_arrows_walk_cards_password_repeat_and_stop() {
    let mut app = app(&temp_dir("keys-enroll-arrows"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
    press(&mut app, KeyCode::Down);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Repeat);
    press(&mut app, KeyCode::Down);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Repeat);
    press(&mut app, KeyCode::Up);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
    press(&mut app, KeyCode::Up);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Cards);
    press(&mut app, KeyCode::Up);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Cards);
}

#[test]
fn enroll_enter_moves_password_to_repeat_then_confirms() {
    let mut app = app(&temp_dir("keys-enroll-enter"));
    reach_verify(&mut app);
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Password);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    assert_eq!(create_state(&app).enroll.focus, EnrollFocus::Repeat);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
}
