//! Lock-screen navigation, storage switching, and action controls.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::flows::unlock::{Mode, UnlockFocus, UnlockState};
use tui::app::keymap::{hints, label, Scope};
use tui::app::screen::Screen;
use tui::App;

use common::{app, ctrl, make_vault, press, render, temp_dir, type_text, wait, PASSWORD};

fn unlock(app: &App) -> &UnlockState {
    let Screen::Unlock(state) = &app.screen else {
        panic!("not unlock: {}", app.screen.name())
    };
    state
}

fn assert_focus(app: &App, expected: UnlockFocus) {
    assert_eq!(unlock(app).focus, expected);
}

#[test]
fn bottom_bar_and_action_buttons_match_the_lock_screen() {
    let base = temp_dir("unlock-buttons");
    make_vault(&base);
    let app = app(&base);
    let shown: Vec<(String, &str)> = hints(Scope::Unlock)
        .map(|binding| (label(binding.key, false).into_owned(), binding.hint))
        .collect();
    assert_eq!(
        shown,
        [
            (String::from("Ctrl-O"), "reveal"),
            (String::from("Esc"), "clear"),
            (String::from("Ctrl-Q"), "quit")
        ]
    );
    let screen = render(&app, 100, 30);
    for landmark in [
        "ZEBRAPASS",
        "Unlock your vault",
        "quantum-safe",
        "Storage 1/1",
        "Password",
        "Enter password",
        "Unlock",
        "New",
        "Ctrl-O reveal",
        "Esc clear",
        "Ctrl-Q quit",
    ] {
        assert!(screen.contains(landmark), "missing {landmark:?}:\n{screen}");
    }
    for removed in [
        "Recovery phrase",
        "Optional passphrase",
        "Show password",
        "New storage",
        "Restore or import",
    ] {
        assert!(
            !screen.contains(removed),
            "still shows {removed:?}:\n{screen}"
        );
    }
}

#[test]
fn tab_and_shift_tab_tour_every_control() {
    let base = temp_dir("unlock-tab-tour");
    make_vault(&base);
    let mut app = app(&base);
    assert_focus(&app, UnlockFocus::Input);
    for expected in [
        UnlockFocus::Unlock,
        UnlockFocus::New,
        UnlockFocus::Storage,
        UnlockFocus::Factor,
        UnlockFocus::Input,
    ] {
        press(&mut app, KeyCode::Tab);
        assert_focus(&app, expected);
    }
    press(&mut app, KeyCode::BackTab);
    assert_focus(&app, UnlockFocus::Factor);
    press(&mut app, KeyCode::BackTab);
    assert_focus(&app, UnlockFocus::Storage);
}

#[test]
fn ctrl_o_reveals_the_password_and_unlock_button_works() {
    let base = temp_dir("unlock-action-buttons");
    make_vault(&base);
    let mut app = app(&base);
    type_text(&mut app, PASSWORD);
    assert!(!render(&app, 100, 30).contains("Enter password"));
    app.on_key(&ctrl('o'));
    assert!(render(&app, 100, 30).contains(PASSWORD));
    app.on_key(&ctrl('o'));
    assert!(!render(&app, 100, 30).contains(PASSWORD));
    press(&mut app, KeyCode::Tab);
    assert_focus(&app, UnlockFocus::Unlock);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
}

#[test]
fn factor_arrows_keep_password_and_move_to_unlock() {
    let base = temp_dir("unlock-factor-arrows");
    make_vault(&base);
    let mut app = app(&base);
    assert_eq!(unlock(&app).modes(), [Mode::Password]);
    press(&mut app, KeyCode::Up);
    assert_focus(&app, UnlockFocus::Factor);
    press(&mut app, KeyCode::Right);
    assert_eq!(unlock(&app).mode, Mode::Password);
    press(&mut app, KeyCode::Enter);
    assert_focus(&app, UnlockFocus::Input);
    press(&mut app, KeyCode::Down);
    assert_focus(&app, UnlockFocus::Unlock);
    press(&mut app, KeyCode::Up);
    assert_focus(&app, UnlockFocus::Input);
    press(&mut app, KeyCode::Up);
    assert_focus(&app, UnlockFocus::Factor);
}

#[test]
fn storage_arrows_and_picker_switch_vaults_and_wipe_input() {
    let base = temp_dir("unlock-storage-switch");
    make_vault(&base);
    make_vault(&base);
    let mut app = app(&base);
    assert_eq!(unlock(&app).vaults.len(), 2);
    assert_eq!(unlock(&app).current, 0);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::BackTab);
    press(&mut app, KeyCode::BackTab);
    assert_focus(&app, UnlockFocus::Storage);
    press(&mut app, KeyCode::Right);
    assert_eq!(unlock(&app).current, 1);
    assert!(unlock(&app).password.is_empty());
    assert!(render(&app, 100, 30).contains("Storage 2/2"));

    press(&mut app, KeyCode::Enter);
    assert_eq!(unlock(&app).picker, Some(1));
    press(&mut app, KeyCode::Up);
    assert_eq!(unlock(&app).picker, Some(0));
    press(&mut app, KeyCode::Enter);
    assert_eq!(unlock(&app).picker, None);
    assert_eq!(unlock(&app).current, 0);

    press(&mut app, KeyCode::Left);
    assert_eq!(unlock(&app).current, 1);
    press(&mut app, KeyCode::Right);
    assert_eq!(unlock(&app).current, 0);
}

#[test]
fn new_opens_the_create_or_restore_choice() {
    let base = temp_dir("unlock-new-button");
    make_vault(&base);
    let mut create_app = app(&base);
    press(&mut create_app, KeyCode::Tab);
    press(&mut create_app, KeyCode::Tab);
    assert_focus(&create_app, UnlockFocus::New);
    press(&mut create_app, KeyCode::Enter);
    assert_eq!(create_app.screen.name(), "welcome");
    let choice = render(&create_app, 100, 30);
    assert!(choice.contains("Create a new vault"), "{choice}");
    assert!(choice.contains("Restore or import"), "{choice}");
    press(&mut create_app, KeyCode::Enter);
    assert_eq!(create_app.screen.name(), "create");

    let mut restore_app = app(&base);
    press(&mut restore_app, KeyCode::Tab);
    press(&mut restore_app, KeyCode::Tab);
    press(&mut restore_app, KeyCode::Enter);
    press(&mut restore_app, KeyCode::Right);
    press(&mut restore_app, KeyCode::Enter);
    assert_eq!(restore_app.screen.name(), "import");
}
