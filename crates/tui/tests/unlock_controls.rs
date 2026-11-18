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
use tui::App;
use tui::app::flows::unlock::{Mode, UnlockFocus, UnlockState};
use tui::app::keymap::{Scope, hints, label};
use tui::app::screen::Screen;
use tui::ui::widgets::vault_card::{card_codename, short_tag, sigil_rows};

use common::{PASSWORD, app, ctrl, make_vault, press, render, temp_dir, type_text, wait};

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
            (String::from("←"), "card"),
            (String::from("Ctrl-N"), "next card"),
            (String::from("Ctrl-O"), "reveal"),
            (String::from("Esc"), "clear"),
            (String::from("Ctrl-Q"), "quit")
        ]
    );
    let id = unlock(&app).active_vault_id();
    let codename = card_codename(id.as_ref());
    let tag = short_tag(id.as_ref());
    let [sigil_top, _, _] = sigil_rows(id.as_ref(), false);
    let screen = render(&app, 100, 30);
    for landmark in [
        "ZEBRAPASS",
        "Unlock your vault",
        "This vault is locked",
        "quantum-safe",
        "VAULT CARD",
        codename.as_str(),
        tag.as_str(),
        sigil_top.as_str(),
        "solo card",
        "Password",
        "Enter password",
        "Unlock",
        "New",
        "← card",
        "Ctrl-N next card",
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
        "Storage 1/1",
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
    let first_name = card_codename(unlock(&app).vaults[0].vault_id.as_ref());
    let second_name = card_codename(unlock(&app).vaults[1].vault_id.as_ref());
    let first_screen = render(&app, 100, 30);
    assert!(first_screen.contains(&first_name), "{first_screen}");
    assert!(first_screen.contains("● ○"), "{first_screen}");

    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::BackTab);
    press(&mut app, KeyCode::BackTab);
    assert_focus(&app, UnlockFocus::Storage);
    press(&mut app, KeyCode::Right);
    assert_eq!(unlock(&app).current, 1);
    assert!(unlock(&app).password.is_empty());
    let second_screen = render(&app, 100, 30);
    assert!(second_screen.contains(&second_name), "{second_screen}");
    assert!(second_screen.contains("○ ●"), "{second_screen}");
    assert!(
        second_screen.contains("←/→ · h/l flip · Enter deck"),
        "{second_screen}"
    );
    assert!(!second_screen.contains("Storage 2/2"), "{second_screen}");

    press(&mut app, KeyCode::Enter);
    assert_eq!(unlock(&app).picker, Some(1));
    let modal_screen = render(&app, 100, 30);
    assert!(
        modal_screen.contains("Choose a vault card"),
        "{modal_screen}"
    );
    assert!(modal_screen.contains(&first_name), "{modal_screen}");
    assert!(modal_screen.contains(&second_name), "{modal_screen}");
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

#[test]
fn last_unlocked_vault_is_remembered_and_priority_selected() {
    let base = temp_dir("unlock-remember-last");
    make_vault(&base);
    make_vault(&base);

    let mut first_run = app(&base);
    assert_eq!(unlock(&first_run).vaults.len(), 2);
    let chosen_id = unlock(&first_run).vaults[1].vault_id;
    let chosen_name = card_codename(chosen_id.as_ref());

    // Flip to the second card and unlock it.
    press(&mut first_run, KeyCode::BackTab);
    press(&mut first_run, KeyCode::BackTab);
    assert_focus(&first_run, UnlockFocus::Storage);
    press(&mut first_run, KeyCode::Right);
    assert_eq!(unlock(&first_run).active_vault_id(), chosen_id);
    press(&mut first_run, KeyCode::Tab);
    press(&mut first_run, KeyCode::Tab);
    assert_focus(&first_run, UnlockFocus::Input);
    type_text(&mut first_run, PASSWORD);
    press(&mut first_run, KeyCode::Enter);
    wait(&mut first_run);
    assert_eq!(first_run.screen.name(), "unlocked");

    // Lock within the same session and resume: still priority #0.
    press(&mut first_run, KeyCode::Esc);
    press(&mut first_run, KeyCode::Char('L'));
    press(&mut first_run, KeyCode::Enter);
    assert_eq!(first_run.screen.name(), "unlock");
    assert_eq!(unlock(&first_run).current, 0);
    assert_eq!(unlock(&first_run).active_vault_id(), chosen_id);

    // Relaunch a brand-new App over the same directory: priority #0 and badged.
    drop(first_run);
    let mut second_run = app(&base);
    assert_eq!(unlock(&second_run).current, 0);
    assert_eq!(unlock(&second_run).active_vault_id(), chosen_id);
    assert!(unlock(&second_run).vaults[0].last_unlocked);
    assert!(!unlock(&second_run).vaults[1].last_unlocked);
    let screen = render(&second_run, 100, 30);
    assert!(screen.contains(&chosen_name), "{screen}");
    assert!(screen.contains("LAST UNLOCKED"), "{screen}");
    assert!(screen.contains("● ○"), "{screen}");

    // Typing the password immediately unlocks the priority-selected vault.
    type_text(&mut second_run, PASSWORD);
    press(&mut second_run, KeyCode::Enter);
    wait(&mut second_run);
    assert_eq!(second_run.screen.name(), "unlocked");
}

#[test]
fn arrows_and_ctrl_np_switch_cards_directly_from_input() {
    let base = temp_dir("unlock-arrow-hotkeys");
    make_vault(&base);
    make_vault(&base);
    let mut app = app(&base);
    assert_focus(&app, UnlockFocus::Input);
    assert_eq!(unlock(&app).current, 0);

    // Empty input: Left and Right flip vault cards without leaving Input!
    press(&mut app, KeyCode::Right);
    assert_eq!(unlock(&app).current, 1);
    assert_focus(&app, UnlockFocus::Input);
    press(&mut app, KeyCode::Left);
    assert_eq!(unlock(&app).current, 0);
    assert_focus(&app, UnlockFocus::Input);

    // Non-empty input: Left moves cursor instead of wiping the typed secret...
    type_text(&mut app, "abc");
    press(&mut app, KeyCode::Left);
    assert_eq!(unlock(&app).current, 0);
    assert_eq!(unlock(&app).password.len(), 3);

    // ...while Ctrl-N / Ctrl-P and PageDown / PageUp switch cards anytime!
    app.on_key(&ctrl('n'));
    assert_eq!(unlock(&app).current, 1);
    assert!(unlock(&app).password.is_empty());
    app.on_key(&ctrl('p'));
    assert_eq!(unlock(&app).current, 0);
    press(&mut app, KeyCode::PageDown);
    assert_eq!(unlock(&app).current, 1);
    press(&mut app, KeyCode::PageUp);
    assert_eq!(unlock(&app).current, 0);
}

#[test]
fn vim_keys_navigate_and_switch_cards_without_eating_passwords() {
    use seed::SeedPhrase;
    use session::KdfProfile;
    use tui::vault::create::{Enrollment, NewVault, create};
    use zeroize::Zeroizing;

    let base = temp_dir("unlock-vim-hotkeys");
    let tricky_pw = "hjkl-HL-[]-i ?-secret-42";
    for label in ["Alpha", "Beta", "Gamma"] {
        let phrase = SeedPhrase::generate_24().unwrap();
        let vault = create(NewVault {
            phrase: Box::new(phrase),
            name: String::from(label),
            base: base.clone(),
            profile: KdfProfile::Fast,
            factor: Enrollment::Password(Zeroizing::new(tricky_pw.as_bytes().to_vec())),
            records: Vec::new(),
        })
        .unwrap();
        drop(vault);
    }

    let mut app = app(&base);
    assert_eq!(unlock(&app).vaults.len(), 3);
    assert_focus(&app, UnlockFocus::Input);

    // Esc on empty Input enters normal mode on the Vault Card deck.
    press(&mut app, KeyCode::Esc);
    assert_focus(&app, UnlockFocus::Storage);

    // h / l flip cards in normal mode.
    press(&mut app, KeyCode::Char('l'));
    assert_eq!(unlock(&app).current, 1);
    press(&mut app, KeyCode::Char('l'));
    assert_eq!(unlock(&app).current, 2);
    press(&mut app, KeyCode::Char('h'));
    assert_eq!(unlock(&app).current, 1);

    // j / k walk controls vertically, and [ / ] / H / L switch cards from any non-input focus.
    press(&mut app, KeyCode::Char('j'));
    assert_focus(&app, UnlockFocus::Factor);
    press(&mut app, KeyCode::Char(']'));
    assert_eq!(unlock(&app).current, 2);
    press(&mut app, KeyCode::Char('['));
    assert_eq!(unlock(&app).current, 1);
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(unlock(&app).current, 2);
    press(&mut app, KeyCode::Char('H'));
    assert_eq!(unlock(&app).current, 1);
    press(&mut app, KeyCode::Char('k'));
    assert_focus(&app, UnlockFocus::Storage);

    // Picker modal supports j / k / g / G / Space / q.
    press(&mut app, KeyCode::Enter);
    assert_eq!(unlock(&app).picker, Some(1));
    press(&mut app, KeyCode::Char('G'));
    assert_eq!(unlock(&app).picker, Some(2));
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(unlock(&app).picker, Some(0));
    press(&mut app, KeyCode::Char('j'));
    assert_eq!(unlock(&app).picker, Some(1));
    press(&mut app, KeyCode::Char(' '));
    assert_eq!(unlock(&app).picker, None);
    assert_eq!(unlock(&app).current, 1);

    // 'i' enters Input mode, and typing vim hotkey chars never steals them from the password.
    press(&mut app, KeyCode::Char('i'));
    assert_focus(&app, UnlockFocus::Input);
    type_text(&mut app, tricky_pw);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
}
