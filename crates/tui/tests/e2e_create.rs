//! The whole first-run path through the UI: create wizard (setup, phrase,
//! verify, enroll), a record typed in the editor, copy, lock, and unlock.

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
use tui::app::flows::create::Step;
use tui::app::screen::Screen;

use common::{app, ctrl, press, render, temp_dir, type_text, unlock, wait, PASSWORD};

const RECORD_PASSWORD: &str = "S3cure-Pa55!word";

/// Answer the three verify cards with the right words.
fn pass_verify(app: &mut tui::App, wrong_first: bool) {
    for card in 0..3 {
        let (choices, expected) = {
            let Screen::Create(state) = &app.screen else {
                panic!("not create")
            };
            let verify = state.verify.as_ref().unwrap();
            let phrase = state
                .phrase
                .as_ref()
                .unwrap()
                .phrase_normalized()
                .to_owned();
            let word = phrase
                .split(' ')
                .nth(verify.position(card) - 1)
                .unwrap()
                .to_owned();
            (verify.choices(card), word)
        };
        let right = choices
            .iter()
            .position(|choice| *choice == expected)
            .unwrap();
        let pick = if wrong_first && card == 0 {
            (right + 1) % 4
        } else {
            right
        };
        for _ in 0..pick {
            press(app, KeyCode::Down);
        }
        press(app, KeyCode::Enter);
    }
}

#[test]
fn first_run_creates_a_vault_and_round_trips_a_record() {
    let base = temp_dir("e2e");
    let mut app = app(&base);
    assert_eq!(app.screen.name(), "welcome");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(state.step, Step::Ceremony);

    press(&mut app, KeyCode::Enter);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(
        state.step,
        Step::Ceremony,
        "cannot continue before ticking 'written'"
    );
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);

    pass_verify(&mut app, true);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(
        state.step,
        Step::Verify,
        "a wrong pick keeps the verify step"
    );
    assert!(render(&app, 100, 30).contains("Not quite. Check your paper."));
    pass_verify(&mut app, false);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    assert_eq!(state.step, Step::Enroll);

    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, PASSWORD);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");

    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Mail");
    for _ in 0..4 {
        press(&mut app, KeyCode::Tab);
    }
    type_text(&mut app, RECORD_PASSWORD);
    app.on_key(&ctrl('s'));
    wait(&mut app);
    assert!(render(&app, 140, 40).contains("Mail"));

    let _ = app.take_outbox();
    press(&mut app, KeyCode::Char('c'));
    let out = app.take_outbox();
    assert_eq!(out.len(), 1, "one OSC 52 write");

    press(&mut app, KeyCode::Char('L'));
    assert_eq!(app.screen.name(), "locked");
    press(&mut app, KeyCode::Enter);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "unlocked");
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    assert_eq!(state.cache.len(), 1);
    assert_eq!(&*state.cache[0].title, "Mail");
}
