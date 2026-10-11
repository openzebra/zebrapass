//! Settings → Sync: live peer-to-peer rows for the unlocked vault, the
//! outcome of a real check-in, and the Sync now action.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use local::Listen;
use tui::app::flows::unlocked::Unlocked;
use tui::app::screen::Screen;
use tui::App;

use common::{
    app, keep_to_this_device, make_vault, press, render, temp_dir, type_text, unlock, wait,
    PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
}

/// Open settings on the Sync section.
fn open_sync(app: &mut App) -> String {
    type_text(app, ",");
    press(app, KeyCode::Tab);
    press(app, KeyCode::Tab);
    render(app, 140, 40)
}

fn tick_until(app: &mut App, done: impl Fn(&App) -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(60);
    while Instant::now() < until {
        app.on_tick(Instant::now());
        if done(app) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done(app)
}

/// Cycle the listening choice with `l` until `want`.
fn choose(app: &mut App, want: Listen) {
    press(app, KeyCode::Char('S'));
    for _ in 0..Listen::ALL.len() {
        if state(app).listen_mode() == want {
            return;
        }
        press(app, KeyCode::Char('l'));
        wait(app);
    }
    assert_eq!(state(app).listen_mode(), want);
}

fn type_phrase(app: &mut App, words: &str) {
    for word in words.split(' ') {
        type_text(app, word);
        press(app, KeyCode::Char(' '));
    }
}

/// A second device restored from the first one's phrase and listening
/// address, left unlocked.
fn restored_from(words: &str, address: &str, tag: &str) -> App {
    let mut second = app(&temp_dir(tag));
    press(&mut second, KeyCode::Right);
    press(&mut second, KeyCode::Enter);
    press(&mut second, KeyCode::Enter);
    type_phrase(&mut second, words);
    press(&mut second, KeyCode::Tab);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, address);
    press(&mut second, KeyCode::Enter);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Enter);
    wait(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    second
}

#[test]
fn the_sync_section_shows_live_rows_and_waits_for_the_first_check_in() {
    let base = temp_dir("settings-sync");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    let screen = open_sync(&mut app);
    for label in [
        "Status",
        "Last check-in",
        "Peers",
        "Relays",
        "Advertised address",
        "Beacon",
        "Sync now",
    ] {
        assert!(screen.contains(label), "{label}: {screen}");
    }
    assert!(screen.contains("waiting for first check-in"), "{screen}");
    assert!(screen.contains("0 known · 0 reachable"), "{screen}");
    assert!(screen.contains("0 saved · not holding"), "{screen}");
    assert!(!screen.contains("soon"), "{screen}");
    assert!(!screen.contains("Test connection"), "{screen}");
}

#[test]
fn sync_now_with_no_peers_checks_in_without_failing() {
    let base = temp_dir("settings-sync-now");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    open_sync(&mut app);
    for _ in 0..6 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    let screen = render(&app, 140, 40);
    assert!(screen.contains("Checking with your peers"), "{screen}");
    assert!(screen.contains("Settings"), "the modal stays open");
}

#[test]
fn a_real_check_in_shows_its_outcome_and_sync_now_runs_another() {
    let base = temp_dir("settings-sync-first");
    let words = make_vault(&base);
    keep_to_this_device(&base);
    let mut first = app(&base);
    unlock(&mut first, PASSWORD);
    let address = state(&first)
        .p2p
        .as_ref()
        .expect("the node runs")
        .service
        .local_addr()
        .expect("the node listens")
        .to_string();

    let mut second = restored_from(&words, &address, "settings-sync-second");
    choose(&mut second, Listen::Fetch);
    press(&mut second, KeyCode::Esc);
    assert!(
        tick_until(&mut second, |app| state(app)
            .p2p
            .as_ref()
            .is_some_and(|p2p| p2p.last_checkin.is_some())),
        "a check-in ended"
    );
    let screen = open_sync(&mut second);
    assert!(screen.contains("synced ·"), "{screen}");
    assert!(!screen.contains("waiting for first check-in"), "{screen}");

    let before = state(&second)
        .p2p
        .as_ref()
        .unwrap()
        .last_checkin
        .unwrap()
        .at;
    for _ in 0..6 {
        press(&mut second, KeyCode::Down);
    }
    press(&mut second, KeyCode::Enter);
    assert!(
        tick_until(&mut second, |app| state(app)
            .p2p
            .as_ref()
            .and_then(|p2p| p2p.last_checkin)
            .is_some_and(|checkin| checkin.at > before)),
        "Sync now triggered one more check-in"
    );
}
