//! Relay slots on the share screen: pasted, checked, saved in the vault's
//! sealed preferences, kept across a restart, and offered to check-ins.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::App;

use common::{
    app, keep_to_this_device, make_vault, press, render, temp_dir, type_text, unlock, wait,
    PASSWORD,
};

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
}

fn share(app: &App) -> &ShareState {
    let View::Sync(share) = &state(app).view else {
        panic!("not on the share screen")
    };
    share
}

fn saved(app: &App) -> Vec<String> {
    state(app)
        .info
        .prefs
        .as_ref()
        .map(|prefs| prefs.p2p_relays.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

fn hint(n: u8) -> String {
    format!("93.184.216.{n}:7447/{}", "ab".repeat(16))
}

fn on_share(base: &std::path::Path) -> App {
    let mut app = app(base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('S'));
    assert!(matches!(share(&app).step, Step::Overview));
    app
}

fn paste_relay(app: &mut App, text: &str) {
    press(app, KeyCode::Char('v'));
    assert!(matches!(share(app).step, Step::Relay(_)));
    type_text(app, text);
    press(app, KeyCode::Enter);
}

#[test]
fn a_pasted_relay_is_checked_saved_and_kept_across_a_restart() {
    let base = temp_dir("relay-ui");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = on_share(&base);
    assert!(state(&app).p2p.as_ref().unwrap().relays.is_empty());
    assert!(!render(&app, 110, 30).contains("saved"));

    // Wrong input: a toast says why, and nothing is saved.
    for bad in [
        "not a hint",
        "93.184.216.9:7447",
        "93.184.216.9:7447/abcd",
        &hint(9).to_uppercase(),
        &format!("169.254.169.254:80/{}", "ab".repeat(16)),
        &format!("10.0.0.1:99/{}", "ab".repeat(15)),
    ] {
        paste_relay(&mut app, bad);
        assert!(matches!(share(&app).step, Step::Relay(_)), "{bad}");
        assert!(saved(&app).is_empty(), "{bad}");
        let screen = render(&app, 120, 30);
        assert!(
            screen.contains("ip:port/slot") || screen.contains("cannot reach"),
            "{bad}\n{screen}"
        );
        for _ in 0..bad.len() {
            press(&mut app, KeyCode::Backspace);
        }
        press(&mut app, KeyCode::Esc);
    }

    // Esc applies nothing.
    press(&mut app, KeyCode::Char('v'));
    type_text(&mut app, &hint(9));
    press(&mut app, KeyCode::Esc);
    assert!(matches!(share(&app).step, Step::Overview));
    assert!(saved(&app).is_empty());

    // Enter applies.
    paste_relay(&mut app, &hint(9));
    wait(&mut app);
    assert!(matches!(share(&app).step, Step::Overview));
    assert_eq!(saved(&app), [hint(9)]);
    assert_eq!(state(&app).p2p.as_ref().unwrap().relays, [hint(9)]);
    assert!(render(&app, 120, 30).contains("1 saved"));

    // The same one twice, and a fifth, are refused.
    paste_relay(&mut app, &hint(9));
    assert!(matches!(share(&app).step, Step::Relay(_)));
    press(&mut app, KeyCode::Esc);
    for n in 10..13 {
        paste_relay(&mut app, &hint(n));
        wait(&mut app);
    }
    assert_eq!(saved(&app).len(), 4);
    paste_relay(&mut app, &hint(13));
    assert!(matches!(share(&app).step, Step::Relay(_)));
    assert_eq!(saved(&app).len(), 4);
    press(&mut app, KeyCode::Esc);

    // A restart: lock, unlock, and the relays are in the node's list again.
    drop(app);
    let mut again = app_over(&base);
    assert_eq!(
        state(&again).p2p.as_ref().unwrap().relays,
        [hint(9), hint(10), hint(11), hint(12)]
    );
    press(&mut again, KeyCode::Char('S'));
    assert!(render(&again, 120, 30).contains("4 saved"));
}

fn app_over(base: &std::path::Path) -> App {
    let mut app = app(base);
    unlock(&mut app, PASSWORD);
    app
}

#[test]
fn the_node_line_says_when_the_node_holds_a_relay_slot() {
    let base = temp_dir("relay-marker");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = on_share(&base);
    assert!(!render(&app, 120, 30).contains("via relay"));
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!()
    };
    state.note_relayed(hint_value(7));
    let screen = render(&app, 120, 30);
    assert!(screen.contains("via relay"), "{screen}");
}

fn hint_value(n: u8) -> p2p_net::RelayHint {
    hint(n).parse().unwrap()
}

#[test]
fn a_relay_slot_from_a_beacon_enters_the_pull_list_only_if_it_could_ever_be_dialed() {
    let base = temp_dir("relay-beacon");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = on_share(&base);
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!()
    };
    let p2p = state.p2p.as_deref_mut().unwrap();
    let slot = "ab".repeat(16);
    for forbidden in [
        format!("169.254.169.254:7447/{slot}"),
        format!("0.0.0.0:7447/{slot}"),
        format!("224.0.0.1:7447/{slot}"),
        format!("203.0.113.9:7447/{slot}"),
    ] {
        p2p.discover_relay(&forbidden.parse().unwrap());
    }
    assert!(p2p.discovered.is_empty());
    p2p.discover_relay(&hint_value(5));
    assert_eq!(p2p.discovered, [hint(5)]);
}
