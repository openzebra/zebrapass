//! Announcing this device through a saved relay: the switch, what it holds,
//! and what drops the slot again.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use p2p_net::{Relay, RelayLimits};
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, Op};
use tui::App;
use zeroize::Zeroizing;

use common::{
    app, keep_to_this_device, make_vault, press, render, temp_dir, type_text, unlock, wait,
    PASSWORD,
};

fn relay() -> Relay {
    Relay::start(
        "127.0.0.1:0",
        RelayLimits {
            difficulty_idle: 4,
            ..RelayLimits::default()
        },
    )
    .unwrap()
}

fn slot_hint(relay: &Relay) -> String {
    format!("{}/{}", relay.local_addr(), "ab".repeat(16))
}

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

fn holds(app: &App) -> bool {
    state(app)
        .info
        .prefs
        .as_ref()
        .is_some_and(|prefs| prefs.p2p_hold)
}

/// Run the app's timers until `done`, or give up after a while.
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

fn reservations(relay: &Relay, wanted: usize) -> bool {
    let until = Instant::now() + Duration::from_secs(60);
    while Instant::now() < until {
        if relay.stats().reservations == wanted {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn on_share(base: &Path) -> App {
    let mut app = app(base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('S'));
    assert!(matches!(share(&app).step, Step::Overview));
    app
}

#[test]
fn the_switch_holds_and_drops_a_slot_and_is_kept_across_a_restart() {
    let relay = relay();
    let base = temp_dir("hold-cycle");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = on_share(&base);

    // With no saved relay the key says what to do first and holds nothing.
    press(&mut app, KeyCode::Char('t'));
    assert!(render(&app, 160, 30).contains("Save a relay first"));
    assert!(!holds(&app));
    assert_eq!(relay.stats().reservations, 0);

    press(&mut app, KeyCode::Char('v'));
    type_text(&mut app, &slot_hint(&relay));
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert!(render(&app, 160, 30).contains("t announces me"));
    assert_eq!(
        relay.stats().reservations,
        0,
        "saving a relay holds nothing"
    );

    // On: a slot is held, the node reports it, the line says so.
    press(&mut app, KeyCode::Char('t'));
    wait(&mut app);
    assert!(holds(&app));
    assert!(reservations(&relay, 1));
    assert!(tick_until(&mut app, |app| state(app)
        .p2p
        .as_ref()
        .is_some_and(|p2p| p2p.relayed.is_some())));
    let screen = render(&app, 160, 30);
    assert!(screen.contains("announced via relay"), "{screen}");
    assert!(screen.contains("t stops"), "{screen}");

    // Off: the node restarts and the relay sees the slot go.
    press(&mut app, KeyCode::Char('t'));
    wait(&mut app);
    assert!(!holds(&app));
    assert!(reservations(&relay, 0), "the slot was dropped");
    assert!(state(&app).p2p.as_ref().unwrap().relayed.is_none());
    assert!(!render(&app, 160, 30).contains("announced via relay"));

    // On again, then a restart of the whole app: still on, and held again.
    press(&mut app, KeyCode::Char('t'));
    wait(&mut app);
    assert!(reservations(&relay, 1));
    drop(app);
    assert!(reservations(&relay, 0), "closing the app frees the slot");
    let mut again = app_unlocked(&base);
    assert!(holds(&again));
    assert!(reservations(&relay, 1), "held again after the restart");
    assert!(tick_until(&mut again, |app| state(app)
        .p2p
        .as_ref()
        .is_some_and(|p2p| p2p.relayed.is_some())));
}

fn app_unlocked(base: &Path) -> App {
    let mut app = app(base);
    unlock(&mut app, PASSWORD);
    app
}

#[test]
fn taking_every_relay_back_turns_the_switch_off_and_frees_the_slot() {
    let relay = relay();
    let base = temp_dir("hold-remove");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = on_share(&base);
    press(&mut app, KeyCode::Char('v'));
    type_text(&mut app, &slot_hint(&relay));
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    press(&mut app, KeyCode::Char('t'));
    wait(&mut app);
    assert!(reservations(&relay, 1));

    // An empty entry takes the saved relays back.
    press(&mut app, KeyCode::Char('v'));
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert!(matches!(share(&app).step, Step::Overview));
    assert!(!holds(&app), "nothing to announce through");
    assert!(state(&app)
        .info
        .prefs
        .as_ref()
        .unwrap()
        .p2p_relays
        .is_empty());
    assert!(reservations(&relay, 0));
    press(&mut app, KeyCode::Char('t'));
    assert!(render(&app, 160, 30).contains("Save a relay first"));

    // And with none saved, an empty entry has nothing to remove.
    press(&mut app, KeyCode::Char('v'));
    press(&mut app, KeyCode::Enter);
    assert!(matches!(share(&app).step, Step::Relay(_)));
}

#[test]
fn a_node_that_listens_nowhere_still_holds_a_slot_and_announces_it() {
    let relay = relay();
    let base = temp_dir("hold-off");
    make_vault(&base);
    let paths = discover(&base).first().unwrap().paths.clone();
    let password = Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()));
    let mut vault = unlock_vault(paths, password).unwrap();
    let prefs = local::Prefs {
        p2p_listen: local::Listen::Off,
        p2p_relays: vec![slot_hint(&relay).into()],
        p2p_hold: true,
        ..local::Prefs::default()
    };
    apply(&mut vault, Op::SavePrefs(Box::new(prefs))).unwrap();
    drop(vault);

    let mut app = app_unlocked(&base);
    let p2p = state(&app)
        .p2p
        .as_ref()
        .expect("the node runs to hold the slot");
    assert!(p2p.service.local_addr().is_none(), "it listens nowhere");
    assert!(reservations(&relay, 1));
    assert!(tick_until(&mut app, |app| state(app)
        .p2p
        .as_ref()
        .is_some_and(|p2p| p2p.relayed.is_some())));
    press(&mut app, KeyCode::Char('S'));
    let screen = render(&app, 160, 30);
    assert!(screen.contains("not listening"), "{screen}");
    assert!(screen.contains("announced via relay"), "{screen}");
}
