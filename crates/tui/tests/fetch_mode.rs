//! Fetch only: a device that listens nowhere, announces nothing and holds no
//! slot, yet restores from a peer, pulls what the peer wrote since, and keeps
//! its place in the account.

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

use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use local::Listen;
use p2p_net::{BeaconConfig, Relay, RelayLimits};
use record::{Document, TAG_TITLE};
use session::write_record;
use tui::app::flows::restore::RestoreField;
use tui::app::personal::wants_node;
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::App;
use zeroize::Zeroizing;

use common::{
    app, app_with, config, ctrl, keep_to_this_device, make_vault, press, render, temp_dir,
    type_text, unlock, wait, CAPS, PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

/// Put records into the vault under `base` while no app has it open.
fn add_records(base: &Path, titles: &[&str]) {
    let paths = discover(base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(
        paths,
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    for title in titles {
        write_record(&mut vault.session, &mut vault.file, None, &titled(title)).unwrap();
    }
    vault.persist().unwrap();
}

/// The first device: a vault with records, its node on this device only, and
/// the app unlocked so the node runs. Returns the app, the phrase and the
/// address the node listens at.
fn first_device(tag: &str) -> (App, String, String) {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    keep_to_this_device(&base);
    add_records(&base, &["wifi", "bank"]);
    let mut first = app(&base);
    unlock(&mut first, PASSWORD);
    let address = listening(&first);
    (first, words, address)
}

fn listening(app: &App) -> String {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
        .p2p
        .as_ref()
        .expect("the node runs without a shared vault")
        .service
        .local_addr()
        .expect("the node listens")
        .to_string()
}

fn titles_of(app: &App) -> Vec<String> {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    let mut titles: Vec<String> = state
        .cache
        .iter()
        .map(|row| row.title.to_string())
        .collect();
    titles.sort();
    titles
}

/// Welcome → restore chooser → the phrase restore.
fn open_restore(app: &mut App) {
    press(app, KeyCode::Right);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
}

fn type_phrase(app: &mut App, words: &str) {
    for word in words.split(' ') {
        type_text(app, word);
        press(app, KeyCode::Char(' '));
    }
}

fn restore_state(app: &App) -> &tui::app::flows::restore::RestoreState {
    let Screen::Restore(state) = &app.screen else {
        panic!("not restore: {}", app.screen.name())
    };
    state
}

/// Put `address` in the network source and press Continue.
fn set_address_and_continue(app: &mut App, address: &str) {
    while restore_state(app).field != RestoreField::Phrase {
        press(app, KeyCode::BackTab);
    }
    if !restore_state(app).network {
        app.on_key(&ctrl('n'));
    }
    press(app, KeyCode::Tab);
    assert_eq!(restore_state(app).field, RestoreField::Source);
    for _ in 0..restore_state(app).address.value().len() {
        press(app, KeyCode::Backspace);
    }
    type_text(app, address);
    press(app, KeyCode::Enter);
}

/// Phrase, then the network source with `address`, then Continue.
fn enter_phrase_and_address(app: &mut App, words: &str, address: &str) {
    assert_eq!(restore_state(app).field, RestoreField::Phrase);
    type_phrase(app, words);
    set_address_and_continue(app, address);
}

fn enroll_password(app: &mut App) {
    type_text(app, SECOND_PASSWORD);
    press(app, KeyCode::Tab);
    type_text(app, SECOND_PASSWORD);
    press(app, KeyCode::Enter);
    wait(app);
}

/// Add `title` to the vault file under `base` while its app keeps running: the
/// node serves what is on disk.
fn write_behind(base: &Path, title: &str) {
    add_records(base, &[title]);
}

fn state(app: &App) -> &tui::app::flows::unlocked::Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
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

#[test]
fn only_a_fetch_only_or_listening_device_wants_a_node_and_off_is_unchanged() {
    // With the account's gate secret and nothing else asking.
    for (listen, holds, expected) in [
        (Listen::Lan, false, true),
        (Listen::Beacon, false, true),
        (Listen::Local, false, true),
        (Listen::Fetch, false, true),
        (Listen::Off, false, false),
        (Listen::Off, true, true),
    ] {
        assert_eq!(
            wants_node(true, 0, listen, holds),
            expected,
            "{listen:?} {holds}"
        );
        assert!(
            wants_node(true, 1, listen, holds),
            "a shared vault always does"
        );
    }
    assert!(
        !wants_node(false, 0, Listen::Fetch, false),
        "no gate, nothing to serve or pull"
    );
}

#[test]
fn a_restored_device_set_to_fetch_only_still_pulls_what_the_peer_wrote_after() {
    let (first, words, address) = first_device("fetch-first");
    let first_base = state(&first).base.clone();
    let base = temp_dir("fetch-second");
    let mut second = app(&base);
    open_restore(&mut second);
    enter_phrase_and_address(&mut second, &words, &address);
    enroll_password(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    assert_eq!(
        titles_of(&second),
        ["bank", "wifi"],
        "the restore dialed out"
    );

    choose(&mut second, Listen::Fetch);
    let screen = render(&second, 140, 40);
    assert!(screen.contains("fetch only · pulls every 15 s"), "{screen}");
    let p2p = state(&second)
        .p2p
        .as_ref()
        .expect("the node runs, to dial out");
    assert!(p2p.service.local_addr().is_none(), "no listener");

    // The peer writes; the fetch-only device finds it when it next pulls
    // (here, at the restart the lock and unlock make).
    write_behind(&first_base, "mail");
    press(&mut second, KeyCode::Esc);
    press(&mut second, KeyCode::Char('L'));
    press(&mut second, KeyCode::Enter);
    unlock(&mut second, SECOND_PASSWORD);
    assert_eq!(
        state(&second).listen_mode(),
        Listen::Fetch,
        "the choice is kept"
    );
    assert!(
        tick_until(&mut second, |app| titles_of(app)
            .contains(&"mail".to_owned())),
        "the pull brought it"
    );
    assert_eq!(titles_of(&second), ["bank", "mail", "wifi"]);
    assert!(state(&second)
        .p2p
        .as_ref()
        .unwrap()
        .service
        .local_addr()
        .is_none());
}

#[test]
fn fetch_only_binds_no_socket_beacons_nothing_and_holds_no_slot() {
    let relay = Relay::start(
        "127.0.0.1:0",
        RelayLimits {
            difficulty_idle: 4,
            ..RelayLimits::default()
        },
    )
    .unwrap();
    let probe = |port: u16| UdpSocket::bind(("127.0.0.1", port));
    let beacon_port = {
        let socket = probe(0).unwrap();
        socket.local_addr().unwrap().port()
    };
    let base = temp_dir("fetch-quiet");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut cfg = config(&base);
    cfg.beacon = Some(BeaconConfig {
        send_to: format!("127.0.0.1:{beacon_port}").parse().unwrap(),
        bind: format!("127.0.0.1:{beacon_port}").parse().unwrap(),
        join: None,
        every: Duration::from_millis(100),
        loopback: true,
    });
    let mut app = app_with(&cfg, &base, CAPS);
    unlock(&mut app, PASSWORD);

    // A saved relay, announcing on, then fetch only: the switch goes off.
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('v'));
    type_text(
        &mut app,
        &format!("{}/{}", relay.local_addr(), "ab".repeat(16)),
    );
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    press(&mut app, KeyCode::Char('t'));
    wait(&mut app);
    assert!(state(&app).info.prefs.as_ref().unwrap().p2p_hold);
    choose(&mut app, Listen::Fetch);
    assert!(
        !state(&app).info.prefs.as_ref().unwrap().p2p_hold,
        "cycling into fetch only turns it off"
    );

    // The node runs, but nothing about it is reachable or announced.
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        app.on_tick(Instant::now());
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(relay.stats().reservations, 0, "no slot");
    assert!(probe(beacon_port).is_ok(), "no beacon socket");
    assert!(state(&app)
        .p2p
        .as_ref()
        .unwrap()
        .service
        .local_addr()
        .is_none());
    assert!(state(&app).p2p.as_ref().unwrap().relayed.is_none());

    // The announce key says why it does nothing.
    press(&mut app, KeyCode::Char('t'));
    assert!(render(&app, 160, 30).contains("Fetch only holds no relay slot"));
    assert!(!state(&app).info.prefs.as_ref().unwrap().p2p_hold);
    assert_eq!(relay.stats().reservations, 0);
}
