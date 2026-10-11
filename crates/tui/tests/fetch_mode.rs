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
use tui::app::personal::wants_node;
use tui::app::screen::Screen;
use tui::App;

use common::{
    add_records, announcing_device, app_with, beacon, config, free_udp_port, keep_to_this_device,
    make_vault, press, render, restore_empty, temp_dir, titles_of, type_text, unlock, wait,
    wait_adopted, CAPS, PASSWORD,
};

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
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, first_base) = announcing_device(
        "fetch-first",
        beacon(first_bind, second_bind),
        &["wifi", "bank"],
    );
    let base = temp_dir("fetch-second");
    let mut second = restore_empty(&base, &words, PASSWORD, beacon(second_bind, first_bind));
    wait_adopted(&mut second, Duration::from_secs(60));
    assert_eq!(
        titles_of(&second),
        ["bank", "wifi"],
        "the vault was brought in"
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
    unlock(&mut second, PASSWORD);
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
