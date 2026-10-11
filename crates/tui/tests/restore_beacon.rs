//! The restore screen listens for LAN beacons: another device of the account
//! that announces itself shows up as a candidate, and picking it only fills
//! the address field. Driven with real keystrokes against two apps, with the
//! beacons carried over loopback unicast instead of multicast.

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

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use p2p_net::BeaconConfig;
use tui::app::flows::restore::RestoreState;
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, Op};
use tui::App;
use zeroize::Zeroizing;

use common::{
    app_with, config, ctrl, make_vault, press, render, temp_dir, type_text, unlock, wait, CAPS,
    PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Beacons from `send_to_port` side heard on `bind_port`, every 150 ms.
fn beacon(bind_port: u16, send_to_port: u16) -> BeaconConfig {
    BeaconConfig {
        send_to: SocketAddr::from(([127, 0, 0, 1], send_to_port)),
        bind: SocketAddr::from(([127, 0, 0, 1], bind_port)),
        join: None,
        every: Duration::from_millis(150),
        loopback: true,
    }
}

/// Save the beacon listening mode in the vault under `base`.
fn announce_on_the_network(base: &Path) {
    let paths = discover(base).first().unwrap().paths.clone();
    let password = Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()));
    let mut vault = unlock_vault(paths, password).unwrap();
    let prefs = local::Prefs {
        p2p_listen: local::Listen::Beacon,
        ..local::Prefs::default()
    };
    apply(&mut vault, Op::SavePrefs(Box::new(prefs))).unwrap();
}

/// A device that is unlocked and announces itself: returns its app, its
/// phrase and the address its node listens at.
fn announcing_device(tag: &str, bind_port: u16, send_to_port: u16) -> (App, String, String) {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    announce_on_the_network(&base);
    let mut cfg = config(&base);
    cfg.beacon = Some(beacon(bind_port, send_to_port));
    let mut first = app_with(&cfg, &base, CAPS);
    unlock(&mut first, PASSWORD);
    let Screen::Unlocked(state) = &first.screen else {
        panic!("not unlocked")
    };
    let address = state
        .p2p
        .as_ref()
        .expect("the node runs")
        .service
        .local_addr()
        .unwrap()
        .to_string();
    (first, words, address)
}

fn open_restore(app: &mut App) {
    press(app, KeyCode::Right);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
}

fn state(app: &App) -> &RestoreState {
    let Screen::Restore(state) = &app.screen else {
        panic!("not restore: {}", app.screen.name())
    };
    state
}

/// The restore screen over the network with `words` typed in.
fn restore_over_network(base: &Path, words: &str, beacon: Option<BeaconConfig>) -> App {
    let mut cfg = config(base);
    cfg.beacon = beacon;
    let mut second = app_with(&cfg, base, CAPS);
    open_restore(&mut second);
    for word in words.split(' ') {
        type_text(&mut second, word);
        press(&mut second, KeyCode::Char(' '));
    }
    second
}

/// Run the app's timers until `done` holds, or `within` has passed.
fn tick_until(app: &mut App, within: Duration, done: impl Fn(&RestoreState) -> bool) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        app.on_tick(Instant::now());
        if done(state(app)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done(state(app))
}

#[test]
fn a_device_that_announces_itself_is_a_candidate_and_the_restore_through_it_succeeds() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (first, words, address) = announcing_device("bc-first", first_bind, second_bind);
    let base = temp_dir("bc-second");
    let mut second = restore_over_network(&base, &words, Some(beacon(second_bind, first_bind)));

    assert!(
        tick_until(&mut second, Duration::from_secs(60), |s| !s
            .found
            .is_empty()),
        "the beacon was heard"
    );
    // The node listens on every interface; the beacon came from loopback.
    let port = address.rsplit(':').next().unwrap();
    let address = format!("127.0.0.1:{port}");
    assert_eq!(state(&second).found, [address.clone().into_boxed_str()]);
    let screen = render(&second, 120, 40);
    assert!(screen.contains("1 found"), "{screen}");

    // Nothing was dialed or filled in by itself.
    assert_eq!(state(&second).address.value(), "");
    assert_eq!(second.screen.name(), "restore");

    // One key puts it in the field; continuing is still the person's act.
    second.on_key(&ctrl('b'));
    assert_eq!(state(&second).address.value(), address);
    press(&mut second, KeyCode::Enter);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Enter);
    wait(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    drop(first);
}

#[test]
fn a_device_of_another_account_never_appears() {
    let (second_bind, other_bind) = (free_udp_port(), free_udp_port());
    // The announcing device belongs to another account than the phrase typed.
    let (_other, _other_words, _) = announcing_device("bc-other", other_bind, second_bind);
    let base_a = temp_dir("bc-mine");
    let mine = make_vault(&base_a);
    let mut second = restore_over_network(
        &temp_dir("bc-second-b"),
        &mine,
        Some(beacon(second_bind, other_bind)),
    );
    assert!(
        !tick_until(&mut second, Duration::from_secs(4), |s| !s.found.is_empty()),
        "a beacon sealed for another account is not even opened"
    );
    second.on_key(&ctrl('b'));
    assert_eq!(state(&second).address.value(), "");
}

#[test]
fn with_the_beacon_off_nothing_is_listened_for() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, _address) = announcing_device("bc-off-first", first_bind, second_bind);
    let mut second = restore_over_network(&temp_dir("bc-off-second"), &words, None);
    assert!(
        !tick_until(&mut second, Duration::from_secs(3), |s| !s.found.is_empty()),
        "no beacon listener, no candidates"
    );
    // The port the announcing device sends to stays unbound.
    assert!(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], second_bind))).is_ok());
    second.on_key(&ctrl('b'));
    assert_eq!(state(&second).address.value(), "");
}

#[test]
fn the_listener_follows_the_phrase_and_stops_with_the_screen() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, _address) = announcing_device("bc-follow", first_bind, second_bind);
    let base = temp_dir("bc-follow-second");
    let mut second = restore_over_network(&base, &words, Some(beacon(second_bind, first_bind)));
    assert!(tick_until(&mut second, Duration::from_secs(60), |s| !s
        .found
        .is_empty()));
    assert!(
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], second_bind))).is_err(),
        "the listener holds its port while the phrase is whole"
    );

    // Taking the last word back makes the phrase incomplete: the listener
    // closes and what was found is forgotten.
    press(&mut second, KeyCode::Backspace);
    press(&mut second, KeyCode::Backspace);
    assert!(state(&second).found.is_empty());
    assert!(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], second_bind))).is_ok());

    // Leaving the screen with the phrase whole again also frees the port.
    type_text(&mut second, "zoo");
    press(&mut second, KeyCode::Char(' '));
    drop(second);
    assert!(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], second_bind))).is_ok());
}
