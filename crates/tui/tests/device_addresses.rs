//! A device address typed in Settings → Sync bootstraps a restored device
//! that no beacon reaches: another network, another country. Two apps on
//! loopback, with the beacons pointed at ports nobody listens on.

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

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use tui::app::flows::unlocked::Unlocked;
use tui::App;

use common::{
    add_address, address_of, announcing_device, beacon, fetch_only_with, free_udp_port,
    is_placeholder, make_vault, open_address_list, pair, press, render, restore_empty, temp_dir,
    tick, tick_both, titles_of, type_text, unlock, wait, PASSWORD,
};

const WITHIN: Duration = Duration::from_secs(60);

fn state(app: &App) -> &Unlocked {
    common::unlocked_state(app)
}

fn tick_until(app: &mut App, done: impl Fn(&App) -> bool) -> bool {
    let until = Instant::now() + WITHIN;
    while Instant::now() < until {
        tick(app, Duration::from_millis(50));
        app.wait_for_job(Duration::from_millis(50));
        if done(app) {
            return true;
        }
    }
    done(app)
}

#[test]
fn a_typed_address_brings_the_vault_in_and_later_edits_reach_the_first_device() {
    let (mut a, mut b, base_b) = pair("da-bootstrap");
    assert!(is_placeholder(&b));
    open_address_list(&mut b);
    add_address(&mut b, &address_of(&a));
    assert!(
        tick_until(&mut b, |app| !app.ctx.busy()
            && !is_placeholder(app)
            && app.screen.name() == "unlocked"),
        "the vault never arrived"
    );
    assert_eq!(titles_of(&b), ["bank", "wifi"]);
    assert_eq!(
        state(&b).manual_devices().count(),
        1,
        "the typed address stays with the account's vault"
    );

    // The adopted vault dials the typed address on every check-in, and a
    // later edit travels the push path to the first device.
    press(&mut b, KeyCode::Char('L'));
    press(&mut b, KeyCode::Enter);
    fetch_only_with(&base_b, PASSWORD);
    unlock(&mut b, PASSWORD);
    assert_eq!(
        state(&b).manual_devices().count(),
        1,
        "survives lock and unlock"
    );
    press(&mut b, KeyCode::Char('n'));
    type_text(&mut b, "Router");
    b.on_key(&common::ctrl('s'));
    wait(&mut b);
    assert!(
        tick_both(&mut a, &mut b, WITHIN, |a, _| titles_of(a)
            .contains(&"Router".to_owned())),
        "the edit never reached the first device"
    );
}

#[test]
fn bad_and_duplicate_addresses_are_refused_with_a_reason() {
    let (_a, mut b, _) = pair("da-refuse");
    open_address_list(&mut b);
    add_address(&mut b, "not an address");
    assert!(render(&b, 120, 40).contains("ip:port"), "invalid");
    assert_eq!(state(&b).manual_devices().count(), 0);
    press(&mut b, KeyCode::Esc);
    add_address(&mut b, "169.254.169.254:80");
    assert!(
        render(&b, 120, 40).contains("cannot reach"),
        "never dialable"
    );
    press(&mut b, KeyCode::Esc);
    add_address(&mut b, "127.0.0.1:9");
    press(&mut b, KeyCode::Esc);
    assert_eq!(state(&b).manual_devices().count(), 1);
    add_address(&mut b, "127.0.0.1:9");
    assert!(render(&b, 120, 40).contains("Already added"), "duplicate");
    assert_eq!(state(&b).manual_devices().count(), 1);
}

#[test]
fn deleting_an_address_asks_first_and_stops_the_dialing() {
    let (a, mut b, _) = pair("da-delete");
    open_address_list(&mut b);
    add_address(&mut b, "127.0.0.1:9");
    assert_eq!(state(&b).manual_devices().count(), 1);
    press(&mut b, KeyCode::Delete);
    assert!(render(&b, 120, 40).contains("Remove this address?"));
    press(&mut b, KeyCode::Esc);
    assert_eq!(state(&b).manual_devices().count(), 1, "cancel keeps it");
    press(&mut b, KeyCode::Enter);
    press(&mut b, KeyCode::Delete);
    press(&mut b, KeyCode::Enter);
    assert_eq!(state(&b).manual_devices().count(), 0);
    drop(a);
}

#[test]
fn a_foreign_account_at_the_address_is_turned_away_at_the_handshake() {
    let (other, _, _) = announcing_device(
        "da-foreign-a",
        beacon(free_udp_port(), free_udp_port()),
        &["secret"],
    );
    let mine = make_vault(&temp_dir("da-foreign-mine"));
    let mut b = restore_empty(
        &temp_dir("da-foreign-b"),
        &mine,
        PASSWORD,
        beacon(free_udp_port(), free_udp_port()),
    );
    let identity = {
        let phrase = common::phrase(&mine);
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        local::SyncIdentity::enroll(phrase.seed(), &client_id, [9; 16], u64::MAX).unwrap()
    };
    assert_eq!(
        p2p_net::fetch_personal(&identity, &address_of(&other), true).unwrap_err(),
        p2p_net::FetchError::Refused,
        "the handshake turns a foreign account away"
    );
    open_address_list(&mut b);
    add_address(&mut b, &address_of(&other));
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        tick(&mut b, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(b.screen.name(), "unlocked", "{}", render(&b, 120, 40));
    assert!(
        is_placeholder(&b),
        "nothing was adopted\n{}",
        render(&b, 120, 40)
    );
    assert!(titles_of(&b).is_empty());
}

#[test]
fn the_restore_sync_modal_opens_on_empty_restore_and_can_be_cancelled() {
    let (_a, mut b, _) = pair("da-guidance");
    for width in [80, 140] {
        let screen = render(&b, width, 30);
        assert!(screen.contains("p2p sync // restore"), "{width}: {screen}");
        assert!(
            !screen.contains("Sync starts when this device finds your other one"),
            "{width}: {screen}"
        );
    }
    press(&mut b, KeyCode::Enter);
    assert!(
        render(&b, 140, 30).contains("p2p sync // restore"),
        "Enter does not close the modal"
    );
    press(&mut b, KeyCode::Char('c'));
    assert!(
        render(&b, 140, 30).contains("p2p sync // restore"),
        "c does not close the modal"
    );
    press(&mut b, KeyCode::Char(','));
    assert!(
        render(&b, 140, 30).contains("p2p sync // restore"),
        "comma does not close the modal"
    );
    press(&mut b, KeyCode::Esc);
    assert!(!render(&b, 140, 30).contains("p2p sync // restore"));
}
