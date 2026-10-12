//! A restore with no vault file starts an empty vault of its own, and the
//! account's vault arrives once another device is found by its beacon. Driven
//! with real keystrokes against two apps, with the beacons carried over
//! loopback unicast instead of multicast.

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
use tui::vault::discover::discover;

use common::{
    announcing_device, beacon, ctrl, free_udp_port, is_placeholder, make_vault, press, render,
    restore_empty, temp_dir, tick, titles_of, type_text, unlock, wait, wait_adopted, PASSWORD,
};

const FOUND_WITHIN: Duration = Duration::from_secs(60);
const OTHER_PASSWORD: &str = "another-long-password-for-B-77";

#[test]
fn an_empty_restore_finds_the_announcing_device_and_brings_the_vault_in() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, _) = announcing_device(
        "bc-first",
        beacon(first_bind, second_bind),
        &["wifi", "bank"],
    );
    let base = temp_dir("bc-second");
    let mut second = restore_empty(&base, &words, PASSWORD, beacon(second_bind, first_bind));
    assert!(is_placeholder(&second), "an empty vault of its own first");
    assert!(titles_of(&second).is_empty());
    let before = discover(&base);
    assert_eq!(before.len(), 1);

    wait_adopted(&mut second, FOUND_WITHIN);
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
    let after = discover(&base);
    assert_eq!(after.len(), 1, "the placeholder is gone");
    assert_ne!(after[0].vault_id, before[0].vault_id);
    assert!(
        after[0].paths.peers_store().is_file(),
        "the device is remembered"
    );

    // The password it was restored with opens the account's vault.
    press(&mut second, KeyCode::Char('L'));
    press(&mut second, KeyCode::Enter);
    assert_eq!(second.screen.name(), "unlock");
    unlock(&mut second, PASSWORD);
    assert_eq!(titles_of(&second), ["bank", "wifi"]);
}

#[test]
fn a_device_of_another_account_brings_nothing() {
    let (second_bind, other_bind) = (free_udp_port(), free_udp_port());
    let (_other, _words, _) =
        announcing_device("bc-other", beacon(other_bind, second_bind), &["secret"]);
    let mine = make_vault(&temp_dir("bc-mine"));
    let mut second = restore_empty(
        &temp_dir("bc-second-b"),
        &mine,
        PASSWORD,
        beacon(second_bind, other_bind),
    );
    let until = Instant::now() + Duration::from_secs(4);
    while Instant::now() < until {
        tick(&mut second, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(is_placeholder(&second));
    assert!(titles_of(&second).is_empty());
}

#[test]
fn another_password_on_the_other_device_says_so_and_stops() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, _) =
        announcing_device("bc-pw-first", beacon(first_bind, second_bind), &["wifi"]);
    let base = temp_dir("bc-pw-second");
    let mut second = restore_empty(
        &base,
        &words,
        OTHER_PASSWORD,
        beacon(second_bind, first_bind),
    );
    let until = Instant::now() + FOUND_WITHIN;
    let mut screen = String::new();
    while Instant::now() < until && !screen.contains("different password") {
        tick(&mut second, Duration::from_millis(50));
        second.wait_for_job(Duration::from_millis(50));
        screen = render(&second, 140, 50);
    }
    assert!(screen.contains("different password"), "{screen}");
    assert!(is_placeholder(&second), "nothing was replaced");
    assert!(titles_of(&second).is_empty());
}

#[test]
fn a_placeholder_that_already_holds_a_record_is_never_replaced() {
    let (second_bind, first_bind) = (free_udp_port(), free_udp_port());
    let (_first, words, _) =
        announcing_device("bc-keep-first", beacon(first_bind, second_bind), &["wifi"]);
    let base = temp_dir("bc-keep-second");
    let mut second = restore_empty(&base, &words, PASSWORD, beacon(second_bind, first_bind));
    press(&mut second, KeyCode::Char('n'));
    type_text(&mut second, "Mine");
    for _ in 0..4 {
        press(&mut second, KeyCode::Tab);
    }
    type_text(&mut second, "S3cure-Pa55!word");
    second.on_key(&ctrl('s'));
    wait(&mut second);
    assert_eq!(titles_of(&second), ["Mine"]);

    let until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < until {
        tick(&mut second, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(is_placeholder(&second));
    assert_eq!(titles_of(&second), ["Mine"]);
}
