//! Alice removes Bob from a shared vault through the interface. The vault
//! rotates, Carol picks up the new key when she checks in, and Bob does not.

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
use record::{Document, TAG_TITLE};
use session::write_record;
use tui::app::flows::home::Filter;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::App;

use common::{
    app, keep_to_this_device, make_vault, press, render, temp_dir, tick, type_text, unlock, wait,
    PASSWORD,
};

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn share(app: &App) -> &ShareState {
    let View::Sync(share) = &state(app).view else {
        panic!("not on the share screen")
    };
    share
}

fn signed_in(tag: &str) -> App {
    let base = temp_dir(tag);
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    app
}

fn until(app: &mut App, what: &str, mut done: impl FnMut(&App) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done(app) {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tick(app, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `guest` copies their key, `owner` adds them as a writer and hands back the
/// invitation, `guest` pastes it and syncs the vault.
fn bring_in(owner: &mut App, guest: &mut App) {
    press(guest, KeyCode::Char('S'));
    let key = share(guest).me.as_ref().unwrap().text.to_string();
    press(owner, KeyCode::Char('a'));
    owner.on_paste(&key);
    press(owner, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share(owner).step else {
        panic!("not done")
    };
    let invitation = invitation.to_string();
    press(owner, KeyCode::Esc);
    press(guest, KeyCode::Char('j'));
    guest.on_paste(&invitation);
    press(guest, KeyCode::Enter);
    wait(guest);
    until(guest, "the vault to arrive", |app| {
        state(app).shared[0].ready()
    });
}

fn titles(app: &App) -> Vec<String> {
    let state = state(app);
    let mut found: Vec<String> = state.shared[0]
        .cache
        .iter()
        .map(|summary| summary.display_title().to_owned())
        .collect();
    found.sort();
    found
}

#[test]
fn removing_a_person_rotates_the_key_and_only_the_others_receive_it() {
    let mut alice = signed_in("rm-alice");
    let mut bob = signed_in("rm-bob");
    let mut carol = signed_in("rm-carol");

    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "Family");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    write_shared(&mut alice, "before");
    bring_in(&mut alice, &mut bob);
    bring_in(&mut alice, &mut carol);
    assert_eq!(titles(&bob), ["before"]);
    assert_eq!(titles(&carol), ["before"]);
    assert_eq!(state(&alice).shared[0].people, 3);

    // Alice picks Bob by his fingerprint and confirms.
    let bobs_print = share(&bob).me.as_ref().unwrap().print.to_string();
    press(&mut alice, KeyCode::Char('x'));
    assert!(matches!(share(&alice).step, Step::PickPerson(0)));
    let people = state(&alice).people(0);
    assert_eq!(people.len(), 2);
    let bob_at = people
        .iter()
        .position(|person| person.print.to_string() == bobs_print)
        .expect("Bob is listed");
    for _ in 0..bob_at {
        press(&mut alice, KeyCode::Down);
    }
    let screen = render(&alice, 100, 30);
    assert!(
        screen.contains(bobs_print.split(' ').next().unwrap()),
        "{screen}"
    );
    press(&mut alice, KeyCode::Enter);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("new key"), "{screen}");
    assert!(screen.contains("Enter removes"), "{screen}");
    press(&mut alice, KeyCode::Enter);

    let item = &state(&alice).shared[0];
    assert_eq!(item.reference.epoch, 1);
    assert_eq!(item.reference.retired.len(), 1);
    assert_eq!(item.people, 2);
    assert!(matches!(share(&alice).step, Step::Overview));
    write_shared(&mut alice, "after");

    // Carol checks in: she authenticates as a member, is handed the new key
    // and the rotated vault, and sees the new record.
    press(&mut carol, KeyCode::Char('r'));
    until(&mut carol, "the new key", |app| {
        state(app).shared[0].reference.epoch == 1
    });
    assert_eq!(titles(&carol), ["after", "before"]);
    assert!(!state(&carol).shared[0].stale);

    // Bob checks in with the old seed and is turned away; he keeps what he
    // had and nothing new.
    press(&mut bob, KeyCode::Char('r'));
    until(&mut bob, "the refusal", |app| {
        state(app).shared[0].waiting.is_some()
    });
    assert_eq!(titles(&bob), ["before"]);
    assert_eq!(state(&bob).shared[0].reference.epoch, 0);
    let screen = render(&bob, 100, 30);
    assert!(screen.contains("refused"), "{screen}");

    // Back on the home view, Carol's list shows the record written after the
    // rotation.
    press(&mut carol, KeyCode::Esc);
    let Screen::Unlocked(unlocked) = &mut carol.screen else {
        panic!()
    };
    let id = unlocked.shared[0].reference.vault_id;
    unlocked.home.filter = Filter::Shared(id, "Family".into());
    let screen = render(&carol, 110, 30);
    assert!(screen.contains("after"), "{screen}");

    // Locking drops everything; unlocking again finds the new key stored in
    // Carol's personal vault, and the rotated vault opens with it.
    press(&mut carol, KeyCode::Char('L'));
    assert!(matches!(carol.screen, Screen::Locked(_)));
    press(&mut carol, KeyCode::Enter);
    unlock(&mut carol, PASSWORD);
    let reopened = &state(&carol).shared[0];
    assert!(reopened.ready());
    assert!(!reopened.stale);
    assert_eq!(reopened.reference.epoch, 1);
    assert_eq!(titles(&carol), ["after", "before"]);
}

fn write_shared(app: &mut App, title: &str) {
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!()
    };
    let reference = std::sync::Arc::clone(&state.shared[0].reference);
    let vault = state.shared[0].vault_mut().unwrap();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    vault.persist(&reference.seed).unwrap();
    let cache = tui::vault::records::build_cache(&vault.session).unwrap();
    state.shared[0].cache = cache;
}

#[test]
fn nothing_is_offered_when_there_is_no_one_to_remove() {
    let mut alice = signed_in("rm-solo");
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('x'));
    assert!(matches!(share(&alice).step, Step::Overview), "no vault yet");
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "Solo");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    press(&mut alice, KeyCode::Char('x'));
    assert!(
        matches!(share(&alice).step, Step::Overview),
        "no one else is in it"
    );
}
