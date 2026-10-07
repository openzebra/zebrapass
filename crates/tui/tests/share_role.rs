//! An owner changes a role through the interface; the member sees it and
//! their writes stop. Shared records keep a history.

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
use memberlog::Role;
use record::{Document, TAG_TITLE};
use session::write_record;
use tui::app::flows::home::Filter;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::App;

use common::{app, make_vault, press, render, temp_dir, tick, type_text, unlock, wait, PASSWORD};

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

fn write_shared(app: &mut App, title: &str) -> u32 {
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!()
    };
    let reference = std::sync::Arc::clone(&state.shared[0].reference);
    let vault = state.shared[0].vault_mut().unwrap();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    let id = write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    vault.persist(&reference.seed).unwrap();
    let cache = tui::vault::records::build_cache(&vault.session).unwrap();
    state.shared[0].cache = cache;
    id
}

fn owner_and_writer() -> (App, App) {
    let mut alice = signed_in("role-alice");
    let mut bob = signed_in("role-bob");
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "Family");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    write_shared(&mut alice, "before");
    bring_in(&mut alice, &mut bob);
    (alice, bob)
}

#[test]
fn an_owner_makes_a_writer_a_reader_and_the_member_sees_it() {
    let (mut alice, mut bob) = owner_and_writer();
    assert_eq!(state(&bob).shared[0].my_role, Some(Role::Writer));

    // A writer cannot start the flow.
    press(&mut bob, KeyCode::Char('c'));
    assert!(matches!(share(&bob).step, Step::Overview));

    press(&mut alice, KeyCode::Char('c'));
    assert!(matches!(share(&alice).step, Step::PickRole(0)));
    press(&mut alice, KeyCode::Enter);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("new role"), "{screen}");
    // Confirming without picking another role changes nothing.
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(share(&alice).step, Step::RoleConfirm { .. }));
    press(&mut alice, KeyCode::Left);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("reader"), "{screen}");
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(share(&alice).step, Step::Overview));
    assert_eq!(state(&alice).people(0)[0].role, Role::Reader);

    // Bob's next check-in brings the new entry, and his screen follows.
    press(&mut bob, KeyCode::Char('r'));
    until(&mut bob, "the role change", |app| {
        state(app).shared[0].my_role == Some(Role::Reader)
    });
    press(&mut bob, KeyCode::Esc);
    let Screen::Unlocked(unlocked) = &mut bob.screen else {
        panic!()
    };
    let id = unlocked.shared[0].reference.vault_id;
    unlocked.home.filter = Filter::Shared(id, "Family".into());
    press(&mut bob, KeyCode::Char('n'));
    let screen = render(&bob, 100, 30);
    assert!(
        screen.contains("read this vault, not change it"),
        "{screen}"
    );
}

#[test]
fn an_owner_can_make_a_second_owner() {
    let (mut alice, _bob) = owner_and_writer();
    // Make Bob an owner: Right from writer.
    press(&mut alice, KeyCode::Char('c'));
    press(&mut alice, KeyCode::Enter);
    press(&mut alice, KeyCode::Right);
    press(&mut alice, KeyCode::Enter);
    assert_eq!(state(&alice).people(0)[0].role, Role::Owner);
}

#[test]
fn a_shared_record_keeps_a_history_that_can_be_read() {
    let (mut alice, _bob) = owner_and_writer();
    press(&mut alice, KeyCode::Esc);
    let Screen::Unlocked(unlocked) = &mut alice.screen else {
        panic!()
    };
    let id = unlocked.shared[0].reference.vault_id;
    unlocked.home.filter = Filter::Shared(id, "Family".into());
    unlocked.load_detail();
    press(&mut alice, KeyCode::Char('h'));
    assert!(
        matches!(state(&alice).view, View::History(_)),
        "{}",
        render(&alice, 100, 30)
    );
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("created"), "{screen}");
}

fn allow_loopback(app: &App) {
    state(app)
        .p2p
        .as_deref()
        .unwrap()
        .provider
        .allow_loopback_peers();
}

#[test]
fn the_only_owner_is_told_to_name_another_owner_first() {
    let (mut alice, _bob) = owner_and_writer();
    press(&mut alice, KeyCode::Char('d'));
    assert!(matches!(share(&alice).step, Step::Overview));
    assert_eq!(state(&alice).shared.len(), 1);
}

/// Bob leaves; Alice fetches that from him; Bob's copy is gone and Alice has
/// seen it.
fn bob_leaves_and_alice_learns(alice: &mut App, bob: &mut App) {
    use p2p_net::Provider;
    allow_loopback(alice);
    let vault = state(alice).shared[0].reference.vault_id;

    // Alice learns where Bob can be reached.
    press(bob, KeyCode::Char('r'));
    let found = |app: &App| {
        !state(app)
            .p2p
            .as_deref()
            .unwrap()
            .provider
            .peer_hints(&vault)
            .is_empty()
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    while !found(alice) {
        assert!(
            Instant::now() < deadline,
            "Alice never learned Bob's address"
        );
        tick(bob, Duration::from_millis(50));
        tick(alice, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }

    // Bob leaves. The vault stays, shown as left.
    press(bob, KeyCode::Char('d'));
    assert!(matches!(share(bob).step, Step::LeaveConfirm(_)));
    let screen = render(bob, 100, 30);
    assert!(screen.contains("Enter leaves"), "{screen}");
    press(bob, KeyCode::Enter);
    assert!(matches!(share(bob).step, Step::Overview));
    assert_eq!(state(bob).shared.len(), 1, "kept until a member has it");
    assert_eq!(state(bob).shared[0].my_role, None);
    let screen = render(bob, 100, 30);
    assert!(screen.contains("left"), "{screen}");

    // Alice checks in with the members, fetches Bob's log, and Bob's copy goes.
    press(alice, KeyCode::Char('r'));
    let deadline = Instant::now() + Duration::from_secs(90);
    while !state(bob).shared.is_empty() {
        assert!(Instant::now() < deadline, "Bob's copy was never deleted");
        tick(alice, Duration::from_millis(50));
        tick(bob, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    until(alice, "Bob gone from Alice's list", |app| {
        state(app).people(0).is_empty()
    });
}

#[test]
fn a_member_leaves_stays_until_it_is_fetched_then_is_gone() {
    let (mut alice, mut bob) = owner_and_writer();
    bob_leaves_and_alice_learns(&mut alice, &mut bob);

    // It stays gone: nothing points at it any more after a lock and unlock.
    press(&mut bob, KeyCode::Esc);
    press(&mut bob, KeyCode::Char('L'));
    assert!(matches!(bob.screen, Screen::Locked(_)));
    press(&mut bob, KeyCode::Enter);
    unlock(&mut bob, PASSWORD);
    assert!(state(&bob).shared.is_empty());
}

#[test]
fn after_someone_leaves_the_owner_is_told_and_can_replace_the_key() {
    let (mut alice, mut bob) = owner_and_writer();
    assert_eq!(state(&alice).shared[0].leaves, 0);
    bob_leaves_and_alice_learns(&mut alice, &mut bob);
    assert_eq!(state(&alice).shared[0].leaves, 1);
    let screen = render(&alice, 110, 30);
    assert!(screen.contains("k replaces the key"), "{screen}");

    press(&mut alice, KeyCode::Char('k'));
    assert!(matches!(share(&alice).step, Step::RekeyConfirm));
    let screen = render(&alice, 110, 30);
    assert!(screen.contains("Enter replaces the key"), "{screen}");
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(share(&alice).step, Step::Overview));
    let item = &state(&alice).shared[0];
    assert_eq!(item.reference.epoch, 1);
    assert_eq!(item.leaves, 0);
    assert!(item.ready());
    let screen = render(&alice, 110, 30);
    assert!(!screen.contains("k replaces the key"), "{screen}");
}

#[test]
fn only_an_owner_can_replace_the_key() {
    let (_alice, mut bob) = owner_and_writer();
    press(&mut bob, KeyCode::Char('k'));
    assert!(matches!(share(&bob).step, Step::Overview));
    assert_eq!(state(&bob).shared[0].reference.epoch, 0);
}
