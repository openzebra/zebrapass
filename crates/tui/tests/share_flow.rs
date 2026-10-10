//! Two people, two apps, real keys and pastes: Bob copies his key, Alice
//! makes a vault and adds him, Bob pastes the invitation, and the vault
//! syncs into his interface.

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

#[test]
fn bob_and_alice_share_a_vault_through_the_interface() {
    let mut alice = signed_in("alice");
    let mut bob = signed_in("bob");

    // Bob opens Share: his key and its fingerprint, nothing else.
    press(&mut bob, KeyCode::Char('S'));
    let screen = render(&bob, 100, 30);
    assert!(screen.contains("your key"), "{screen}");
    assert!(screen.contains("none yet"), "{screen}");
    let bobs_print = share(&bob).me.as_ref().unwrap().print.to_string();
    press(&mut bob, KeyCode::Enter);
    assert!(
        !bob.ctx.clipboard.outbox().is_empty(),
        "Enter copies the key"
    );
    let bobs_key = share(&bob).me.as_ref().unwrap().text.to_string();
    assert!(bobs_key.starts_with("zp-card1:"));

    // Alice makes a vault called Family.
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "Family");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("Family"), "{screen}");
    assert!(screen.contains("owner"), "{screen}");
    assert!(
        screen.contains("listening"),
        "the node shows where it listens: {screen}"
    );

    // Something worth syncing sits in it.
    {
        let Screen::Unlocked(state) = &mut alice.screen else {
            panic!()
        };
        let seed = std::sync::Arc::clone(&state.shared[0].reference);
        let vault = state.shared[0].vault_mut().unwrap();
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, "wifi password");
        write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
        vault.persist(&seed.seed).unwrap();
    }

    // Alice adds Bob: paste his key, compare the fingerprint, pick Writer.
    press(&mut alice, KeyCode::Char('a'));
    assert!(matches!(share(&alice).step, Step::PasteCard));
    alice.on_paste(&bobs_key);
    let screen = render(&alice, 100, 30);
    let first_group = bobs_print.split(' ').next().unwrap();
    assert!(
        screen.contains(first_group),
        "Bob's fingerprint is shown: {screen}"
    );
    assert!(screen.contains("writer"), "{screen}");
    press(&mut alice, KeyCode::Right);
    assert!(render(&alice, 100, 30).contains("owner"));
    press(&mut alice, KeyCode::Left);
    press(&mut alice, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share(&alice).step else {
        panic!("not done")
    };
    let invitation = invitation.to_string();
    assert!(invitation.starts_with("zp-invite1:"));
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("vault number"), "{screen}");
    press(&mut alice, KeyCode::Enter);
    assert!(!alice.ctx.clipboard.outbox().is_empty());
    press(&mut alice, KeyCode::Esc);

    // Bob joins: paste, compare, confirm.
    press(&mut bob, KeyCode::Char('j'));
    assert!(matches!(share(&bob).step, Step::PasteInvite));
    bob.on_paste(&invitation);
    let screen = render(&bob, 100, 30);
    assert!(screen.contains("Family"), "{screen}");
    assert!(screen.contains("vault number"), "{screen}");
    assert!(screen.contains("must match"), "{screen}");
    press(&mut bob, KeyCode::Enter);
    wait(&mut bob);
    assert_eq!(state(&bob).shared.len(), 1);

    // His node fetches it; the vault fills in on its own.
    let deadline = Instant::now() + Duration::from_secs(90);
    while !state(&bob).shared[0].ready() {
        assert!(Instant::now() < deadline, "the vault never arrived");
        tick(&mut bob, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    let screen = render(&bob, 100, 30);
    assert!(screen.contains("synced"), "{screen}");
    press(&mut bob, KeyCode::Esc);
    let (id, name) = {
        let item = &state(&bob).shared[0];
        (item.reference.vault_id, item.name().to_owned())
    };
    let Screen::Unlocked(unlocked) = &mut bob.screen else {
        panic!()
    };
    unlocked.home.filter = Filter::Shared(id, name.into());
    unlocked.load_detail();
    let screen = render(&bob, 120, 40);
    assert!(screen.contains("wifi password"), "{screen}");
}

#[test]
fn a_garbage_paste_is_refused_and_nothing_changes() {
    let mut alice = signed_in("garbage");
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('j'));
    alice.on_paste("this is not an invitation");
    assert!(matches!(share(&alice).step, Step::PasteInvite));
    assert!(state(&alice).shared.is_empty());
    press(&mut alice, KeyCode::Esc);
    assert!(matches!(share(&alice).step, Step::Overview));
    press(&mut alice, KeyCode::Char('a'));
    assert!(
        matches!(share(&alice).step, Step::Overview),
        "nothing to add people to yet"
    );
    press(&mut alice, KeyCode::Esc);
    assert_eq!(alice.screen.name(), "unlocked");
}

#[test]
fn the_listening_choice_cycles_and_is_always_visible() {
    let mut alice = signed_in("listen");
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "Home");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("local network"), "{screen}");
    assert!(
        !screen.contains("announced"),
        "the beacon is off by default"
    );
    press(&mut alice, KeyCode::Char('l'));
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("local network, announced"), "{screen}");
    assert!(
        state(&alice)
            .p2p
            .as_deref()
            .unwrap()
            .service
            .local_addr()
            .is_some(),
        "the beacon mode listens like the network mode"
    );
    press(&mut alice, KeyCode::Char('l'));
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("this device only"), "{screen}");
    assert!(screen.contains("127.0.0.1"), "{screen}");
    press(&mut alice, KeyCode::Char('l'));
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("fetch only · pulls every 15 s"), "{screen}");
    assert!(
        state(&alice)
            .p2p
            .as_deref()
            .unwrap()
            .service
            .local_addr()
            .is_none(),
        "fetch only listens nowhere"
    );
    press(&mut alice, KeyCode::Char('l'));
    wait(&mut alice);
    let screen = render(&alice, 100, 30);
    assert!(screen.contains("off"), "{screen}");
    assert!(screen.contains("not listening"), "{screen}");
    assert!(state(&alice)
        .p2p
        .as_deref()
        .unwrap()
        .service
        .local_addr()
        .is_none());
    // Adding someone needs an address they can reach.
    press(&mut alice, KeyCode::Char('a'));
    assert!(matches!(share(&alice).step, Step::Overview));
}
