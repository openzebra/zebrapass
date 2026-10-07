//! A writer changes a shared vault from the interface and the change reaches
//! the owner's device; a reader is told it cannot.

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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use local::{create_shared_vault, join_shared_vault, open_shared_vault, SharedRef, SyncIdentity};
use memberlog::{Action, Role};
use p2p_net::{Service, SharedProvider};
use session::{list_records, open_record, KdfProfile};
use sharing::{ContactCard, Invitation, Inviter, Offer};
use tui::app::flows::home::Filter;
use tui::app::screen::Screen;
use tui::vault::open::{unlock_vault, Credential};
use tui::App;
use zeroize::Zeroizing;

use common::{app, ctrl, make_vault, press, render, settle, tick, type_text, unlock, PASSWORD};

fn unlocked(app: &App) -> &tui::app::flows::unlocked::Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

struct World {
    alice_dir: PathBuf,
    alice: Arc<SyncIdentity>,
    alice_ref: SharedRef,
    bob: App,
    _node: Service,
}

fn now() -> u64 {
    p2p_net::now_ms()
}

/// Alice's records; an unreadable moment (her node is mid-write) is empty.
fn titles_on_alice(world: &World) -> Vec<String> {
    let Ok(vault) = open_shared_vault(&world.alice_dir, &world.alice_ref, &world.alice) else {
        return Vec::new();
    };
    list_records(&vault.session)
        .unwrap()
        .iter()
        .map(|row| {
            open_record(&vault.session, row.id)
                .unwrap()
                .text(record::TAG_TITLE)
                .unwrap()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn bobs_identity(base: &Path) -> (tui::vault::Vault, SyncIdentity) {
    make_vault(base);
    let found = tui::vault::discover::discover(base);
    let paths = found.into_iter().next().unwrap().paths;
    let vault = unlock_vault(
        paths,
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    let identity = SyncIdentity::load(
        &vault.paths.sync_identity(),
        &vault.session.sync_identity_key().unwrap(),
    )
    .unwrap();
    (*vault, identity)
}

/// Alice owns "Family"; Bob has joined it as `role`, is unlocked in his app
/// and has the vault open.
fn world(role: Role) -> World {
    let (alice_dir, bob_dir) = (common::temp_dir("alice"), common::temp_dir("bob"));
    let alice = Arc::new(SyncIdentity::enroll(&[1; 64], &[1; 64], [1; 16], u64::MAX).unwrap());
    let (shared, alice_ref) =
        create_shared_vault(&alice_dir, &alice, "Family", KdfProfile::Fast).unwrap();
    drop(shared);
    let provider = Arc::new(SharedProvider::new(alice_dir.clone(), Arc::clone(&alice)));
    provider.serve(Arc::new(alice_ref.duplicate()));
    let node = Service::start(Some("127.0.0.1:0"), provider).unwrap();
    let hint = node.local_addr().unwrap().to_string();

    let (mut bob_vault, bob) = bobs_identity(&bob_dir);
    let publics = bob.share_publics().unwrap();
    let card = ContactCard::issue(
        &bob.sign_key(),
        &bob.devices()[0],
        bob.root_vk(),
        publics.ec_pub,
        &publics.kem_ek[..],
        now(),
    )
    .unwrap();
    let mut vault = open_shared_vault(&alice_dir, &alice_ref, &alice).unwrap();
    let add = Action::Add {
        client_id: card.cert.client_id,
        root_vk: card.root_vk.clone(),
        role,
    };
    let entry = vault
        .log
        .propose(&alice.sign_key(), &alice.devices()[0], add, now())
        .unwrap();
    vault.log.append(entry).unwrap();
    vault.save_log(&alice_ref.seed).unwrap();
    let key = alice.sign_key();
    let text = Invitation::issue(
        &Inviter {
            sign: &key,
            cert: &alice.devices()[0],
        },
        &vault.log,
        &card,
        &Offer {
            seed: &alice_ref.seed,
            name: "Family",
            hints: std::slice::from_ref(&hint),
        },
        now(),
    )
    .unwrap()
    .to_text()
    .unwrap();
    let invitation = Invitation::from_text(&text).unwrap();
    let opened = invitation
        .open(
            &bob.share_keys().ec_secret().unwrap(),
            bob.share_keys().kem_seed(),
            &card,
            now(),
        )
        .unwrap();
    let reference = SharedRef {
        vault_id: invitation.vault_id,
        anchor: *opened.log.anchor(),
        seed: opened.seed,
        name: opened.name,
        hints: opened.hints,
        epoch: 0,
        retired: Vec::new(),
    };
    join_shared_vault(&bob_dir, &reference, &opened.log).unwrap();
    session::write_record(
        &mut bob_vault.session,
        &mut bob_vault.file,
        None,
        &reference.to_document(),
    )
    .unwrap();
    bob_vault.persist().unwrap();
    drop(bob_vault);

    let mut bob_app = app(&bob_dir);
    unlock(&mut bob_app, PASSWORD);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !unlocked(&bob_app).shared[0].ready() {
        assert!(Instant::now() < deadline, "the vault never arrived");
        tick(&mut bob_app, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    let id = unlocked(&bob_app).shared[0].reference.vault_id;
    let Screen::Unlocked(state) = &mut bob_app.screen else {
        panic!("not unlocked")
    };
    state.home.filter = Filter::Shared(id, "Family".into());
    state.load_detail();
    World {
        alice_dir,
        alice,
        alice_ref,
        bob: bob_app,
        _node: node,
    }
}

#[test]
fn a_writer_adds_a_record_and_it_reaches_the_owner() {
    let mut w = world(Role::Writer);
    press(&mut w.bob, KeyCode::Char('n'));
    type_text(&mut w.bob, "Router");
    w.bob.on_key(&ctrl('s'));
    settle(&mut w.bob);
    let screen = render(&w.bob, 120, 40);
    assert!(screen.contains("Router"), "{screen}");

    let deadline = Instant::now() + Duration::from_secs(90);
    while titles_on_alice(&w) != ["Router"] {
        assert!(Instant::now() < deadline, "Alice never received it");
        tick(&mut w.bob, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_reader_is_told_it_cannot_change_the_vault() {
    let mut w = world(Role::Reader);
    press(&mut w.bob, KeyCode::Char('n'));
    assert!(
        matches!(unlocked(&w.bob).view, tui::app::flows::unlocked::View::Home),
        "no editor opens for a reader"
    );
    let screen = render(&w.bob, 120, 40);
    assert!(screen.contains("read this vault"), "{screen}");
    settle(&mut w.bob);
    assert!(titles_on_alice(&w).is_empty());
}
