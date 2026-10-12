//! A shared vault appears in the interface by itself: Bob's app unlocks, his
//! node asks Alice's device for the vault, the cryptography checks out, and
//! the vault shows up under Shared with its records.

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

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{
    create_shared_vault, join_shared_vault, open_shared_vault, Introduction, SharedRef,
    SyncIdentity,
};
use memberlog::{Action, Role};
use p2p_net::{Service, SharedProvider};
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{write_record, KdfProfile};
use sharing::{ContactCard, Invitation, Inviter, Offer};
use tui::app::flows::home::Filter;
use tui::app::screen::Screen;
use tui::vault::open::{unlock_vault, Credential};
use tui::App;
use zeroize::Zeroizing;

use common::{app, keep_to_this_device, make_vault, render, tick, unlock, PASSWORD};

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

fn unlocked(app: &App) -> &tui::app::flows::unlocked::Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn now() -> u64 {
    p2p_net::now_ms()
}

/// Bob's personal vault on disk, locked, and his identity.
fn bobs_vault(base: &Path) -> (tui::vault::Vault, SyncIdentity) {
    make_vault(base);
    keep_to_this_device(base);
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

#[test]
fn the_shared_vault_appears_and_fills_in_when_the_sync_completes() {
    let (alice_dir, bob_dir) = (common::temp_dir("alice"), common::temp_dir("bob"));

    // Alice: an identity, a shared vault with two records, and a node.
    let alice = Arc::new(SyncIdentity::enroll(&[1; 64], &[1; 64], [1; 16], u64::MAX).unwrap());
    let (mut shared, alice_ref) =
        create_shared_vault(&alice_dir, &alice, "Family", KdfProfile::Fast).unwrap();
    write_record(&mut shared.session, &mut shared.file, None, &titled("wifi")).unwrap();
    write_record(&mut shared.session, &mut shared.file, None, &titled("bank")).unwrap();
    shared.persist(&alice_ref.seed).unwrap();
    let provider = Arc::new(SharedProvider::new(alice_dir.clone(), Arc::clone(&alice)));
    provider.serve(Arc::new(SharedRef {
        vault_id: alice_ref.vault_id,
        anchor: alice_ref.anchor,
        seed: Secret::new(*alice_ref.seed.expose()),
        name: alice_ref.name.clone(),
        hints: Vec::new(),
        epoch: 0,
        retired: Vec::new(),
        introduction: None,
    }));
    let node = Service::start(Some("127.0.0.1:0"), provider).unwrap();
    let hint = node.local_addr().unwrap().to_string();

    // Bob: a real personal vault; he gives Alice his card.
    let (mut bob_vault, bob) = bobs_vault(&bob_dir);
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

    // Alice adds him and hands back an invitation carrying her address.
    let mut vault = open_shared_vault(&alice_dir, &alice_ref, &alice).unwrap();
    let add = Action::Add {
        client_id: card.cert.client_id,
        root_vk: card.root_vk.clone(),
        role: Role::Writer,
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

    // Bob pastes it: his vault stores the reference and the log. Nothing else
    // yet.
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
        introduction: Some(Introduction {
            head: opened.head,
            inviter_id: opened.inviter_id,
            inviter_vk: opened.inviter_vk,
        }),
    };
    join_shared_vault(&bob_dir, &reference, &opened.log).unwrap();
    write_record(
        &mut bob_vault.session,
        &mut bob_vault.file,
        None,
        &reference.to_document(),
    )
    .unwrap();
    bob_vault.persist().unwrap();
    drop(bob_vault);

    // Bob opens the app. The shared vault is listed at once, still syncing...
    let mut bob_app = app(&bob_dir);
    unlock(&mut bob_app, PASSWORD);
    assert_eq!(unlocked(&bob_app).shared.len(), 1);
    assert_eq!(
        unlocked(&bob_app).cache.len(),
        0,
        "the reference is not a login"
    );
    let screen = render(&bob_app, 120, 40);
    assert!(screen.contains("Shared"), "{screen}");
    assert!(screen.contains("Family"), "{screen}");
    let row = |screen: &str| {
        screen
            .lines()
            .skip_while(|line| !line.contains(" Shared"))
            .find(|line| line.contains("Family"))
            .unwrap_or_default()
            .to_owned()
    };
    assert!(row(&screen).contains("sync"), "{screen}");

    // ...and fills in on its own once the node has fetched and verified it.
    let deadline = Instant::now() + Duration::from_secs(90);
    while !unlocked(&bob_app).shared[0].ready() {
        assert!(Instant::now() < deadline, "the vault never arrived");
        tick(&mut bob_app, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
    let name = unlocked(&bob_app).shared[0].name().to_owned();
    let id = unlocked(&bob_app).shared[0].reference.vault_id;
    let Screen::Unlocked(state) = &mut bob_app.screen else {
        panic!("not unlocked")
    };
    state.home.filter = Filter::Shared(id, name.into());
    state.load_detail();
    let screen = render(&bob_app, 120, 40);
    assert!(screen.contains("wifi"), "{screen}");
    assert!(screen.contains("bank"), "{screen}");
    assert!(!row(&screen).contains("sync"), "{screen}");
    assert!(
        row(&screen).trim_end().ends_with('2') || row(&screen).contains(" 2 "),
        "{screen}"
    );
}
