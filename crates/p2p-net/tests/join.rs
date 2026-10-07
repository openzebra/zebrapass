#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use local::{
    create_shared_vault, is_pending, join_shared_vault, open_shared_vault, Introduction, SharedRef,
    SyncIdentity,
};
use memberlog::{Action, Role};
use p2p_net::{finish_join, Event, Joined, Known, Service, SharedProvider};
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{list_records, open_record, write_record, KdfProfile};
use sharing::{ContactCard, Invitation, Inviter, Offer};

const WAIT: Duration = Duration::from_secs(60);

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-join-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

fn copy_of(reference: &SharedRef) -> SharedRef {
    SharedRef {
        vault_id: reference.vault_id,
        anchor: reference.anchor,
        seed: Secret::new(*reference.seed.expose()),
        name: reference.name.clone(),
        hints: reference.hints.clone(),
        epoch: reference.epoch,
        retired: reference
            .retired
            .iter()
            .map(|old| Secret::new(*old.expose()))
            .collect(),
        introduction: reference.introduction.clone(),
    }
}

fn introduction_of(opened: &sharing::Opened) -> Introduction {
    Introduction {
        head: opened.head,
        inviter_id: opened.inviter_id,
        inviter_vk: opened.inviter_vk.clone(),
    }
}

fn card_of(person: &SyncIdentity, at: u64) -> ContactCard {
    let publics = person.share_publics().unwrap();
    ContactCard::issue(
        &person.sign_key(),
        &person.devices()[0],
        person.root_vk(),
        publics.ec_pub,
        &publics.kem_ek[..],
        at,
    )
    .unwrap()
}

fn now() -> u64 {
    p2p_net::now_ms()
}

struct World {
    alice_dir: PathBuf,
    bob_dir: PathBuf,
    alice: Arc<SyncIdentity>,
    bob: Arc<SyncIdentity>,
    alice_ref: SharedRef,
    alice_service: Service,
    alice_addr: String,
}

/// Alice has a shared vault with two records, her node is up, and Bob is not
/// yet in the member log.
fn world() -> World {
    let (alice_dir, bob_dir) = (temp_dir("alice"), temp_dir("bob"));
    let alice = Arc::new(SyncIdentity::enroll(&[1; 64], &[1; 64], [1; 16], u64::MAX).unwrap());
    let bob = Arc::new(SyncIdentity::enroll(&[2; 64], &[2; 64], [2; 16], u64::MAX).unwrap());
    let (mut vault, alice_ref) =
        create_shared_vault(&alice_dir, &alice, "Family", KdfProfile::Fast).unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("wifi")).unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("bank")).unwrap();
    vault.persist(&alice_ref.seed).unwrap();
    let provider = Arc::new(SharedProvider::new(alice_dir.clone(), Arc::clone(&alice)));
    provider.serve(Arc::new(copy_of(&alice_ref)));
    let alice_service = Service::start(Some("127.0.0.1:0"), provider).unwrap();
    let alice_addr = alice_service.local_addr().unwrap().to_string();
    World {
        alice_dir,
        bob_dir,
        alice,
        bob,
        alice_ref,
        alice_service,
        alice_addr,
    }
}

/// Alice adds Bob from his card and invites him; returns the text Bob pastes.
fn invite(world: &World, card: &ContactCard) -> String {
    let mut vault = open_shared_vault(&world.alice_dir, &world.alice_ref, &world.alice).unwrap();
    let action = Action::Add {
        client_id: card.cert.client_id,
        root_vk: card.root_vk.clone(),
        role: Role::Writer,
    };
    let entry = vault
        .log
        .propose(
            &world.alice.sign_key(),
            &world.alice.devices()[0],
            action,
            now(),
        )
        .unwrap();
    vault.log.append(entry).unwrap();
    vault.save_log(&world.alice_ref.seed).unwrap();
    let key = world.alice.sign_key();
    Invitation::issue(
        &Inviter {
            sign: &key,
            cert: &world.alice.devices()[0],
        },
        &vault.log,
        card,
        &Offer {
            seed: &world.alice_ref.seed,
            name: "Family",
            hints: std::slice::from_ref(&world.alice_addr),
        },
        now(),
    )
    .unwrap()
    .to_text()
    .unwrap()
}

fn vault_of(joined: Joined) -> local::SharedVault {
    match joined {
        Joined::Opened(vault) => *vault,
        other => panic!("expected an opened vault, got {other:?}"),
    }
}

fn next_event(service: &Service) -> Event {
    loop {
        match service.events().recv_timeout(WAIT).unwrap() {
            Event::Listening(_) => {}
            other => return other,
        }
    }
}

#[test]
fn bob_pastes_the_invitation_his_device_syncs_and_the_vault_opens() {
    let w = world();
    let bobs_card = card_of(&w.bob, now()).to_text().unwrap();
    let card = ContactCard::from_text(&bobs_card).unwrap();
    let pasted = invite(&w, &card);

    // Bob pastes: verify, learn the vault number and the inviter, confirm.
    let invitation = Invitation::from_text(&pasted).unwrap();
    let publics_card = card_of(&w.bob, now());
    let opened = invitation
        .open(
            &w.bob.share_keys().ec_secret().unwrap(),
            w.bob.share_keys().kem_seed(),
            &publics_card,
            now(),
        )
        .unwrap();
    assert_eq!(opened.name, "Family");
    assert_eq!(opened.hints, vec![w.alice_addr.clone()]);
    let introduction = introduction_of(&opened);
    let bob_ref = SharedRef {
        vault_id: invitation.vault_id,
        anchor: *opened.log.anchor(),
        seed: opened.seed,
        name: opened.name,
        hints: opened.hints.clone(),
        epoch: 0,
        retired: Vec::new(),
        introduction: Some(introduction),
    };
    join_shared_vault(&w.bob_dir, &bob_ref, &opened.log).unwrap();
    assert!(is_pending(&w.bob_dir, &bob_ref), "nothing but the log yet");

    // His device starts synchronizing.
    let bob_provider = Arc::new(SharedProvider::new(w.bob_dir.clone(), Arc::clone(&w.bob)));
    let bob_service = Service::start(Some("127.0.0.1:0"), Arc::clone(&bob_provider)).unwrap();
    let view = bob_provider.view_for(&bob_ref).unwrap();
    bob_service.fetch_with(view, opened.hints, 5, Duration::from_millis(200));
    assert!(bob_service.status().fetching <= 1);

    let Event::Fetched {
        vault_id,
        log,
        snapshot,
        ..
    } = next_event(&bob_service)
    else {
        panic!("the fetch did not complete");
    };
    assert_eq!(vault_id, bob_ref.vault_id);

    // All the cryptography held: the vault is adopted and shows up.
    let vault =
        vault_of(finish_join(&w.bob_dir, &bob_ref, &w.bob, &log, snapshot, None, None).unwrap());
    assert!(!is_pending(&w.bob_dir, &bob_ref));
    let listed = list_records(&vault.session).unwrap();
    let mut titles: Vec<String> = listed
        .iter()
        .map(|record| {
            open_record(&vault.session, record.id)
                .unwrap()
                .text(TAG_TITLE)
                .unwrap()
                .unwrap()
                .to_owned()
        })
        .collect();
    titles.sort();
    assert_eq!(titles, ["bank", "wifi"]);
    assert_eq!(vault.log.members().len(), 2);
    assert_eq!(vault.log.role_of(&[2; 64]), Some(Role::Writer));

    // Alice's node saw Bob's device authenticate.
    let Event::PeerConnected {
        vault_id: seen_vault,
        device_id,
        client_id,
    } = next_event(&w.alice_service)
    else {
        panic!("Alice saw no peer");
    };
    assert_eq!(seen_vault, bob_ref.vault_id);
    assert_eq!(device_id, [2; 16]);
    assert_eq!(client_id, [2; 64]);
}

#[test]
fn a_person_alice_never_added_gets_nothing() {
    let w = world();
    let mallory = Arc::new(SyncIdentity::enroll(&[9; 64], &[9; 64], [9; 16], u64::MAX).unwrap());
    let stolen = copy_of(&w.alice_ref);
    let dir = temp_dir("mallory");
    let log = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice)
        .unwrap()
        .log;
    join_shared_vault(&dir, &stolen, &log).unwrap();
    let provider = Arc::new(SharedProvider::new(dir.clone(), mallory));
    let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    // Mallory even has the seed (the gate passes), but her account is not in
    // the member log, so the handshake fails.
    let view = provider.view_for(&stolen).unwrap();
    service.fetch_with(view, vec![w.alice_addr], 2, Duration::from_millis(100));
    assert!(matches!(
        next_event(&service),
        Event::FetchFailed {
            reason: p2p_net::FetchError::Refused,
            ..
        }
    ));
    assert!(is_pending(&dir, &stolen));
}

#[test]
fn someone_without_the_seed_cannot_even_start_a_handshake() {
    let w = world();
    let outsider = Arc::new(SyncIdentity::enroll(&[7; 64], &[7; 64], [7; 16], u64::MAX).unwrap());
    let mut guessed = copy_of(&w.alice_ref);
    guessed.seed = Secret::new([0x33; 64]);
    let dir = temp_dir("outsider");
    let log = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice)
        .unwrap()
        .log;
    let honest = copy_of(&w.alice_ref);
    join_shared_vault(&dir, &honest, &log).unwrap();
    let provider = Arc::new(SharedProvider::new(dir, outsider));
    let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let mut view = provider.view_for(&honest).unwrap();
    view.gate_keys = vec![kdf::shared_gate_key(guessed.seed.expose(), &guessed.vault_id).unwrap()];
    service.fetch_with(view, vec![w.alice_addr], 2, Duration::from_millis(100));
    assert!(matches!(
        next_event(&service),
        Event::FetchFailed {
            reason: p2p_net::FetchError::Refused,
            ..
        }
    ));
}

#[test]
fn a_dead_address_is_reported_as_unreachable() {
    let w = world();
    let reference = copy_of(&w.alice_ref);
    let dir = temp_dir("dead");
    let log = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice)
        .unwrap()
        .log;
    join_shared_vault(&dir, &reference, &log).unwrap();
    let provider = Arc::new(SharedProvider::new(dir, Arc::clone(&w.alice)));
    let service = Service::start(None, Arc::clone(&provider)).unwrap();
    assert!(
        service.local_addr().is_none(),
        "no listener in fetch-only mode"
    );
    let view = provider.view_for(&reference).unwrap();
    service.fetch_with(
        view,
        vec![String::from("127.0.0.1:1")],
        2,
        Duration::from_millis(50),
    );
    assert!(matches!(
        next_event(&service),
        Event::FetchFailed {
            reason: p2p_net::FetchError::Unreachable,
            ..
        }
    ));
}

#[test]
fn a_tampered_vault_file_is_refused_and_the_device_stays_pending() {
    let w = world();
    let card = card_of(&w.bob, now());
    let pasted = invite(&w, &card);
    let invitation = Invitation::from_text(&pasted).unwrap();
    let opened = invitation
        .open(
            &w.bob.share_keys().ec_secret().unwrap(),
            w.bob.share_keys().kem_seed(),
            &card_of(&w.bob, now()),
            now(),
        )
        .unwrap();
    let bob_ref = SharedRef {
        vault_id: invitation.vault_id,
        anchor: *opened.log.anchor(),
        seed: opened.seed,
        name: opened.name,
        hints: opened.hints.clone(),
        epoch: 0,
        retired: Vec::new(),
        introduction: None,
    };
    join_shared_vault(&w.bob_dir, &bob_ref, &opened.log).unwrap();
    let provider = Arc::new(SharedProvider::new(w.bob_dir.clone(), Arc::clone(&w.bob)));
    let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    service.fetch_with(
        provider.view_for(&bob_ref).unwrap(),
        opened.hints,
        3,
        Duration::from_millis(100),
    );
    let Event::Fetched { log, snapshot, .. } = next_event(&service) else {
        panic!("the fetch did not complete");
    };

    let mut flipped = snapshot.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 1;
    assert!(finish_join(&w.bob_dir, &bob_ref, &w.bob, &log, flipped, None, None).is_err());
    assert!(
        is_pending(&w.bob_dir, &bob_ref),
        "a bad file must not be kept"
    );

    let mut bad_log = log.clone();
    let last = bad_log.len() - 1;
    bad_log[last] ^= 1;
    assert!(finish_join(
        &w.bob_dir,
        &bob_ref,
        &w.bob,
        &bad_log,
        snapshot.clone(),
        None,
        None
    )
    .is_err());
    assert!(is_pending(&w.bob_dir, &bob_ref));
    assert!(finish_join(
        &w.bob_dir,
        &bob_ref,
        &w.bob,
        &log[..log.len() - 1],
        snapshot.clone(),
        None,
        None
    )
    .is_err());

    assert!(finish_join(&w.bob_dir, &bob_ref, &w.bob, &log, snapshot, None, None).is_ok());
}

/// Alice's vault with Bob and Carol in it, both holding the file, and Alice's
/// node serving. Returns the world, and the two guests' references.
fn trio() -> (
    World,
    Arc<SyncIdentity>,
    Arc<SyncIdentity>,
    SharedRef,
    SharedRef,
    PathBuf,
    PathBuf,
) {
    let w = world();
    let carol = Arc::new(SyncIdentity::enroll(&[3; 64], &[3; 64], [3; 16], u64::MAX).unwrap());
    let bob = Arc::clone(&w.bob);
    let mut vault = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice).unwrap();
    for guest in [&bob, &carol] {
        let add = Action::Add {
            client_id: guest.devices()[0].client_id,
            root_vk: Box::new(*guest.root_vk()),
            role: Role::Writer,
        };
        let entry = vault
            .log
            .propose(&w.alice.sign_key(), &w.alice.devices()[0], add, now())
            .unwrap();
        vault.log.append(entry).unwrap();
    }
    vault.save_log(&w.alice_ref.seed).unwrap();
    let attested = vault.attestations(&w.alice_ref, &w.alice).unwrap();
    let carol_dir = temp_dir("carol");
    let bob_ref = SharedRef {
        hints: vec![w.alice_addr.clone()],
        ..copy_of(&w.alice_ref)
    };
    let carol_ref = SharedRef {
        hints: vec![w.alice_addr.clone()],
        ..copy_of(&w.alice_ref)
    };
    for (dir, reference, who) in [
        (&w.bob_dir, &bob_ref, &bob),
        (&carol_dir, &carol_ref, &carol),
    ] {
        join_shared_vault(dir, reference, &vault.log).unwrap();
        local::adopt_shared_file(
            dir,
            reference,
            session::VaultFile::new(vault.file.as_bytes().to_vec()),
            &attested,
            who,
        )
        .unwrap();
    }
    let bob_dir = w.bob_dir.clone();
    (w, bob, carol, bob_ref, carol_ref, bob_dir, carol_dir)
}

#[test]
fn a_removed_member_is_refused_and_a_remaining_one_receives_the_new_seed() {
    let (w, bob, carol, bob_ref, carol_ref, bob_dir, carol_dir) = trio();
    let known = Known {
        generation: open_shared_vault(&carol_dir, &carol_ref, &carol)
            .unwrap()
            .session
            .generation(),
        stale: false,
    };

    // Alice removes Bob: the new seed is stored, the vault rotates, and her
    // node serves the new reference.
    let mut vault = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice).unwrap();
    let next = local::plan_rotation(&w.alice_ref, vault.log.epoch()).unwrap();
    local::apply_rotation(
        &mut vault,
        &next,
        &w.alice,
        local::Replace::Remove(bob.devices()[0].client_id),
    )
    .unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("after")).unwrap();
    vault.persist(&next.seed).unwrap();
    let provider = Arc::new(SharedProvider::new(
        w.alice_dir.clone(),
        Arc::clone(&w.alice),
    ));
    provider.serve(Arc::new(copy_of(&next)));
    let node = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let address = node.local_addr().unwrap().to_string();

    // Bob still knows the old seed, so he passes the cheap gate; the
    // handshake turns him away because his account left the log.
    let bob_provider = Arc::new(SharedProvider::new(bob_dir, Arc::clone(&bob)));
    let bob_node = Service::start(None, Arc::clone(&bob_provider)).unwrap();
    bob_node.fetch_with(
        bob_provider.view_for(&bob_ref).unwrap(),
        vec![address.clone()],
        2,
        Duration::from_millis(50),
    );
    assert!(matches!(
        next_event(&bob_node),
        Event::FetchFailed {
            reason: p2p_net::FetchError::Refused,
            ..
        }
    ));

    // Carol connects with her old gate key, authenticates as a member, and is
    // handed the new seed over the channel.
    let carol_provider = Arc::new(SharedProvider::new(carol_dir.clone(), Arc::clone(&carol)));
    let carol_node = Service::start(None, Arc::clone(&carol_provider)).unwrap();
    carol_node.fetch_with(
        carol_provider.view_for(&carol_ref).unwrap(),
        vec![address],
        3,
        Duration::from_millis(50),
    );
    let Event::Fetched {
        log,
        snapshot,
        rekey,
        ..
    } = next_event(&carol_node)
    else {
        panic!("Carol's fetch did not complete");
    };
    let rekey = rekey.expect("the node offers the new seed");
    assert_eq!(rekey.len(), 68);

    // Every check holds, so she adopts; a seed that does not match the
    // owner's commitment, or a wrong epoch, is refused.
    let mut lying = rekey.to_vec();
    lying[0] ^= 1;
    assert!(finish_join(
        &carol_dir,
        &carol_ref,
        &carol,
        &log,
        snapshot.clone(),
        Some(&lying),
        Some(known)
    )
    .is_err());
    let mut skipped = rekey.to_vec();
    skipped[67] = 5;
    assert!(finish_join(
        &carol_dir,
        &carol_ref,
        &carol,
        &log,
        snapshot.clone(),
        Some(&skipped),
        Some(known)
    )
    .is_err());
    let joined = finish_join(
        &carol_dir,
        &carol_ref,
        &carol,
        &log,
        snapshot,
        Some(&rekey),
        Some(known),
    )
    .unwrap();
    let Joined::Rekey(plan) = joined else {
        panic!("Carol's vault should be replaced");
    };
    let reference = plan.reference().duplicate();
    assert_eq!(reference.epoch, 1);
    assert_eq!(reference.retired.len(), 1);
    let vault = plan.commit().unwrap();
    assert_eq!(list_records(&vault.session).unwrap().len(), 3);
    assert!(vault.log.role_of(&bob.devices()[0].client_id).is_none());
    assert!(open_shared_vault(&carol_dir, &reference, &carol).is_ok());

    // Nothing in the fetch replaces an open vault when no seed was offered.
    assert!(matches!(
        finish_join(
            &carol_dir,
            &reference,
            &carol,
            &log,
            Vec::new(),
            None,
            Some(Known {
                generation: 1,
                stale: false,
            })
        )
        .unwrap(),
        Joined::Unchanged
    ));
}

/// Bob joins with an introduction `tamper` has changed, fetches from Alice,
/// and tries to finish the join.
fn join_with(
    tamper: impl FnOnce(&mut Introduction),
    doctor: impl FnOnce(Vec<u8>) -> Vec<u8>,
) -> (World, SharedRef, anyhow::Result<()>) {
    let w = world();
    let card = card_of(&w.bob, now());
    let pasted = invite(&w, &card);
    let invitation = Invitation::from_text(&pasted).unwrap();
    let opened = invitation
        .open(
            &w.bob.share_keys().ec_secret().unwrap(),
            w.bob.share_keys().kem_seed(),
            &card_of(&w.bob, now()),
            now(),
        )
        .unwrap();
    let mut introduction = introduction_of(&opened);
    tamper(&mut introduction);
    let bob_ref = SharedRef {
        vault_id: invitation.vault_id,
        anchor: *opened.log.anchor(),
        seed: opened.seed,
        name: opened.name,
        hints: opened.hints.clone(),
        epoch: 0,
        retired: Vec::new(),
        introduction: Some(introduction),
    };
    join_shared_vault(&w.bob_dir, &bob_ref, &opened.log).unwrap();
    let provider = Arc::new(SharedProvider::new(w.bob_dir.clone(), Arc::clone(&w.bob)));
    let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let view = provider.view_for(&bob_ref).unwrap();
    service.fetch_with(view, opened.hints, 5, Duration::from_millis(200));
    let Event::Fetched { log, snapshot, .. } = next_event(&service) else {
        panic!("the fetch did not complete");
    };
    let snapshot = doctor(snapshot);
    let joined = finish_join(&w.bob_dir, &bob_ref, &w.bob, &log, snapshot, None, None).map(|_| ());
    (w, bob_ref, joined)
}

#[test]
fn a_log_that_does_not_reach_the_signed_head_is_refused() {
    let (w, bob_ref, joined) = join_with(|intro| intro.head[0] ^= 1, |snapshot| snapshot);
    assert!(joined.is_err());
    assert!(is_pending(&w.bob_dir, &bob_ref));
}

#[test]
fn an_inviter_the_log_does_not_list_is_refused() {
    let (w, bob_ref, joined) = join_with(|intro| intro.inviter_id = [7; 64], |snapshot| snapshot);
    assert!(joined.is_err());
    assert!(is_pending(&w.bob_dir, &bob_ref));
}

#[test]
fn an_inviter_with_a_different_root_key_is_refused() {
    let (w, bob_ref, joined) = join_with(|intro| intro.inviter_vk[0] ^= 1, |snapshot| snapshot);
    assert!(joined.is_err());
    assert!(is_pending(&w.bob_dir, &bob_ref));
}

#[test]
fn a_snapshot_without_its_attestations_is_refused() {
    let (w, bob_ref, joined) = join_with(
        |_| {},
        |snapshot| {
            let (file, _) = syncwire::decode_snapshot(snapshot).unwrap();
            syncwire::encode_snapshot(&file, &[]).unwrap()
        },
    );
    assert!(joined.is_err());
    assert!(is_pending(&w.bob_dir, &bob_ref));
}

#[test]
fn a_snapshot_missing_one_records_attestation_is_refused() {
    let (w, bob_ref, joined) = join_with(
        |_| {},
        |snapshot| {
            let (file, mut attestations) = syncwire::decode_snapshot(snapshot).unwrap();
            attestations.pop();
            syncwire::encode_snapshot(&file, &attestations).unwrap()
        },
    );
    assert!(joined.is_err(), "a record lost its attestation");
    assert!(is_pending(&w.bob_dir, &bob_ref));
}

#[test]
fn a_rotation_that_removes_nobody_reaches_every_member() {
    let (w, bob, carol, bob_ref, carol_ref, bob_dir, carol_dir) = trio();
    let mut vault = open_shared_vault(&w.alice_dir, &w.alice_ref, &w.alice).unwrap();
    let next = local::plan_rotation(&w.alice_ref, vault.log.epoch()).unwrap();
    local::apply_rotation(&mut vault, &next, &w.alice, local::Replace::Rotate).unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("after")).unwrap();
    vault.persist(&next.seed).unwrap();
    let provider = Arc::new(SharedProvider::new(
        w.alice_dir.clone(),
        Arc::clone(&w.alice),
    ));
    provider.serve(Arc::new(copy_of(&next)));
    let node = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let address = node.local_addr().unwrap().to_string();

    for (dir, reference, who) in [(bob_dir, bob_ref, bob), (carol_dir, carol_ref, carol)] {
        let known = Known {
            generation: open_shared_vault(&dir, &reference, &who)
                .unwrap()
                .session
                .generation(),
            stale: false,
        };
        let theirs = Arc::new(SharedProvider::new(dir.clone(), Arc::clone(&who)));
        let service = Service::start(None, Arc::clone(&theirs)).unwrap();
        service.fetch_with(
            theirs.view_for(&reference).unwrap(),
            vec![address.clone()],
            3,
            Duration::from_millis(50),
        );
        let Event::Fetched {
            log,
            snapshot,
            rekey,
            ..
        } = next_event(&service)
        else {
            panic!("the fetch did not complete");
        };
        let rekey = rekey.expect("the node offers the new seed");
        let Joined::Rekey(plan) = finish_join(
            &dir,
            &reference,
            &who,
            &log,
            snapshot,
            Some(&rekey),
            Some(known),
        )
        .unwrap() else {
            panic!("the vault should be replaced");
        };
        assert_eq!(plan.reference().epoch, 1);
        let adopted = plan.commit().unwrap();
        assert_eq!(adopted.log.members().len(), 3, "nobody was removed");
        assert_eq!(list_records(&adopted.session).unwrap().len(), 3);
    }
}
