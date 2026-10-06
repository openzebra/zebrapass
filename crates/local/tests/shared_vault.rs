#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use local::{
    adopt_shared_file, create_shared_vault, is_pending, join_shared_vault, open_shared_vault,
    SharedRef, SyncIdentity,
};
use memberlog::{Action, Role};
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{history, list_records, open_record, write_record, KdfProfile, VaultFile};

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-shared-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn person(n: u8) -> SyncIdentity {
    SyncIdentity::enroll(&[n; 64], &[n; 64], [n; 16], u64::MAX).unwrap()
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
        epoch: 0,
        retired: Vec::new(),
    }
}

struct Scene {
    alice_dir: PathBuf,
    bob_dir: PathBuf,
    alice: SyncIdentity,
    bob: SyncIdentity,
    alice_ref: SharedRef,
    bob_ref: SharedRef,
}

fn scene() -> Scene {
    let (alice_dir, bob_dir) = (temp_dir("alice"), temp_dir("bob"));
    let (alice, bob) = (person(1), person(2));
    let (mut vault, alice_ref) =
        create_shared_vault(&alice_dir, &alice, "Family", KdfProfile::Fast).unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("wifi")).unwrap();
    let add = Action::Add {
        client_id: bob.devices()[0].client_id,
        root_vk: Box::new(*bob.root_vk()),
        role: Role::Writer,
    };
    let entry = vault
        .log
        .propose(&alice.sign_key(), &alice.devices()[0], add, 1_000)
        .unwrap();
    vault.log.append(entry).unwrap();
    vault.save_log(&alice_ref.seed).unwrap();
    vault.persist(&alice_ref.seed).unwrap();
    let bob_ref = copy_of(&alice_ref);
    join_shared_vault(&bob_dir, &bob_ref, &vault.log).unwrap();
    Scene {
        alice_dir,
        bob_dir,
        alice,
        bob,
        alice_ref,
        bob_ref,
    }
}

fn alice_file(scene: &Scene) -> Vec<u8> {
    let paths = local::shared_paths_for(&scene.alice_dir, &scene.alice_ref.vault_id);
    fs::read(paths.vault_file).unwrap()
}

#[test]
fn a_creator_gets_a_vault_whose_first_owner_is_their_account() {
    let dir = temp_dir("solo");
    let alice = person(1);
    let (vault, reference) = create_shared_vault(&dir, &alice, "Family", KdfProfile::Fast).unwrap();
    assert_eq!(reference.name, "Family");
    assert_eq!(vault.log.members().len(), 1);
    assert_eq!(vault.log.role_of(&[1; 64]), Some(Role::Owner));
    assert_eq!(&reference.anchor, vault.log.anchor());
    assert_eq!(vault.session.origin_device(), [1; 16]);
    assert!(!is_pending(&dir, &reference));
    let reopened = open_shared_vault(&dir, &reference, &alice).unwrap();
    assert_eq!(reopened.log.head(), vault.log.head());
    assert!(create_shared_vault(&dir, &alice, &"n".repeat(65), KdfProfile::Fast).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_joined_device_is_pending_until_the_vault_file_arrives_and_then_works() {
    let s = scene();
    assert!(is_pending(&s.bob_dir, &s.bob_ref));
    assert!(open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).is_err());

    let file = VaultFile::new(alice_file(&s));
    let mut vault = adopt_shared_file(&s.bob_dir, &s.bob_ref, file, &s.bob).unwrap();
    assert!(!is_pending(&s.bob_dir, &s.bob_ref));
    assert_eq!(vault.log.members().len(), 2);
    assert_eq!(vault.log.role_of(&[2; 64]), Some(Role::Writer));
    let listed = list_records(&vault.session).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        open_record(&vault.session, listed[0].id)
            .unwrap()
            .text(TAG_TITLE)
            .unwrap(),
        Some("wifi")
    );

    let id = write_record(&mut vault.session, &mut vault.file, None, &titled("bank")).unwrap();
    vault.persist(&s.bob_ref.seed).unwrap();
    let origin = history(&vault.session, id).unwrap()[0].origin_device;
    assert_eq!(
        origin, [2; 16],
        "Bob's frames carry Bob's certified device id"
    );

    let reopened = open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).unwrap();
    assert_eq!(list_records(&reopened.session).unwrap().len(), 2);
}

#[test]
fn an_older_copy_of_the_vault_file_is_refused_as_a_rollback() {
    let s = scene();
    let old = alice_file(&s);
    let mut vault =
        adopt_shared_file(&s.bob_dir, &s.bob_ref, VaultFile::new(old.clone()), &s.bob).unwrap();
    write_record(&mut vault.session, &mut vault.file, None, &titled("new")).unwrap();
    vault.persist(&s.bob_ref.seed).unwrap();
    fs::write(&vault.paths.vault_file, &old).unwrap();
    assert!(open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).is_err());
}

#[test]
fn a_wrong_seed_a_foreign_file_and_a_wrong_anchor_are_refused() {
    let s = scene();
    let mut wrong_seed = copy_of(&s.bob_ref);
    wrong_seed.seed = Secret::new([9; 64]);
    let file = || VaultFile::new(alice_file(&s));
    assert!(adopt_shared_file(&s.bob_dir, &wrong_seed, file(), &s.bob).is_err());

    let other_dir = temp_dir("other");
    let (_, other_ref) =
        create_shared_vault(&other_dir, &s.alice, "Other", KdfProfile::Fast).unwrap();
    let foreign =
        fs::read(local::shared_paths_for(&other_dir, &other_ref.vault_id).vault_file).unwrap();
    assert!(adopt_shared_file(&s.bob_dir, &s.bob_ref, VaultFile::new(foreign), &s.bob).is_err());

    let mut wrong_anchor = copy_of(&s.bob_ref);
    wrong_anchor.anchor = [1; 32];
    assert!(adopt_shared_file(&s.bob_dir, &wrong_anchor, file(), &s.bob).is_err());
    let alice_log = open_shared_vault(&s.alice_dir, &s.alice_ref, &s.alice)
        .unwrap()
        .log;
    assert!(join_shared_vault(&s.bob_dir, &wrong_anchor, &alice_log).is_err());
}

#[test]
fn a_tampered_or_missing_local_file_stops_the_vault_from_opening() {
    let s = scene();
    adopt_shared_file(
        &s.bob_dir,
        &s.bob_ref,
        VaultFile::new(alice_file(&s)),
        &s.bob,
    )
    .unwrap();
    let paths = local::shared_paths_for(&s.bob_dir, &s.bob_ref.vault_id);

    for path in [paths.members_log(), paths.shared_state()] {
        let original = fs::read(&path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&path, &damaged).unwrap();
        assert!(open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).is_err());
        fs::remove_file(&path).unwrap();
        assert!(
            open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).is_err(),
            "a deleted file must not reset what the device has seen"
        );
        fs::write(&path, &original).unwrap();
        assert!(open_shared_vault(&s.bob_dir, &s.bob_ref, &s.bob).is_ok());
    }
}

#[test]
fn the_reference_record_round_trips_and_other_records_are_not_references() {
    let seed = Secret::new([7; 64]);
    let reference = SharedRef {
        vault_id: [5; 16],
        anchor: [6; 32],
        seed,
        name: String::from("Family"),
        hints: vec![String::from("10.0.0.2:7447")],
        epoch: 0,
        retired: Vec::new(),
    };
    let doc = reference.to_document();
    let parsed = SharedRef::from_document(&doc).unwrap().unwrap();
    assert_eq!(parsed.vault_id, [5; 16]);
    assert_eq!(parsed.anchor, [6; 32]);
    assert_eq!(parsed.seed.expose(), &[7; 64]);
    assert_eq!(parsed.name, "Family");
    assert_eq!(parsed.hints, vec![String::from("10.0.0.2:7447")]);

    let mut crowded = SharedRef::from_document(&doc).unwrap().unwrap();
    crowded.hints = (0..5).map(|n| format!("10.0.0.{n}:1")).collect();
    assert!(SharedRef::from_document(&crowded.to_document()).is_err());
    crowded.hints = vec![String::new(), String::from("x:1")];
    assert!(SharedRef::from_document(&crowded.to_document()).is_err());
    crowded.hints = Vec::new();
    assert!(SharedRef::from_document(&crowded.to_document())
        .unwrap()
        .unwrap()
        .hints
        .is_empty());
    let shown = format!("{parsed:?}");
    assert!(shown.contains("[REDACTED]") && !shown.contains("7, 7"));
    assert!(SharedRef::from_document(&titled("a login"))
        .unwrap()
        .is_none());

    let mut broken = doc;
    broken.remove(record::TAG_SHARED_SEED);
    assert!(SharedRef::from_document(&broken).is_err());
}

#[test]
fn shared_vaults_live_apart_from_personal_vaults() {
    let dir = temp_dir("apart");
    let alice = person(1);
    let (_, reference) = create_shared_vault(&dir, &alice, "Family", KdfProfile::Fast).unwrap();
    let shared = local::shared_paths_for(&dir, &reference.vault_id);
    assert!(shared.vault_file.exists());
    assert!(shared.vault_file.starts_with(dir.join("shared")));
    assert!(
        !dir.join("vaults").exists(),
        "the unlock screen lists <base>/vaults and must not see a shared vault"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_listening_choice_survives_a_round_trip_and_cycles_through_all_three() {
    use local::{Listen, Prefs};
    let mut seen = vec![Listen::Lan];
    let mut mode = Listen::Lan;
    for _ in 0..2 {
        mode = mode.next();
        seen.push(mode);
    }
    assert_eq!(
        mode.next(),
        Listen::Lan,
        "a full cycle returns to the start"
    );
    seen.sort_by_key(|listen| u8::from(*listen));
    seen.dedup();
    assert_eq!(seen.len(), 3);
    for listen in [Listen::Off, Listen::Local, Listen::Lan] {
        let prefs = Prefs {
            p2p_listen: listen,
            ..Prefs::default()
        };
        let mut doc = Document::new();
        prefs.write(&mut doc);
        assert_eq!(Prefs::read(&doc).unwrap().unwrap().p2p_listen, listen);
    }
    let mut doc = Document::new();
    Prefs::default().write(&mut doc);
    doc.set_data(record::TAG_PREF_P2P_LISTEN, record::ValueType::Bytes, &[9]);
    assert!(
        Prefs::read(&doc).is_err(),
        "an unknown mode is an error, not a default"
    );
}
