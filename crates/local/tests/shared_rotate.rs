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
    adopt_rekeyed, adopt_shared_file, apply_rotation, create_shared_vault, is_behind,
    join_shared_vault, open_shared_vault, plan_rotation, seed_matches_log, Replace, SharedRef,
    SharedVault, SyncIdentity,
};
use memberlog::{Action, Role};
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{list_records, unlock, write_record, KdfProfile, UnlockCreds, VaultFile};

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-rot-{tag}-");
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

fn dup(reference: &SharedRef) -> SharedRef {
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
    }
}

struct Group {
    dirs: [PathBuf; 3],
    ids: [SyncIdentity; 3],
    alice: SharedVault,
    refs: [SharedRef; 3],
}

/// Alice owns a vault with one record; Bob and Carol are writers who both
/// hold the vault file.
fn group() -> Group {
    let dirs = [temp_dir("a"), temp_dir("b"), temp_dir("c")];
    let ids = [person(1), person(2), person(3)];
    let (mut alice, alice_ref) =
        create_shared_vault(&dirs[0], &ids[0], "Family", KdfProfile::Fast).unwrap();
    write_record(&mut alice.session, &mut alice.file, None, &titled("before")).unwrap();
    for guest in &ids[1..] {
        let add = Action::Add {
            client_id: guest.devices()[0].client_id,
            root_vk: Box::new(*guest.root_vk()),
            role: Role::Writer,
        };
        let entry = alice
            .log
            .propose(&ids[0].sign_key(), &ids[0].devices()[0], add, 1)
            .unwrap();
        alice.log.append(entry).unwrap();
    }
    alice.save_log(&alice_ref.seed).unwrap();
    alice.persist(&alice_ref.seed).unwrap();
    let refs = [dup(&alice_ref), dup(&alice_ref), dup(&alice_ref)];
    for index in 1..3 {
        join_shared_vault(&dirs[index], &refs[index], &alice.log).unwrap();
        adopt_shared_file(
            &dirs[index],
            &refs[index],
            VaultFile::new(alice.file.as_bytes().to_vec()),
            &ids[index],
        )
        .unwrap();
    }
    Group {
        dirs,
        ids,
        alice,
        refs,
    }
}

fn entries_of(vault: &SharedVault) -> Vec<memberlog::Entry> {
    vault.log.entries().to_vec()
}

#[test]
fn removing_a_member_closes_the_vault_to_the_seed_they_hold() {
    let mut g = group();
    let old_seed = Secret::new(*g.refs[0].seed.expose());
    let old_file = g.alice.file.as_bytes().to_vec();
    let bob_client = g.ids[1].devices()[0].client_id;

    let next = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    assert_eq!(next.epoch, 1);
    assert_eq!(next.retired.len(), 1);
    assert_eq!(next.retired[0].expose(), old_seed.expose());

    // The new seed is stored first; until the vault moves, everything still
    // opens through the retired seed.
    assert!(open_shared_vault(&g.dirs[0], &next, &g.ids[0]).is_ok());

    apply_rotation(&mut g.alice, &next, &g.ids[0], Replace::Remove(bob_client)).unwrap();
    assert_eq!(g.alice.log.epoch(), 1);
    assert!(g.alice.log.role_of(&bob_client).is_none());
    assert_eq!(
        list_records(&g.alice.session).unwrap().len(),
        1,
        "history is kept"
    );

    let new_file = g.alice.file.as_bytes().to_vec();
    assert_ne!(new_file, old_file);
    let opens = |file: &[u8], seed: &Secret<[u8; 64]>| {
        unlock(
            &VaultFile::new(file.to_vec()),
            &UnlockCreds::master(seed.expose()),
            None,
        )
        .is_ok()
    };
    assert!(opens(&new_file, &next.seed));
    assert!(
        !opens(&new_file, &old_seed),
        "the removed member's seed no longer opens it"
    );
    assert!(
        opens(&old_file, &old_seed),
        "what they already had stays theirs"
    );

    // A write after the rotation is closed to the old seed too.
    write_record(
        &mut g.alice.session,
        &mut g.alice.file,
        None,
        &titled("after"),
    )
    .unwrap();
    g.alice.persist(&next.seed).unwrap();
    let after = g.alice.file.as_bytes().to_vec();
    assert!(!opens(&after, &old_seed));

    // Alice reopens with the new reference, and the old one alone no longer
    // opens the new file.
    let reopened = open_shared_vault(&g.dirs[0], &next, &g.ids[0]).unwrap();
    assert_eq!(list_records(&reopened.session).unwrap().len(), 2);
    assert!(open_shared_vault(&g.dirs[0], &g.refs[0], &g.ids[0]).is_err());
}

#[test]
fn a_remaining_member_adopts_the_rotated_vault_only_when_every_check_holds() {
    let mut g = group();
    let carol_generation = {
        let carol = open_shared_vault(&g.dirs[2], &g.refs[2], &g.ids[2]).unwrap();
        carol.session.generation()
    };
    let bob_client = g.ids[1].devices()[0].client_id;
    let next = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    apply_rotation(&mut g.alice, &next, &g.ids[0], Replace::Remove(bob_client)).unwrap();
    write_record(
        &mut g.alice.session,
        &mut g.alice.file,
        None,
        &titled("after"),
    )
    .unwrap();
    g.alice.persist(&next.seed).unwrap();
    let file = || VaultFile::new(g.alice.file.as_bytes().to_vec());
    let entries = entries_of(&g.alice);
    let carol_old = &g.refs[2];
    let carol_next = carol_old.rotated(Secret::new(*next.seed.expose()), 1);

    // Wrong seed, wrong epoch, no log, an old file, a stale generation, and a
    // removed member all fail, and none of them touches Carol's vault.
    let wrong_seed = carol_old.rotated(Secret::new([9; 64]), 1);
    let wrong_epoch = carol_old.rotated(Secret::new(*next.seed.expose()), 2);
    let old_file = VaultFile::new(
        open_shared_vault(&g.dirs[2], carol_old, &g.ids[2])
            .unwrap()
            .file
            .as_bytes()
            .to_vec(),
    );
    let bad = |new: &SharedRef, file: VaultFile, entries: &[memberlog::Entry], floor| {
        adopt_rekeyed(
            &g.dirs[2],
            carol_old,
            new.duplicate(),
            file,
            &g.ids[2],
            entries,
            floor,
        )
    };
    assert!(bad(&wrong_seed, file(), &entries, None).is_err());
    assert!(bad(&wrong_epoch, file(), &entries, None).is_err());
    assert!(
        bad(&carol_next, file(), &[], None).is_err(),
        "no log, no commitment to check"
    );
    assert!(bad(&carol_next, old_file, &entries, None).is_err());
    assert!(bad(&carol_next, file(), &entries, Some(u64::MAX)).is_err());
    let mut forged = entries.clone();
    forged.last_mut().unwrap().at_ms += 1;
    assert!(bad(&carol_next, file(), &forged, None).is_err());
    assert!(
        open_shared_vault(&g.dirs[2], carol_old, &g.ids[2]).is_ok(),
        "Carol still has her old, working vault"
    );

    let bob_next = g.refs[1].rotated(Secret::new(*next.seed.expose()), 1);
    assert!(
        adopt_rekeyed(
            &g.dirs[1],
            &g.refs[1],
            bob_next,
            file(),
            &g.ids[1],
            &entries,
            None
        )
        .is_err(),
        "a removed member cannot adopt even with the seed"
    );

    let carol = adopt_rekeyed(
        &g.dirs[2],
        carol_old,
        carol_next.duplicate(),
        file(),
        &g.ids[2],
        &entries,
        Some(carol_generation),
    )
    .unwrap();
    assert_eq!(list_records(&carol.session).unwrap().len(), 2);
    assert_eq!(carol.log.epoch(), 1);
    assert!(carol.log.role_of(&bob_client).is_none());
    let reopened = open_shared_vault(&g.dirs[2], &carol_next, &g.ids[2]).unwrap();
    assert_eq!(list_records(&reopened.session).unwrap().len(), 2);
    assert!(open_shared_vault(&g.dirs[2], carol_old, &g.ids[2]).is_err());
}

#[test]
fn a_rotation_without_a_removal_replaces_the_seed_and_keeps_everyone() {
    let mut g = group();
    let next = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    apply_rotation(&mut g.alice, &next, &g.ids[0], Replace::Rotate).unwrap();
    assert_eq!(g.alice.log.epoch(), 1);
    assert_eq!(g.alice.log.members().len(), 3);
    assert!(is_behind(&g.refs[2], &g.alice.log));
    assert!(!is_behind(&next, &g.alice.log));
    assert!(seed_matches_log(&g.alice.log, 1, &next.seed));
    assert!(!seed_matches_log(&g.alice.log, 1, &g.refs[0].seed));
    assert!(!seed_matches_log(&g.alice.log, 2, &next.seed));
}

#[test]
fn a_refused_request_changes_nothing() {
    let mut g = group();
    let old_file = g.alice.file.as_bytes().to_vec();
    let next = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    let alice_client = g.ids[0].devices()[0].client_id;
    let stranger = [0x77; 64];

    for replace in [Replace::Remove(alice_client), Replace::Remove(stranger)] {
        assert!(apply_rotation(&mut g.alice, &next, &g.ids[0], replace).is_err());
        assert_eq!(g.alice.log.epoch(), 0);
        assert_eq!(g.alice.file.as_bytes(), old_file.as_slice());
    }
    let skipped = plan_rotation(&next, 1).unwrap();
    assert!(
        apply_rotation(&mut g.alice, &skipped, &g.ids[0], Replace::Rotate).is_err(),
        "an epoch cannot be skipped"
    );
    // Bob is a writer: his entry would be refused by the log.
    let mut bob = open_shared_vault(&g.dirs[1], &g.refs[1], &g.ids[1]).unwrap();
    let bob_next = plan_rotation(&g.refs[1], bob.log.epoch()).unwrap();
    let bob_file = bob.file.as_bytes().to_vec();
    assert!(apply_rotation(&mut bob, &bob_next, &g.ids[1], Replace::Rotate).is_err());
    assert_eq!(bob.file.as_bytes(), bob_file.as_slice());
    assert!(open_shared_vault(&g.dirs[1], &g.refs[1], &g.ids[1]).is_ok());
    assert!(open_shared_vault(&g.dirs[0], &g.refs[0], &g.ids[0]).is_ok());
}

#[test]
fn the_reference_remembers_its_epoch_and_a_bounded_history_of_seeds() {
    let mut reference = SharedRef {
        vault_id: [1; 16],
        anchor: [2; 32],
        seed: Secret::new([3; 64]),
        name: String::from("Family"),
        hints: Vec::new(),
        epoch: 0,
        retired: Vec::new(),
    };
    for round in 1..=10u8 {
        reference = reference.rotated(Secret::new([100 + round; 64]), u32::from(round));
    }
    assert_eq!(reference.epoch, 10);
    assert_eq!(reference.retired.len(), 8, "the oldest are forgotten");
    assert_eq!(reference.retired[0].expose(), &[109; 64], "newest first");
    assert_eq!(reference.seeds().count(), 9);

    let parsed = SharedRef::from_document(&reference.to_document())
        .unwrap()
        .unwrap();
    assert_eq!(parsed.epoch, 10);
    assert_eq!(parsed.seed.expose(), reference.seed.expose());
    assert_eq!(parsed.retired.len(), 8);
    assert_eq!(parsed.retired[7].expose(), reference.retired[7].expose());

    let mut doc = reference.to_document();
    doc.set_data(record::TAG_SHARED_EPOCH, record::ValueType::Bytes, &[1, 2]);
    assert!(SharedRef::from_document(&doc).is_err());
    let mut gap = reference.to_document();
    gap.remove(record::TAG_SHARED_RETIRED_MIN);
    assert!(
        SharedRef::from_document(&gap).is_err(),
        "retired seeds are contiguous"
    );
}

#[test]
fn a_crash_between_storing_the_reference_and_writing_the_files_is_recoverable() {
    let mut g = group();
    let bob_client = g.ids[1].devices()[0].client_id;
    let next = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    apply_rotation(&mut g.alice, &next, &g.ids[0], Replace::Remove(bob_client)).unwrap();
    let entries = entries_of(&g.alice);
    let new_file = || VaultFile::new(g.alice.file.as_bytes().to_vec());
    let carol_old = &g.refs[2];
    let carol_next = carol_old.rotated(Secret::new(*next.seed.expose()), 1);

    // Phase one verifies and writes nothing: Carol's files are untouched.
    let plan = local::prepare_rekey(
        &g.dirs[2],
        carol_old,
        carol_next.duplicate(),
        new_file(),
        &g.ids[2],
        &entries,
        None,
    )
    .unwrap();
    assert_eq!(plan.reference().epoch, 1);
    assert!(open_shared_vault(&g.dirs[2], carol_old, &g.ids[2]).is_ok());

    // The caller stores the new reference, then the process dies before the
    // commit. Carol's vault still opens: through the retired seed, flagged
    // as behind.
    let behind = open_shared_vault(&g.dirs[2], &carol_next, &g.ids[2]).unwrap();
    assert!(behind.stale, "the files are older than the reference");
    assert!(
        !open_shared_vault(&g.dirs[0], &next, &g.ids[0])
            .unwrap()
            .stale
    );

    // A later fetch offers the same seed again; because the vault is stale
    // the same reference is accepted once more and the commit completes.
    let again = local::prepare_rekey(
        &g.dirs[2],
        &carol_next,
        carol_next.duplicate(),
        new_file(),
        &g.ids[2],
        &entries,
        Some(behind.session.generation()),
    )
    .unwrap();
    let vault = again.commit().unwrap();
    assert!(!vault.stale);
    let healed = open_shared_vault(&g.dirs[2], &carol_next, &g.ids[2]).unwrap();
    assert!(!healed.stale);
    assert_eq!(healed.log.epoch(), 1);
}

#[test]
fn a_cut_short_attempt_does_not_block_the_next_one() {
    let mut g = group();
    let bob_client = g.ids[1].devices()[0].client_id;
    // The reference of an attempt that stored the new seed and then failed:
    // epoch 1 in the reference, epoch 0 in the log.
    let failed = plan_rotation(&g.refs[0], g.alice.log.epoch()).unwrap();
    assert_eq!(failed.epoch, 1);
    let retry = plan_rotation(&failed, g.alice.log.epoch()).unwrap();
    assert_eq!(
        retry.epoch, 1,
        "the next epoch comes from the log, not the reference"
    );
    assert_eq!(retry.retired.len(), 2);
    apply_rotation(&mut g.alice, &retry, &g.ids[0], Replace::Remove(bob_client)).unwrap();
    assert_eq!(g.alice.log.epoch(), 1);
    let reopened = open_shared_vault(&g.dirs[0], &retry, &g.ids[0]).unwrap();
    assert!(!reopened.stale);
}
