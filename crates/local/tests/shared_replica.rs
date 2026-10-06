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
    adopt_shared_file, apply_rotation, create_shared_vault, join_shared_vault, open_shared_vault,
    plan_rotation, verdict_of, Edit, Replace, SharedRef, SharedVault, SyncIdentity, Verdict,
};
use memberlog::{Action, Role};
use record::{Document, TAG_TITLE};
use session::{
    attest_latest, list_records, open_record, reconcile, write_record, KdfProfile, VaultFile,
};
use syncwire::{decode_bundle, decode_frontier};

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-replica-{tag}-");
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

#[allow(clippy::unnecessary_box_returns, reason = "the edit API takes a box")]
fn titled(text: &str) -> Box<Document> {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    Box::new(doc)
}

fn dup(reference: &SharedRef) -> SharedRef {
    reference.duplicate()
}

struct Member {
    base: PathBuf,
    id: SyncIdentity,
    reference: SharedRef,
    vault: SharedVault,
}

/// Alice (owner), Bob (writer) and Carol (reader) each hold the vault.
fn trio() -> [Member; 3] {
    let dirs = [temp_dir("a"), temp_dir("b"), temp_dir("c")];
    let ids = [person(1), person(2), person(3)];
    let (mut alice, alice_ref) =
        create_shared_vault(&dirs[0], &ids[0], "Family", KdfProfile::Fast).unwrap();
    for (guest, role) in [(&ids[1], Role::Writer), (&ids[2], Role::Reader)] {
        let add = Action::Add {
            client_id: guest.devices()[0].client_id,
            root_vk: Box::new(*guest.root_vk()),
            role,
        };
        let entry = alice
            .log
            .propose(&ids[0].sign_key(), &ids[0].devices()[0], add, 1)
            .unwrap();
        alice.log.append(entry).unwrap();
    }
    alice.save_log(&alice_ref.seed).unwrap();
    alice.persist(&alice_ref.seed).unwrap();
    let mut members = Vec::new();
    for (index, id) in ids.into_iter().enumerate() {
        let base = dirs[index].clone();
        let reference = dup(&alice_ref);
        let vault = if index == 0 {
            open_shared_vault(&dirs[0], &reference, &id).unwrap()
        } else {
            join_shared_vault(&dirs[index], &reference, &alice.log).unwrap();
            adopt_shared_file(
                &dirs[index],
                &reference,
                VaultFile::new(alice.file.as_bytes().to_vec()),
                &id,
            )
            .unwrap()
        };
        members.push(Member {
            base,
            id,
            reference,
            vault,
        });
    }
    let mut it = members.into_iter();
    [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]
}

/// One round of sync from `a` against `b`: pull what `b` has newer, push what
/// `a` has newer. Returns the verdicts of the pushes.
fn exchange(a: &mut Member, b: &mut Member) -> Vec<Verdict> {
    let theirs = decode_frontier(&b.vault.frontier_wire().unwrap()).unwrap();
    let mine = decode_frontier(&a.vault.frontier_wire().unwrap()).unwrap();
    let plan = reconcile(&mine, &theirs);
    for id in plan.pull {
        let bundle = b.vault.bundle(&b.reference, &b.id, id).unwrap().unwrap();
        a.vault.accept(&a.reference, &bundle).unwrap();
    }
    plan.push
        .into_iter()
        .map(|id| {
            let bundle = a.vault.bundle(&a.reference, &a.id, id).unwrap().unwrap();
            b.vault
                .accept(&b.reference, &bundle)
                .map_or_else(|error| verdict_of(&error), |_| Verdict::Applied)
        })
        .collect()
}

fn titles(member: &Member) -> Vec<String> {
    let mut found: Vec<String> = list_records(&member.vault.session)
        .unwrap()
        .iter()
        .map(|row| {
            open_record(&member.vault.session, row.id)
                .unwrap()
                .text(TAG_TITLE)
                .unwrap()
                .unwrap()
                .to_owned()
        })
        .collect();
    found.sort();
    found
}

#[test]
fn a_writers_record_reaches_everyone_through_a_relay_with_its_author() {
    let [mut alice, mut bob, mut carol] = trio();
    let id = bob
        .vault
        .edit(&bob.reference, &bob.id, Edit::Create(titled("wifi")))
        .unwrap();
    assert_ne!(id, 0);
    assert_eq!(exchange(&mut alice, &mut bob), vec![]);
    assert_eq!(titles(&alice), ["wifi"]);
    // Carol never talks to Bob: Alice relays Bob's signed revision.
    assert_eq!(exchange(&mut carol, &mut alice), vec![]);
    assert_eq!(titles(&carol), ["wifi"]);
    let held = carol.vault.attest.get(id).unwrap();
    assert_eq!(
        held.signer.device_id,
        bob.id.devices()[0].device_id,
        "Bob stays the author"
    );
    assert_eq!(
        decode_frontier(&carol.vault.frontier_wire().unwrap()).unwrap(),
        decode_frontier(&bob.vault.frontier_wire().unwrap()).unwrap()
    );
}

#[test]
fn updates_and_deletions_travel_both_ways() {
    let [mut alice, mut bob, _] = trio();
    let id = alice
        .vault
        .edit(&alice.reference, &alice.id, Edit::Create(titled("one")))
        .unwrap();
    exchange(&mut bob, &mut alice);
    bob.vault
        .edit(&bob.reference, &bob.id, Edit::Update(id, titled("two")))
        .unwrap();
    exchange(&mut alice, &mut bob);
    assert_eq!(titles(&alice), ["two"]);
    alice
        .vault
        .edit(&alice.reference, &alice.id, Edit::Delete(id))
        .unwrap();
    exchange(&mut bob, &mut alice);
    assert!(titles(&bob).is_empty());
    assert!(
        bob.vault
            .edit(&bob.reference, &bob.id, Edit::Update(id, titled("again")))
            .is_err(),
        "a deleted record cannot be updated"
    );
}

#[test]
fn a_reader_cannot_add_to_the_vault_by_any_route() {
    let [mut alice, bob, mut carol] = trio();
    let denied = carol
        .vault
        .edit(&carol.reference, &carol.id, Edit::Create(titled("sneaky")))
        .unwrap_err();
    assert_eq!(denied.to_string(), "not a writer");

    // Bypassing the check: Carol writes a frame with the session API and
    // signs it with her own valid key. Alice refuses it.
    write_record(
        &mut carol.vault.session,
        &mut carol.vault.file,
        Some(77),
        &titled("forged"),
    )
    .unwrap();
    let (attestation, frame) = attest_latest(
        &carol.vault.session,
        &carol.id.sign_key(),
        &carol.id.devices()[0],
        77,
    )
    .unwrap();
    let bundle = syncwire::encode_bundle(&attestation, &frame).unwrap();
    let error = alice.vault.accept(&alice.reference, &bundle).unwrap_err();
    assert_eq!(verdict_of(&error), Verdict::Refused);
    assert!(titles(&alice).is_empty());
    drop(bob);
}

#[test]
fn concurrent_edits_settle_on_one_winner_on_both_sides() {
    let [mut alice, mut bob, _] = trio();
    let id = alice
        .vault
        .edit(&alice.reference, &alice.id, Edit::Create(titled("base")))
        .unwrap();
    exchange(&mut bob, &mut alice);
    alice
        .vault
        .edit(
            &alice.reference,
            &alice.id,
            Edit::Update(id, titled("alice")),
        )
        .unwrap();
    bob.vault
        .edit(&bob.reference, &bob.id, Edit::Update(id, titled("bob")))
        .unwrap();
    exchange(&mut alice, &mut bob);
    exchange(&mut bob, &mut alice);
    assert_eq!(titles(&alice), titles(&bob));
    let winner = if alice.id.devices()[0].device_id > bob.id.devices()[0].device_id {
        "alice"
    } else {
        "bob"
    };
    assert_eq!(titles(&alice), [winner]);
}

#[test]
fn a_member_removed_by_rotation_is_refused_when_pushing() {
    let [mut alice, mut bob, _] = trio();
    let bob_client = bob.id.devices()[0].client_id;
    let next = plan_rotation(&alice.reference, alice.vault.log.epoch()).unwrap();
    apply_rotation(
        &mut alice.vault,
        &next,
        &alice.id,
        Replace::Remove(bob_client),
    )
    .unwrap();
    alice.reference = next;
    // Bob, still on the old vault key, writes and pushes.
    bob.vault
        .edit(&bob.reference, &bob.id, Edit::Create(titled("late")))
        .unwrap();
    let id = decode_frontier(&bob.vault.frontier_wire().unwrap()).unwrap()[0].record_id;
    let bundle = bob
        .vault
        .bundle(&bob.reference, &bob.id, id)
        .unwrap()
        .unwrap();
    let error = alice.vault.accept(&alice.reference, &bundle).unwrap_err();
    assert_eq!(
        verdict_of(&error),
        Verdict::Refused,
        "not in the member log any more"
    );
    assert!(titles(&alice).is_empty());
}

#[test]
fn attestations_and_records_survive_a_reopen_and_a_rotation() {
    let [mut alice, mut bob, carol] = trio();
    let id = bob
        .vault
        .edit(&bob.reference, &bob.id, Edit::Create(titled("wifi")))
        .unwrap();
    exchange(&mut alice, &mut bob);
    assert_eq!(alice.vault.attest.len(), 1);

    let reopened = open_shared_vault(&alice.base, &alice.reference, &alice.id).unwrap();
    assert_eq!(reopened.attest.len(), 1);
    assert!(reopened.attest.get(id).is_some());
    drop(reopened);

    // Remove Carol: every frame is re-sealed, but Bob's attestation still
    // verifies against the re-sealed frame's plaintext and Alice can still
    // serve it.
    let carol_client = carol.id.devices()[0].client_id;
    let next = plan_rotation(&alice.reference, alice.vault.log.epoch()).unwrap();
    apply_rotation(
        &mut alice.vault,
        &next,
        &alice.id,
        Replace::Remove(carol_client),
    )
    .unwrap();
    alice.reference = next;
    let served = alice
        .vault
        .bundle(&alice.reference, &alice.id, id)
        .unwrap()
        .expect("still servable after the rotation");
    let (attestation, frame) = decode_bundle(&served).unwrap();
    assert_eq!(attestation.signer.device_id, bob.id.devices()[0].device_id);
    attestation.verify(bob.id.root_vk(), 1).unwrap();
    assert!(!frame.is_empty());
    assert_eq!(alice.vault.attest.len(), 1);
}
