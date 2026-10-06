#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use record::{Document, TAG_TITLE};
use session::{
    accept_revision, attest_latest, create, delete_record, frontier, issue_device_cert,
    latest_frame, list_records, open_record, plain_digest, rotate_vault_key, sync_verifying_key,
    unlock, write_record, Attestation, BodyAlg, DeviceCert, DeviceSignKey, KdfProfile, RotateCreds,
    Session, SessionError, TrustedAccount, UnlockCreds, VaultFile, SYNC_VK_LEN,
};

const SEED: [u8; 64] = [0x42; 64];
const NOW: u64 = 1_700_000_000_000;

struct Person {
    key: DeviceSignKey,
    cert: DeviceCert,
    root_vk: [u8; SYNC_VK_LEN],
    client: [u8; 64],
}

fn person(n: u8, not_after: u64) -> Person {
    let root_seed = [n; 32];
    let key = DeviceSignKey::from_seed(&[n ^ 0x80; 32]);
    let client = [n; 64];
    let cert = issue_device_cert(
        &root_seed,
        &client,
        &[n ^ 0x40; 16],
        &key.verifying_key().unwrap(),
        not_after,
        u64::from(n),
    )
    .unwrap();
    Person {
        key,
        cert,
        root_vk: sync_verifying_key(&root_seed).unwrap().try_into().unwrap(),
        client,
    }
}

const fn account(person: &Person, can_write: bool) -> TrustedAccount<'_> {
    TrustedAccount {
        client_id: person.client,
        root_vk: &person.root_vk,
        can_write,
    }
}

/// A vault file and one session on it per person, each stamped with the
/// person's certified device id.
fn replicas(people: &[&Person]) -> (VaultFile, Vec<(VaultFile, Session)>) {
    let (file, _) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let sessions = people
        .iter()
        .map(|person| {
            let copy = VaultFile::new(file.as_bytes().to_vec());
            let mut session = unlock(&copy, &UnlockCreds::master(&SEED), None).unwrap();
            session.set_origin_device(person.cert.device_id).unwrap();
            (copy, session)
        })
        .collect();
    (file, sessions)
}

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

fn write(
    person: &Person,
    replica: &mut (VaultFile, Session),
    id: u32,
    text: &str,
) -> (Attestation, Vec<u8>) {
    write_record(&mut replica.1, &mut replica.0, Some(id), &titled(text)).unwrap();
    attest_latest(&replica.1, &person.key, &person.cert, id).unwrap()
}

fn accept(
    to: &mut (VaultFile, Session),
    frame: &[u8],
    attestation: &Attestation,
    accounts: &[TrustedAccount<'_>],
) -> anyhow::Result<session::Accepted> {
    accept_revision(
        &mut to.1,
        &mut to.0,
        frame,
        attestation,
        accounts,
        NOW,
        |_| None,
    )
}

fn why(result: anyhow::Result<session::Accepted>) -> String {
    result.unwrap_err().to_string()
}

#[test]
fn a_writers_revision_is_kept_by_another_device_and_reads_the_same() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let (attestation, frame) = write(&alice, &mut a, 7, "wifi");
    let accounts = [account(&alice, true), account(&bob, true)];
    let accepted = accept(&mut b, &frame, &attestation, &accounts).unwrap();
    assert_eq!((accepted.record_id, accepted.revision), (7, 1));
    assert_eq!(accepted.origin_device, alice.cert.device_id);
    assert_eq!(
        open_record(&b.1, 7).unwrap().text(TAG_TITLE).unwrap(),
        Some("wifi")
    );
    assert_eq!(frontier(&a.1).unwrap(), frontier(&b.1).unwrap());
}

#[test]
fn every_forgery_is_refused_and_changes_nothing() {
    let (alice, bob, mallory) = (
        person(1, u64::MAX),
        person(2, u64::MAX),
        person(9, u64::MAX),
    );
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let (good, frame) = write(&alice, &mut a, 7, "wifi");
    let accounts = [account(&alice, true), account(&bob, true)];
    let before = b.0.as_bytes().to_vec();

    let mut tampered = frame.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(accept(&mut b, &tampered, &good, &accounts).is_err());

    for forged in [
        Attestation {
            revision: 2,
            ..good.clone()
        },
        Attestation {
            record_id: 8,
            ..good.clone()
        },
        Attestation {
            origin_device: [3; 16],
            ..good.clone()
        },
        Attestation {
            vault_id: [1; 16],
            ..good.clone()
        },
        Attestation {
            plain_digest: plain_digest(&good.vault_id, 7, 1, 1, b"other"),
            ..good.clone()
        },
        Attestation {
            signature: vec![0; good.signature.len()],
            ..good.clone()
        },
        Attestation {
            signature: good.signature[..100].to_vec(),
            ..good.clone()
        },
    ] {
        assert!(accept(&mut b, &frame, &forged, &accounts).is_err());
    }

    // The right frame under another writer's name, a stranger's account, and
    // a certificate from the wrong root.
    let mut stolen = good.clone();
    stolen.signer = bob.cert.clone();
    assert!(accept(&mut b, &frame, &stolen, &accounts).is_err());
    assert_eq!(
        why(accept(&mut b, &frame, &good, &[account(&bob, true)])),
        "device not enrolled"
    );
    let other_root = TrustedAccount {
        client_id: alice.client,
        root_vk: &mallory.root_vk,
        can_write: true,
    };
    assert_eq!(
        why(accept(&mut b, &frame, &good, &[other_root])),
        "device cert rejected"
    );

    // Nothing was kept.
    assert_eq!(b.0.as_bytes(), before.as_slice());
    assert!(list_records(&b.1).unwrap().is_empty());
}

#[test]
fn a_reader_cannot_write_even_with_a_valid_signature() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let (attestation, frame) = write(&alice, &mut a, 7, "wifi");
    let alice_reads = [account(&alice, false), account(&bob, true)];
    assert_eq!(
        why(accept(&mut b, &frame, &attestation, &alice_reads)),
        "not a writer"
    );
    assert!(list_records(&b.1).unwrap().is_empty());
}

#[test]
fn an_expired_certificate_is_refused() {
    let (alice, bob) = (person(1, NOW - 1), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let (attestation, frame) = write(&alice, &mut a, 7, "wifi");
    let accounts = [account(&alice, true), account(&bob, true)];
    assert_eq!(
        why(accept(&mut b, &frame, &attestation, &accounts)),
        "device cert expired"
    );
}

#[test]
fn replays_and_older_revisions_are_stale() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let accounts = [account(&alice, true), account(&bob, true)];
    let (first, frame_one) = write(&alice, &mut a, 7, "one");
    accept(&mut b, &frame_one, &first, &accounts).unwrap();
    assert_eq!(
        why(accept(&mut b, &frame_one, &first, &accounts)),
        "stale revision",
        "replay"
    );
    let (second, frame_two) = write(&alice, &mut a, 7, "two");
    accept(&mut b, &frame_two, &second, &accounts).unwrap();
    assert_eq!(
        why(accept(&mut b, &frame_one, &first, &accounts)),
        "stale revision",
        "older"
    );
}

#[test]
fn two_edits_of_the_same_revision_settle_on_the_same_winner_everywhere() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let accounts = [account(&alice, true), account(&bob, true)];
    let (base, frame) = write(&alice, &mut a, 7, "base");
    accept(&mut b, &frame, &base, &accounts).unwrap();

    // Both edit revision 2 before either has seen the other's.
    let (from_alice, alice_frame) = write(&alice, &mut a, 7, "alice two");
    let (from_bob, bob_frame) = write(&bob, &mut b, 7, "bob two");
    let on_a = accept(&mut a, &bob_frame, &from_bob, &accounts);
    let on_b = accept(&mut b, &alice_frame, &from_alice, &accounts);
    let alice_wins = alice.cert.device_id > bob.cert.device_id;
    let winner = if alice_wins { "alice two" } else { "bob two" };
    assert_eq!(
        on_a.is_ok(),
        !alice_wins,
        "Alice takes Bob's only if his id is larger"
    );
    assert_eq!(
        on_b.is_ok(),
        alice_wins,
        "Bob takes Alice's only if her id is larger"
    );
    for replica in [&a, &b] {
        assert_eq!(
            open_record(&replica.1, 7).unwrap().text(TAG_TITLE).unwrap(),
            Some(winner)
        );
    }
    assert_eq!(frontier(&a.1).unwrap(), frontier(&b.1).unwrap());
}

#[test]
fn a_seen_revision_is_never_accepted_below_it() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let (attestation, frame) = write(&alice, &mut a, 7, "wifi");
    let accounts = [account(&alice, true), account(&bob, true)];
    let rolled_back = accept_revision(
        &mut b.1,
        &mut b.0,
        &frame,
        &attestation,
        &accounts,
        NOW,
        |record| (record == 7).then_some(5),
    );
    assert_eq!(why(rolled_back), "stale revision");
}

#[test]
fn a_deletion_travels_as_an_attested_tombstone() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    let accounts = [account(&alice, true), account(&bob, true)];
    let (created, frame) = write(&alice, &mut a, 7, "wifi");
    accept(&mut b, &frame, &created, &accounts).unwrap();
    delete_record(&mut a.1, &mut a.0, 7).unwrap();
    let (tombstone, gone) = attest_latest(&a.1, &alice.key, &alice.cert, 7).unwrap();
    accept(&mut b, &gone, &tombstone, &accounts).unwrap();
    assert!(open_record(&b.1, 7).is_err(), "deleted on both");
    assert_eq!(frontier(&a.1).unwrap(), frontier(&b.1).unwrap());
}

#[test]
fn only_the_writing_device_can_attest_its_frame() {
    let (alice, bob) = (person(1, u64::MAX), person(2, u64::MAX));
    let (_, mut sessions) = replicas(&[&alice, &bob]);
    let mut b = sessions.pop().unwrap();
    let mut a = sessions.pop().unwrap();
    write_record(&mut a.1, &mut a.0, Some(7), &titled("wifi")).unwrap();
    let error = attest_latest(&a.1, &bob.key, &bob.cert, 7).unwrap_err();
    assert_eq!(error.to_string(), "frame written by another device");
    assert!(
        attest_latest(&b.1, &alice.key, &alice.cert, 7).is_err(),
        "unknown record"
    );
    let _ = &mut b;
}

#[test]
fn the_signed_digest_is_the_same_before_and_after_a_rotation() {
    let alice = person(1, u64::MAX);
    let (_, mut sessions) = replicas(&[&alice]);
    let mut a = sessions.pop().unwrap();
    let (before, old_frame) = write(&alice, &mut a, 7, "wifi");
    let creds = RotateCreds {
        master: &[0x77; 64],
        prfs: &[],
        human_password: None,
    };
    rotate_vault_key(&mut a.1, &mut a.0, &creds).unwrap();
    let mut reopened = unlock(&a.0, &UnlockCreds::master(&[0x77; 64]), None).unwrap();
    reopened.set_origin_device(alice.cert.device_id).unwrap();
    let new_frame = latest_frame(&reopened, 7).unwrap();
    assert_ne!(new_frame, old_frame, "the frame was re-sealed");
    let (after, _) = attest_latest(&reopened, &alice.key, &alice.cert, 7).unwrap();
    assert_eq!(
        after.plain_digest, before.plain_digest,
        "the digest survives"
    );
    assert!(
        before.verify(&alice.root_vk, NOW).is_ok(),
        "and so does the old signature"
    );
}

#[test]
fn contexts_are_distinct() {
    assert_ne!(session::REVISION_CTX, session::SYNC_CTX);
    assert_ne!(session::REVISION_CTX, session::DEVICE_CERT_CTX);
    assert_ne!(session::REVISION_CTX, session::REVOKE_CTX);
    let _ = SessionError::NotAWriter;
}

#[test]
fn two_frontiers_say_what_each_side_lacks_and_agree_on_who_wins() {
    use session::{reconcile, FrontierEntry};
    let entry = |id: u32, revision: u64, origin: u8| FrontierEntry {
        record_id: id,
        revision,
        origin_device: [origin; 16],
    };
    let local = [
        entry(1, 2, 1),
        entry(3, 1, 1),
        entry(5, 4, 9),
        entry(7, 1, 1),
    ];
    let remote = [
        entry(1, 3, 2),
        entry(2, 1, 2),
        entry(5, 4, 3),
        entry(7, 1, 1),
    ];
    let plan = reconcile(&local, &remote);
    assert_eq!(
        plan.pull,
        vec![1, 2],
        "newer on their side, and missing here"
    );
    assert_eq!(
        plan.push,
        vec![3, 5],
        "missing there, and the larger device id at a tie"
    );
    let mirror = reconcile(&remote, &local);
    assert_eq!(mirror.pull, plan.push);
    assert_eq!(mirror.push, plan.pull);
    assert_eq!(reconcile(&local, &local), session::Reconcile::default());
    assert_eq!(reconcile(&[], &remote).pull, vec![1, 2, 5, 7]);
    assert_eq!(reconcile(&local, &[]).push, vec![1, 3, 5, 7]);
}
