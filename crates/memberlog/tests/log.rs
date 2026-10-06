#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use memberlog::{rotation_commit, Action, Entry, MemberLog, Role, ENTRY_WIRE_LEN, MAX_ENTRIES};
use pq::SYNC_VK_LEN;
use session::{issue_device_cert, sync_verifying_key, DeviceCert, DeviceSignKey};

const VAULT: [u8; 16] = [0x55; 16];
const T0: u64 = 1_700_000_000_000;

struct User {
    client_id: [u8; 64],
    root_vk: [u8; SYNC_VK_LEN],
    key: DeviceSignKey,
    cert: DeviceCert,
}

fn user(n: u8) -> User {
    let root_seed = [n; 32];
    let key = DeviceSignKey::from_seed(&[n ^ 0x80; 32]);
    let client_id = [n; 64];
    let cert = issue_device_cert(
        &root_seed,
        &client_id,
        &[n ^ 0x40; 16],
        &key.verifying_key().unwrap(),
        u64::MAX,
        u64::from(n),
    )
    .unwrap();
    User {
        client_id,
        root_vk: sync_verifying_key(&root_seed).unwrap().try_into().unwrap(),
        key,
        cert,
    }
}

fn add(user: &User, role: Role) -> Action {
    Action::Add {
        client_id: user.client_id,
        root_vk: Box::new(user.root_vk),
        role,
    }
}

fn step(log: &mut MemberLog, by: &User, action: Action) -> anyhow::Result<()> {
    let entry = log.propose(&by.key, &by.cert, action, T0 + 1)?;
    log.append(entry)
}

fn created_by(owner: &User) -> MemberLog {
    MemberLog::genesis(VAULT, &owner.key, &owner.cert, &owner.root_vk, T0).unwrap()
}

#[test]
fn the_creator_is_the_first_owner() {
    let alice = user(1);
    let log = created_by(&alice);
    assert_eq!(log.members().len(), 1);
    assert_eq!(log.role_of(&alice.client_id), Some(Role::Owner));
    assert_eq!(log.head(), log.anchor());
    assert_eq!(log.entries().len(), 1);
}

#[test]
fn an_owner_adds_members_and_roles_decide_what_they_may_do() {
    let (alice, bob, carol) = (user(1), user(2), user(3));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    step(&mut log, &alice, add(&carol, Role::Reader)).unwrap();
    assert!(log.may_write(&alice.client_id));
    assert!(log.may_write(&bob.client_id));
    assert!(!log.may_write(&carol.client_id));
    assert!(!log.may_write(&[9; 64]));
    assert_eq!(log.members().len(), 3);
}

#[test]
fn only_owners_change_the_member_list() {
    let (alice, bob, carol, dave) = (user(1), user(2), user(3), user(4));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    step(&mut log, &alice, add(&carol, Role::Reader)).unwrap();
    for by in [&bob, &carol] {
        assert!(step(&mut log, by, add(&dave, Role::Reader)).is_err());
        assert!(step(
            &mut log,
            by,
            Action::Remove {
                client_id: alice.client_id,
                commit: [7; 32]
            }
        )
        .is_err());
        let promote = Action::SetRole {
            client_id: by.client_id,
            role: Role::Owner,
        };
        assert!(step(&mut log, by, promote).is_err());
    }
    assert_eq!(log.members().len(), 3);
    assert_eq!(log.role_of(&bob.client_id), Some(Role::Writer));
}

#[test]
fn an_outsider_cannot_sign_even_with_a_valid_certificate() {
    let (alice, mallory) = (user(1), user(9));
    let mut log = created_by(&alice);
    let join = add(&mallory, Role::Owner);
    assert!(step(&mut log, &mallory, join).is_err());
    assert!(log.role_of(&mallory.client_id).is_none());
}

#[test]
fn a_certificate_from_the_wrong_root_cannot_sign_for_a_member() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    // Alice's account id, but a device certified by a different root.
    let forged_cert = issue_device_cert(
        &[0x77; 32],
        &alice.client_id,
        &[0x01; 16],
        &alice.key.verifying_key().unwrap(),
        u64::MAX,
        1,
    )
    .unwrap();
    let entry = log
        .propose(
            &alice.key,
            &forged_cert,
            add(&user(5), Role::Reader),
            T0 + 1,
        )
        .unwrap();
    assert!(log.append(entry).is_err());
}

#[test]
fn removed_members_lose_all_power_and_may_be_added_again() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Owner)).unwrap();
    step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: bob.client_id,
            commit: [7; 32],
        },
    )
    .unwrap();
    assert!(log.role_of(&bob.client_id).is_none());
    assert!(step(&mut log, &bob, add(&user(7), Role::Reader)).is_err());
    step(&mut log, &alice, add(&bob, Role::Reader)).unwrap();
    assert_eq!(log.role_of(&bob.client_id), Some(Role::Reader));
}

#[test]
fn a_member_can_leave_but_the_last_owner_cannot() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    let with_commit = Action::Remove {
        client_id: bob.client_id,
        commit: [7; 32],
    };
    assert!(
        step(&mut log, &bob, with_commit).is_err(),
        "a member cannot commit to a new seed: it is not an owner"
    );
    let leave = Action::Remove {
        client_id: bob.client_id,
        commit: [0; 32],
    };
    step(&mut log, &bob, leave).unwrap();
    assert!(log.role_of(&bob.client_id).is_none());
    assert_eq!(log.epoch(), 0, "a leave replaces no seed by itself");
    assert!(step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: alice.client_id,
            commit: [7; 32]
        }
    )
    .is_err());
    let demote = Action::SetRole {
        client_id: alice.client_id,
        role: Role::Reader,
    };
    assert!(step(&mut log, &alice, demote).is_err());
    step(&mut log, &alice, add(&bob, Role::Owner)).unwrap();
    step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: alice.client_id,
            commit: [7; 32],
        },
    )
    .unwrap();
    assert_eq!(log.members().len(), 1);
}

#[test]
fn duplicates_and_unknown_targets_are_refused() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    assert!(step(&mut log, &alice, add(&alice, Role::Writer)).is_err());
    assert!(step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: bob.client_id,
            commit: [7; 32]
        }
    )
    .is_err());
    let promote = Action::SetRole {
        client_id: bob.client_id,
        role: Role::Owner,
    };
    assert!(step(&mut log, &alice, promote).is_err());
}

#[test]
fn a_log_replays_to_the_same_state_under_its_anchor_only() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    let replay = MemberLog::from_entries(VAULT, log.entries(), log.anchor()).unwrap();
    assert_eq!(replay.members(), log.members());
    assert_eq!(replay.head(), log.head());

    assert!(MemberLog::from_entries(VAULT, log.entries(), &[0; 32]).is_err());
    assert!(MemberLog::from_entries([0x56; 16], log.entries(), log.anchor()).is_err());
    assert!(MemberLog::from_entries(VAULT, &[], log.anchor()).is_err());
    let other = created_by(&user(4));
    assert!(MemberLog::from_entries(VAULT, log.entries(), other.anchor()).is_err());
}

#[test]
fn a_fork_a_gap_and_a_replay_are_told_apart() {
    let (alice, bob, carol) = (user(1), user(2), user(3));
    let mut log = created_by(&alice);
    let first = log
        .propose(&alice.key, &alice.cert, add(&bob, Role::Writer), T0 + 1)
        .unwrap();
    let rival = log
        .propose(&alice.key, &alice.cert, add(&carol, Role::Writer), T0 + 1)
        .unwrap();
    log.append(first.clone()).unwrap();
    log.append(first.clone()).unwrap();
    assert_eq!(
        log.append(rival).unwrap_err().to_string(),
        "member log fork"
    );

    let skipped = Entry { seq: 5, ..first };
    assert_eq!(
        log.append(skipped).unwrap_err().to_string(),
        "member log gap"
    );
    assert_eq!(log.entries().len(), 2);
}

#[test]
fn every_signed_field_breaks_the_entry() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    let base = log
        .propose(&alice.key, &alice.cert, add(&bob, Role::Writer), T0 + 1)
        .unwrap();
    let mut variants = vec![
        Entry {
            at_ms: base.at_ms + 1,
            ..base.clone()
        },
        Entry {
            prev_hash: [1; 32],
            ..base.clone()
        },
        Entry {
            vault_id: [1; 16],
            ..base.clone()
        },
        Entry {
            action: add(&bob, Role::Owner),
            ..base.clone()
        },
        Entry {
            action: add(&user(3), Role::Writer),
            ..base.clone()
        },
        Entry {
            signature: vec![0; base.signature.len()],
            ..base.clone()
        },
    ];
    let mut swapped = base.clone();
    swapped.signer.serial += 1;
    variants.push(swapped);
    for variant in variants {
        assert!(log.append(variant).is_err());
    }
    assert_eq!(log.entries().len(), 1);
    log.append(base).unwrap();
}

#[test]
fn the_genesis_must_be_self_certified_and_make_its_signer_the_owner() {
    let (alice, bob) = (user(1), user(2));
    let log = created_by(&alice);
    let genuine = log.entries()[0].clone();
    let anchor = |entry: &Entry| entry.hash().unwrap();

    let other_owner = Entry {
        action: add(&bob, Role::Owner),
        ..genuine.clone()
    };
    assert!(MemberLog::from_entries(
        VAULT,
        std::slice::from_ref(&other_owner),
        &anchor(&other_owner)
    )
    .is_err());
    let as_writer = Entry {
        action: add(&alice, Role::Writer),
        ..genuine.clone()
    };
    assert!(
        MemberLog::from_entries(VAULT, std::slice::from_ref(&as_writer), &anchor(&as_writer))
            .is_err()
    );
    let late = Entry { seq: 1, ..genuine };
    assert!(MemberLog::from_entries(VAULT, std::slice::from_ref(&late), &anchor(&late)).is_err());
}

#[test]
fn the_log_is_bounded() {
    let alice = user(1);
    let mut log = created_by(&alice);
    let bob = user(2);
    for round in 0..(MAX_ENTRIES - 1) {
        let action = if round % 2 == 0 {
            add(&bob, Role::Reader)
        } else {
            Action::Remove {
                client_id: bob.client_id,
                commit: [7; 32],
            }
        };
        step(&mut log, &alice, action).unwrap();
    }
    assert_eq!(log.entries().len(), MAX_ENTRIES);
    assert!(step(&mut log, &alice, add(&bob, Role::Reader)).is_err());
}

#[test]
fn the_wire_form_is_canonical_strict_and_chains_by_hash() {
    let (alice, bob) = (user(1), user(2));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    step(
        &mut log,
        &alice,
        Action::SetRole {
            client_id: bob.client_id,
            role: Role::Reader,
        },
    )
    .unwrap();
    step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: bob.client_id,
            commit: [7; 32],
        },
    )
    .unwrap();
    for entry in log.entries() {
        let bytes = entry.encode().unwrap();
        assert_eq!(bytes.len(), ENTRY_WIRE_LEN);
        assert_eq!(&bytes[..6], b"ZPML\x00\x02");
        assert_eq!(&Entry::decode(&bytes).unwrap(), entry);
        for len in (0..bytes.len()).step_by(997) {
            assert!(Entry::decode(&bytes[..len]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Entry::decode(&trailing).is_err());
    }
    let entries = log.entries();
    assert_eq!(entries[1].prev_hash, entries[0].hash().unwrap());
    assert_eq!(entries[2].prev_hash, entries[1].hash().unwrap());

    // A non-canonical unused field is rejected, so an entry has one hash.
    let remove = entries[3].encode().unwrap();
    let vk_at = 4 + 2 + 16 + 8 + 32 + 8 + 1 + 1 + 64 + 32;
    let mut stuffed = remove.clone();
    stuffed[vk_at] = 1;
    assert!(Entry::decode(&stuffed).is_err());
    let mut role_on_remove = remove;
    role_on_remove[4 + 2 + 16 + 8 + 32 + 8 + 1] = 2;
    assert!(Entry::decode(&role_on_remove).is_err());
}

#[test]
fn owner_removals_and_rotations_count_epochs_and_carry_commitments() {
    let (alice, bob, carol) = (user(1), user(2), user(3));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    step(&mut log, &alice, add(&carol, Role::Writer)).unwrap();
    assert_eq!(log.epoch(), 0);
    assert!(log.commit_for(0).is_none());
    assert!(log.commit_for(1).is_none());

    let first = rotation_commit(&VAULT, 1, &[5; 64]);
    step(
        &mut log,
        &alice,
        Action::Remove {
            client_id: bob.client_id,
            commit: first,
        },
    )
    .unwrap();
    assert_eq!(log.epoch(), 1);
    assert_eq!(log.commit_for(1), Some(&first));

    let second = rotation_commit(&VAULT, 2, &[6; 64]);
    step(&mut log, &alice, Action::Rotate { commit: second }).unwrap();
    assert_eq!(log.epoch(), 2);
    assert_eq!(log.commit_for(2), Some(&second));
    assert_eq!(log.commit_for(1), Some(&first));

    let replay = MemberLog::from_entries(VAULT, log.entries(), log.anchor()).unwrap();
    assert_eq!(replay.epoch(), 2);
    assert_eq!(replay.commit_for(2), Some(&second));
}

#[test]
fn a_removal_by_an_owner_without_a_commitment_and_a_rotation_by_a_member_are_refused() {
    let (alice, bob, carol) = (user(1), user(2), user(3));
    let mut log = created_by(&alice);
    step(&mut log, &alice, add(&bob, Role::Writer)).unwrap();
    step(&mut log, &alice, add(&carol, Role::Writer)).unwrap();
    let silent = Action::Remove {
        client_id: bob.client_id,
        commit: [0; 32],
    };
    assert!(step(&mut log, &alice, silent).is_err());
    assert!(step(&mut log, &alice, Action::Rotate { commit: [0; 32] }).is_err());
    assert!(step(&mut log, &bob, Action::Rotate { commit: [9; 32] }).is_err());
    assert_eq!(log.epoch(), 0);
    assert!(log.role_of(&bob.client_id).is_some());
}

#[test]
fn the_commitment_binds_the_vault_the_epoch_and_the_seed() {
    let base = rotation_commit(&VAULT, 1, &[5; 64]);
    assert_eq!(base, rotation_commit(&VAULT, 1, &[5; 64]));
    assert_ne!(base, rotation_commit(&[0; 16], 1, &[5; 64]));
    assert_ne!(base, rotation_commit(&VAULT, 2, &[5; 64]));
    assert_ne!(base, rotation_commit(&VAULT, 1, &[6; 64]));
    assert_ne!(base, [0u8; 32]);
}

#[test]
fn a_rotate_entry_is_canonical_on_the_wire() {
    let alice = user(1);
    let mut log = created_by(&alice);
    step(&mut log, &alice, Action::Rotate { commit: [4; 32] }).unwrap();
    let bytes = log.entries()[1].encode().unwrap();
    assert_eq!(&bytes[..6], b"ZPML\x00\x02");
    assert_eq!(&Entry::decode(&bytes).unwrap(), &log.entries()[1]);
    let account_at = 4 + 2 + 16 + 8 + 32 + 8 + 1 + 1;
    let mut named = bytes.clone();
    named[account_at] = 1;
    assert!(
        Entry::decode(&named).is_err(),
        "a rotation names no account"
    );
    let mut empty = bytes;
    for byte in &mut empty[account_at + 64..account_at + 96] {
        *byte = 0;
    }
    assert!(Entry::decode(&empty).is_err(), "a rotation must commit");
}
