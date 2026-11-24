//! Unit regression tests for `zsync` wire authentication, self-certifying
//! repository anchors, and 1-byte tamper rejection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "unit test file"
)]

use kdf::{shared_envelope_key, zsync_vk_envelope_key};
use local::{SharedRepoProof, SyncIdentity};
use memberlog::{Action, MemberLog, Role};
use seed::SeedPhrase;
use syncwire::encode_cert;

use crate::auth::{EnvelopePurpose, RecordMeta, seal_blob, sign_head, sign_record, sign_rekey};
use crate::repo::RepoState;
use crate::wire::{HeadVer, RepoKind, SyncDelta};

#[test]
fn one_byte_tamper_in_commit_head_or_rekey_is_rejected() {
    let phrase = SeedPhrase::generate_24().unwrap();
    let client_id = kdf::client_id(phrase.seed()).unwrap();
    let dev = [0x44u8; 16];
    let identity = SyncIdentity::enroll(phrase.seed(), &client_id, dev, u64::MAX).unwrap();
    let sid = identity.personal_storage_id().unwrap();
    let anchor_wire = identity.personal_anchor().unwrap().encode().unwrap();
    let cert_wire = encode_cert(&identity.devices()[0]).unwrap();
    let sign_key = identity.sign_key();
    let env_key = zsync_vk_envelope_key(&[0x33u8; 32], &sid).unwrap();

    let mut repo = RepoState::new(RepoKind::Personal, sid);
    let mut init = SyncDelta::empty(RepoKind::Personal, sid);
    init.personal_anchor = Some(anchor_wire);
    init.root_vk = Some(Box::new(*identity.root_vk()));
    init.certs.push(cert_wire);
    let (_, changed) = repo.apply_delta(&init).unwrap();
    assert!(changed);

    let rec_env = seal_blob(
        &env_key,
        &sid,
        EnvelopePurpose::PersonalFrame,
        1,
        b"frame-1",
    )
    .unwrap();
    let valid_rec = sign_record(
        &sign_key,
        RecordMeta {
            storage_id: &sid,
            revision: 1,
            key_generation: 1,
            record_id: 1,
            origin_device: dev,
            signer_device: dev,
            kind: RepoKind::Personal,
        },
        rec_env,
    )
    .unwrap();

    let valid_head = sign_head(
        &sign_key,
        RepoKind::Personal,
        &sid,
        HeadVer {
            generation: 1,
            commit_tag: [0x11; 32],
            origin_device: dev,
        },
        seal_blob(&env_key, &sid, EnvelopePurpose::PersonalHead, 1, b"head").unwrap(),
        seal_blob(
            &env_key,
            &sid,
            EnvelopePurpose::PersonalSnapshot,
            1,
            b"snap",
        )
        .unwrap(),
        Some(b"grant-v1".to_vec()),
    )
    .unwrap();

    let valid_rekey = sign_rekey(
        &sign_key,
        RepoKind::Personal,
        &sid,
        2,
        dev,
        [0x55u8; 16],
        b"hybrid-rekey".to_vec(),
    )
    .unwrap();

    let mut bad_rec_env = valid_rec.clone();
    bad_rec_env.envelope[0] ^= 0x80;
    let mut d1 = SyncDelta::empty(RepoKind::Personal, sid);
    d1.records.push(bad_rec_env);
    let (_, ch1) = repo.apply_delta(&d1).unwrap();
    assert!(!ch1);

    let mut bad_rec_signer = valid_rec.clone();
    bad_rec_signer.signer_device[0] ^= 0x01;
    let mut d1_signer = SyncDelta::empty(RepoKind::Personal, sid);
    d1_signer.records.push(bad_rec_signer);
    let (_, ch1_signer) = repo.apply_delta(&d1_signer).unwrap();
    assert!(!ch1_signer);

    let mut bad_rec_sig = valid_rec;
    bad_rec_sig.signature[0] ^= 0x01;
    let mut d2 = SyncDelta::empty(RepoKind::Personal, sid);
    d2.records.push(bad_rec_sig);
    let (_, ch2) = repo.apply_delta(&d2).unwrap();
    assert!(!ch2);

    let mut bad_head = valid_head.clone();
    bad_head.snapshot_env[0] ^= 0x01;
    let mut d3 = SyncDelta::empty(RepoKind::Personal, sid);
    d3.head = Some(bad_head);
    let (_, ch3) = repo.apply_delta(&d3).unwrap();
    assert!(!ch3);

    // Stripping master_grant from SignedHead must also break its signature.
    let mut stripped_grant_head = valid_head;
    stripped_grant_head.master_grant = None;
    let mut d3b = SyncDelta::empty(RepoKind::Personal, sid);
    d3b.head = Some(stripped_grant_head);
    let (_, ch3b) = repo.apply_delta(&d3b).unwrap();
    assert!(!ch3b);

    let mut bad_rekey = valid_rekey;
    bad_rekey.signature[0] ^= 0x01;
    let mut d4 = SyncDelta::empty(RepoKind::Personal, sid);
    d4.rekeys.push(bad_rekey);
    let (_, ch4) = repo.apply_delta(&d4).unwrap();
    assert!(!ch4);
    assert!(repo.records.is_empty());
    assert!(repo.head.is_none());
    assert!(repo.rekeys.is_empty());
}

#[test]
fn shared_repo_accepts_v3_admin_member_and_commits() {
    let owner_phrase = SeedPhrase::generate_24().unwrap();
    let owner_cid = kdf::client_id(owner_phrase.seed()).unwrap();
    let owner_dev = [0x11u8; 16];
    let owner = SyncIdentity::enroll(owner_phrase.seed(), &owner_cid, owner_dev, u64::MAX).unwrap();

    let admin_phrase = SeedPhrase::generate_24().unwrap();
    let admin_cid = kdf::client_id(admin_phrase.seed()).unwrap();
    let admin_dev = [0x22u8; 16];
    let admin = SyncIdentity::enroll(admin_phrase.seed(), &admin_cid, admin_dev, u64::MAX).unwrap();

    let shared_seed = [0x77u8; 64];
    let vault_id = [0x33u8; 16];
    let now_ms = 1_700_000_000_000u64;

    let mut log = MemberLog::genesis(
        vault_id,
        &owner.sign_key(),
        &owner.devices()[0],
        owner.root_vk(),
        now_ms,
    )
    .unwrap();
    let add_admin = log
        .propose(
            &owner.sign_key(),
            &owner.devices()[0],
            Action::Add {
                client_id: admin.devices()[0].client_id,
                root_vk: Box::new(*admin.root_vk()),
                role: Role::Admin,
            },
            now_ms + 1,
        )
        .unwrap();
    log.append(add_admin).unwrap();

    let (proof, shared_sid) =
        SharedRepoProof::issue(&shared_seed, vault_id, *log.anchor()).unwrap();
    let mut repo = RepoState::new(RepoKind::Shared, shared_sid);
    let mut delta = SyncDelta::empty(RepoKind::Shared, shared_sid);
    delta.shared_proof = Some(proof.encode().unwrap());
    delta.member_entries = log.entries().iter().map(|e| e.encode().unwrap()).collect();
    delta.certs.push(encode_cert(&admin.devices()[0]).unwrap());

    let env_key = shared_envelope_key(&shared_seed, &shared_sid).unwrap();
    let rec_env = seal_blob(
        &env_key,
        &shared_sid,
        EnvelopePurpose::SharedFrame,
        1,
        b"rec",
    )
    .unwrap();
    let admin_rec = sign_record(
        &admin.sign_key(),
        RecordMeta {
            storage_id: &shared_sid,
            revision: 1,
            key_generation: 1,
            record_id: 42,
            origin_device: admin_dev,
            signer_device: admin_dev,
            kind: RepoKind::Shared,
        },
        rec_env,
    )
    .unwrap();
    delta.records.push(admin_rec);

    let (accepted, changed) = repo.apply_delta(&delta).unwrap();
    assert!(changed);
    assert_eq!(accepted.member_entries.len(), 2);
    assert_eq!(accepted.certs.len(), 1);
    assert_eq!(accepted.records.len(), 1);
    assert!(repo.records.contains_key(&42));
}

#[test]
fn tofu_squatting_phantom_repo_and_revision_overflow_are_rejected() {
    let dir = std::env::temp_dir().join(format!("zp-zsync-unit-{}", crate::auth::now_ms()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = crate::repo_disk::RepoStore::open(&dir).unwrap();

    let victim_phrase = SeedPhrase::generate_24().unwrap();
    let victim_client = kdf::client_id(victim_phrase.seed()).unwrap();
    let victim =
        SyncIdentity::enroll(victim_phrase.seed(), &victim_client, [0x01; 16], u64::MAX).unwrap();
    let victim_repo_id = victim.personal_storage_id().unwrap();

    let attacker_phrase = SeedPhrase::generate_24().unwrap();
    let attacker_cid = kdf::client_id(attacker_phrase.seed()).unwrap();
    let attacker =
        SyncIdentity::enroll(attacker_phrase.seed(), &attacker_cid, [0x02; 16], u64::MAX).unwrap();

    // 1. Attacker attempts TOFU squatting on victim's personal storage_id with attacker's anchor/root_vk.
    let mut squat = SyncDelta::empty(RepoKind::Personal, victim_repo_id);
    squat.personal_anchor = Some(attacker.personal_anchor().unwrap().encode().unwrap());
    squat.root_vk = Some(Box::new(*attacker.root_vk()));
    squat
        .certs
        .push(encode_cert(&attacker.devices()[0]).unwrap());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_, changed) = rt.block_on(store.apply_and_save(&squat)).unwrap();
    assert!(!changed, "TOFU squatting on personal repo must be rejected");
    assert_eq!(
        store.repo_count(),
        0,
        "rejected delta must leave zero phantom entries in RepoStore"
    );

    // 2. Attacker attempts TOFU squatting on victim's shared storage_id with attacker's SharedRepoProof.
    let (_, victim_shared_sid) =
        SharedRepoProof::issue(&[0xAA; 64], [0xBB; 16], [0xCC; 32]).unwrap();
    let (att_proof, _) = SharedRepoProof::issue(&[0xDD; 64], [0xBB; 16], [0xCC; 32]).unwrap();
    let att_log = MemberLog::genesis(
        [0xBB; 16],
        &attacker.sign_key(),
        &attacker.devices()[0],
        attacker.root_vk(),
        1_700_000_000_000,
    )
    .unwrap();
    let mut shared_squat = SyncDelta::empty(RepoKind::Shared, victim_shared_sid);
    shared_squat.shared_proof = Some(att_proof.encode().unwrap());
    shared_squat.member_entries = vec![att_log.entries()[0].encode().unwrap()];
    let (_, sh_changed) = rt.block_on(store.apply_and_save(&shared_squat)).unwrap();
    assert!(
        !sh_changed,
        "TOFU squatting on shared repo must be rejected"
    );
    assert_eq!(store.repo_count(), 0);

    // 3. Victim initializes legitimately, then attempts revision = u64::MAX: record rejected!
    let mut legit = SyncDelta::empty(RepoKind::Personal, victim_repo_id);
    legit.personal_anchor = Some(victim.personal_anchor().unwrap().encode().unwrap());
    legit.root_vk = Some(Box::new(*victim.root_vk()));
    legit.certs.push(encode_cert(&victim.devices()[0]).unwrap());
    let (_, ok_init) = rt.block_on(store.apply_and_save(&legit)).unwrap();
    assert!(ok_init);
    assert_eq!(store.repo_count(), 1);

    let env_key = zsync_vk_envelope_key(&[0x42; 32], &victim_repo_id).unwrap();
    let max_env = seal_blob(
        &env_key,
        &victim_repo_id,
        EnvelopePurpose::PersonalFrame,
        u64::MAX,
        b"max-rev",
    )
    .unwrap();
    let max_rec = sign_record(
        &victim.sign_key(),
        RecordMeta {
            storage_id: &victim_repo_id,
            revision: u64::MAX,
            key_generation: 1,
            record_id: 9,
            origin_device: [0x01; 16],
            signer_device: [0x01; 16],
            kind: RepoKind::Personal,
        },
        max_env,
    )
    .unwrap();
    let mut d_max = SyncDelta::empty(RepoKind::Personal, victim_repo_id);
    d_max.records.push(max_rec);
    let (_, ch_max) = rt.block_on(store.apply_and_save(&d_max)).unwrap();
    assert!(!ch_max, "server must reject revision = u64::MAX");

    let _ = std::fs::remove_dir_all(&dir);
}
