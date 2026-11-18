//! Unit regression tests for `zsync` wire authentication and 1-byte tamper
//! rejection on `RecordCommit`, `SignedHead`, and `SignedRekey`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "unit test file"
)]

use kdf::{personal_envelope_key, storage_id};
use local::SyncIdentity;
use seed::SeedPhrase;
use syncwire::encode_cert;

use crate::auth::{EnvelopePurpose, RecordMeta, seal_blob, sign_head, sign_record, sign_rekey};
use crate::repo::RepoState;
use crate::wire::{HeadVer, RepoKind, SyncDelta};

#[test]
fn one_byte_tamper_in_commit_head_or_rekey_is_rejected() {
    let phrase = SeedPhrase::generate_24().unwrap();
    let sid = storage_id(phrase.seed()).unwrap();
    let dev = [0x44u8; 16];
    let identity = SyncIdentity::enroll(phrase.seed(), &sid, dev, u64::MAX).unwrap();
    let cert_wire = encode_cert(&identity.devices()[0]).unwrap();
    let sign_key = identity.sign_key();
    let gate = identity.account_gate().unwrap();
    let env_key = personal_envelope_key(gate.expose(), &sid).unwrap();

    let mut repo = RepoState::new(RepoKind::Personal, sid);
    let mut init = SyncDelta::empty(RepoKind::Personal, sid);
    init.root_vk = Some(Box::new(*identity.root_vk()));
    init.certs.push(cert_wire);
    let (_, changed) = repo.apply_delta(&init).unwrap();
    assert!(changed);

    // Build valid record, head, and rekey commits.
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
    )
    .unwrap();

    let valid_rekey = sign_rekey(
        &sign_key,
        RepoKind::Personal,
        &sid,
        2,
        dev,
        [0x55u8; 16],
        seal_blob(&env_key, &sid, EnvelopePurpose::PersonalRekey, 2, b"rekey").unwrap(),
    )
    .unwrap();

    // Flip 1 byte in RecordCommit envelope -> rejected.
    let mut bad_rec_env = valid_rec.clone();
    bad_rec_env.envelope[0] ^= 0x80;
    let mut d1 = SyncDelta::empty(RepoKind::Personal, sid);
    d1.records.push(bad_rec_env);
    let (_, ch1) = repo.apply_delta(&d1).unwrap();
    assert!(!ch1);

    // Flip 1 byte in RecordCommit signer_device -> rejected.
    let mut bad_rec_signer = valid_rec.clone();
    bad_rec_signer.signer_device[0] ^= 0x01;
    let mut d1_signer = SyncDelta::empty(RepoKind::Personal, sid);
    d1_signer.records.push(bad_rec_signer);
    let (_, ch1_signer) = repo.apply_delta(&d1_signer).unwrap();
    assert!(!ch1_signer);

    // Flip 1 byte in RecordCommit signature -> rejected.
    let mut bad_rec_sig = valid_rec;
    bad_rec_sig.signature[0] ^= 0x01;
    let mut d2 = SyncDelta::empty(RepoKind::Personal, sid);
    d2.records.push(bad_rec_sig);
    let (_, ch2) = repo.apply_delta(&d2).unwrap();
    assert!(!ch2);

    // Flip 1 byte in SignedHead snapshot -> rejected.
    let mut bad_head = valid_head;
    bad_head.snapshot_env[0] ^= 0x01;
    let mut d3 = SyncDelta::empty(RepoKind::Personal, sid);
    d3.head = Some(bad_head);
    let (_, ch3) = repo.apply_delta(&d3).unwrap();
    assert!(!ch3);

    // Flip 1 byte in SignedRekey signature -> rejected.
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
