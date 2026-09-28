#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    reason = "tests may unwrap, index, cast counters to byte patterns, and build sntrup keys"
)]

//! Envelope-encryption conformance matrix for zebrapass (BRBY v2 = GEE1).
//!
//! Reference: Hirose & Minematsu, "Envelope Encryption in the Symmetric-Key
//! Setting" (eprint 2023-1727). zebrapass instantiates GEE1: DEK = vault key
//! vk[32] (one-time AEAD domain), KEKs = password wrap (Argon2id -> AEGIS-256)
//! and device wrap (P-256 ECDH + ML-KEM-768 -> HKDF-SHA512 -> AEGIS-256), body
//! = AEGIS-256 or Kuznyechik-CTR + HMAC-SHA256, commit = HMAC-SHA256 over
//! `header || wrapdir || body`.
//!
//! Sections: CORRECTNESS (Dec, §3), CONF (§4.1), INT (§4.2), KCI (committing,
//! §2.1), MU-UNLKAG (§5), POLICY (KDF bounds), FRESHNESS (nonce reuse).

mod common;

use aead::BodyAlg;
use container::{VaultFile, COMMIT_LEN, HEADER_LEN, KDF_M_KIB_MAX, KDF_M_KIB_MIN, KDF_T_MIN};
use kdf::{derive_vault_keys, KdfProfile};
use secret::Secret;
use session::{
    add_chip_unlock, change_master, create, remove_chip_unlock, unlock, ChipKeys, Seen, UnlockCreds,
};

const SEED: [u8; 64] = [0x5E; 64];
const SEED2: [u8; 64] = [0x6E; 64];

// Byte offsets in a freshly created one-password-entry file:
// [header 72][count 2][generation 8][entry hdr 6][kid 8][nonce 32][ct 32][tag 32][body][commit 32]
const OFF_COUNT: usize = HEADER_LEN; // 72
const OFF_DIR_GEN: usize = HEADER_LEN + 2; // 74
const OFF_ENTRY: usize = OFF_DIR_GEN + 8; // 82
const OFF_KID: usize = OFF_ENTRY + 6; // 88
const OFF_NONCE: usize = OFF_KID + 8; // 96
const OFF_CT: usize = OFF_NONCE + 32; // 128
const OFF_TAG: usize = OFF_CT + 32; // 160
const ENTRY_END: usize = OFF_TAG + 32; // 192

fn flip(file: &VaultFile, index: usize) -> VaultFile {
    let mut bytes = file.as_bytes().to_vec();
    *bytes.get_mut(index).unwrap() ^= 0x01;
    VaultFile::new(bytes)
}

fn set_u32_le(file: &VaultFile, offset: usize, value: u32) -> VaultFile {
    let mut bytes = file.as_bytes().to_vec();
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    VaultFile::new(bytes)
}

fn body_span(file: &VaultFile) -> (usize, usize) {
    let body_len = file.parse().unwrap().body.len();
    let end = file.as_bytes().len() - COMMIT_LEN;
    (end - body_len, end)
}

// ---------------------------------------------------------------------------
// CORRECTNESS — §3 Dec: every wrapped KEK path must reproduce the same DEK.
// ---------------------------------------------------------------------------

#[test]
fn gee1_correctness_password_and_device_lifecycle() {
    // GEE1 = (KEKGen, DEKGen, Enc, Wrap, Dec): create seals an empty record
    // body; Wrap adds KEKs; Dec must work through any wrap.
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    assert_eq!(session.generation(), 1);

    let s = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
    assert_eq!(s.generation(), 1);
    assert_eq!(s.commit_tag(), session.commit_tag());

    let key1 = common::enroll(&mut session, &mut file);
    assert_eq!(session.generation(), 2);
    let key2 = common::enroll(&mut session, &mut file);
    assert_eq!(session.generation(), 3);

    // Dec via device 1, device 2, and password: same underlying vault key.
    let s1 = common::unlock_device(&file, &key1).unwrap();
    let s2 = common::unlock_device(&file, &key2).unwrap();
    let sp = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
    assert_eq!(s1.commit_tag(), s2.commit_tag());
    assert_eq!(s2.commit_tag(), sp.commit_tag());
    assert_eq!(s1.generation(), 3);
}

#[test]
fn gee1_wrap_rotation_leaves_body_bytes_untouched() {
    // GEE1 Wrap replaces wrapped-DEK entries without touching C (the body).
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let body_before = {
        let (a, b) = body_span(&file);
        file.as_bytes()[a..b].to_vec()
    };
    change_master(&mut session, &mut file, &SEED2, &[]).unwrap();
    assert_eq!(session.generation(), 2);
    let body_after = {
        let (a, b) = body_span(&file);
        file.as_bytes()[a..b].to_vec()
    };
    assert_eq!(body_before, body_after);

    // New KEK opens, old KEK does not.
    unlock(&file, &UnlockCreds::master(&SEED2), None).unwrap();
    assert!(unlock(&file, &UnlockCreds::master(&SEED), None).is_err());
}

#[test]
fn correctness_remove_device_revokes_only_target_kek() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let key1 = common::enroll(&mut session, &mut file);
    let key2 = common::enroll(&mut session, &mut file);
    let before = file.clone();

    remove_chip_unlock(&mut session, &mut file, key1.id()).unwrap();
    // create=1, add=2, add=3, remove=4 — every wrapdir mutation bumps generation.
    assert_eq!(session.generation(), 4);

    // The removed key's shared secret against its old wrap no longer finds a wrap.
    let ss1 = key1
        .ecdh(&common::eph_pub(&before, key1.id()).unwrap())
        .unwrap();
    let creds1 = UnlockCreds::default().with_chip(key1.chip_keys(), *ss1.expose());
    assert!(unlock(&file, &creds1, None).is_err()); // revoked
    common::unlock_device(&file, &key2).unwrap(); // sibling intact
    unlock(&file, &UnlockCreds::master(&SEED), None).unwrap(); // password intact
    assert!(remove_chip_unlock(&mut session, &mut file, key1.id()).is_err()); // already gone
}

#[test]
fn correctness_seen_blocks_rollback_to_older_file() {
    // MU-UNLKAG §5: the caller's Seen rejects an older, still-valid blob.
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let old_file = file.clone();
    change_master(&mut session, &mut file, &SEED2, &[]).unwrap();

    let seen_now = Seen {
        generation: 2,
        commit_tag: *session.commit_tag(),
    };
    unlock(&file, &UnlockCreds::master(&SEED2), Some(seen_now)).unwrap(); // current accepted

    let seen_stale = Seen {
        generation: 2,
        commit_tag: *session.commit_tag(),
    };
    assert!(unlock(&old_file, &UnlockCreds::master(&SEED), Some(seen_stale)).is_err()); // rollback

    let seen_same_gen_wrong_tag = Seen {
        generation: 1,
        commit_tag: [0u8; 32],
    };
    assert!(unlock(
        &old_file,
        &UnlockCreds::master(&SEED),
        Some(seen_same_gen_wrong_tag)
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// CONF — §4.1 CONFee: without the KEK no information about M leaks.
// ---------------------------------------------------------------------------

#[test]
fn conf_wrong_password_rejected() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let err = unlock(&file, &UnlockCreds::master(&SEED2), None).unwrap_err();
    // Wrong password and tampered wrap must be indistinguishable.
    assert!(err.to_string().contains("wrap authentication failed"));
}

#[test]
fn conf_wrong_device_secret_same_id_rejected() {
    // KCI: attacker knows the public wrap (id, pks) but not the secrets.
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let real = common::enroll(&mut session, &mut file);
    let (_, forged) = common::device();
    // Same id, the attacker's own ML-KEM seed and P-256 scalar.
    let forged_keys = ChipKeys {
        id: *real.id(),
        pq_sk: Secret::new(*forged.chip_keys().pq_sk.expose()),
    };
    let ss = forged
        .ecdh(&common::eph_pub(&file, real.id()).unwrap())
        .unwrap();
    let creds = UnlockCreds::default().with_chip(&forged_keys, *ss.expose());
    assert_eq!(
        unlock(&file, &creds, None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
}

#[test]
fn conf_cross_vault_transplant_password_wrap_rejected() {
    // Two vaults, same password, different vault_id/salt: the wrapped DEK of
    // vault A must not open vault B (wrap AAD binds the header).
    let (file_a, _sa) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (file_b, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let mut bytes_b = file_b.as_bytes().to_vec();
    bytes_b[OFF_ENTRY..ENTRY_END].copy_from_slice(&file_a.as_bytes()[OFF_ENTRY..ENTRY_END]);
    let forged = VaultFile::new(bytes_b);
    let err = unlock(&forged, &UnlockCreds::master(&SEED), None).unwrap_err();
    assert!(err.to_string().contains("wrap authentication failed"));
}

#[test]
fn conf_cross_vault_transplant_device_wrap_rejected() {
    let (mut file_a, mut session_a) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    common::enroll(&mut session_a, &mut file_a);
    let (file_b, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();

    // Splice A's [password+device] entries in front of B's body.
    let a_bytes = file_a.as_bytes();
    let dev_rec_end = body_span(&file_a).0;
    let mut bytes_b = file_b.as_bytes().to_vec();
    let mut spliced = bytes_b[..OFF_ENTRY].to_vec();
    spliced.extend_from_slice(&a_bytes[OFF_ENTRY..dev_rec_end]);
    spliced.extend_from_slice(&bytes_b[ENTRY_END..]);
    bytes_b = spliced;
    assert!(unlock(&VaultFile::new(bytes_b), &UnlockCreds::master(&SEED), None).is_err());
}

#[test]
fn conf_cross_vault_body_swap_rejected() {
    let (file_a, _sa) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (file_b, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (ab, ae) = body_span(&file_a);
    let mut bytes_b = file_b.as_bytes().to_vec();
    let (bb, _be) = body_span(&file_b);
    assert_eq!(ae - ab, 64, "empty-record body is nonce||tag");
    bytes_b[bb..bb + (ae - ab)].copy_from_slice(&file_a.as_bytes()[ab..ae]);
    assert!(unlock(&VaultFile::new(bytes_b), &UnlockCreds::master(&SEED), None).is_err());
}

#[test]
fn conf_cross_vault_tail_swap_rejected() {
    // Swap body+commit wholesale: commit is HMAC under k_commit of vault B,
    // so vault A's tail must fail.
    let (file_a, _sa) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (file_b, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let mut bytes_b = file_b.as_bytes()[..ENTRY_END].to_vec();
    bytes_b.extend_from_slice(&file_a.as_bytes()[ENTRY_END..]);
    assert!(unlock(&VaultFile::new(bytes_b), &UnlockCreds::master(&SEED), None).is_err());
}

// ---------------------------------------------------------------------------
// INT — §4.2 INTee: any modification of (i, A, C, S, H) must yield bottom.
// ---------------------------------------------------------------------------

#[test]
fn int_header_field_flips_all_rejected() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    // magic@0, version@4, kdf_alg@6, kdf_m@8, kdf_t@12, kdf_p@16, salt@20,
    // vault_id@52, body_alg@68, wrap_alg@70.
    for idx in [0, 4, 6, 8, 12, 16, 20, 52, 68, 70] {
        let f = flip(&file, idx);
        assert!(
            unlock(&f, &UnlockCreds::master(&SEED), None).is_err(),
            "header byte {idx} accepted"
        );
    }
}

#[test]
fn int_password_record_field_flips_all_rejected() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    for idx in [OFF_KID, OFF_NONCE, OFF_CT, OFF_TAG] {
        let f = flip(&file, idx);
        let err = unlock(&f, &UnlockCreds::master(&SEED), None).unwrap_err();
        assert!(
            err.to_string().contains("wrap authentication failed"),
            "byte {idx}"
        );
    }
}

#[test]
fn int_device_record_field_flips_all_rejected() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let key = common::enroll(&mut session, &mut file);
    // The shared secret the device would compute against the untampered wrap.
    let ss = key
        .ecdh(&common::eph_pub(&file, key.id()).unwrap())
        .unwrap();
    let creds = UnlockCreds::default().with_chip(key.chip_keys(), *ss.expose());

    // Device entry starts right after the password entry: header, id,
    // chip_pub(65), eph_pub(65), pq_pk(1184), kem_ct(1088), nonce, ct, tag.
    let off_id = ENTRY_END + 6;
    let off_chip_pub = off_id + 16 + 1;
    let off_eph = off_chip_pub + 65;
    let off_pq_pk = off_eph + 65;
    let off_kem_ct = off_pq_pk + 1184;
    let off_tail_nonce = body_span(&file).0 - 96;
    let off_tail_ct = off_tail_nonce + 32;
    let off_tail_tag = off_tail_ct + 32;
    for idx in [
        off_id,
        off_chip_pub,
        off_eph,
        off_pq_pk,
        off_kem_ct,
        off_tail_nonce,
        off_tail_ct,
        off_tail_tag,
    ] {
        let f = flip(&file, idx);
        assert!(unlock(&f, &creds, None).is_err(), "device byte {idx}");
    }
    // Sanity: untampered device still opens.
    unlock(&file, &creds, None).unwrap();
}

#[test]
fn int_wrapdir_generation_flip_detected_by_commit() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    // wrap_count@72 and generation@74 are covered by the commit HMAC.
    for idx in [OFF_COUNT, OFF_DIR_GEN] {
        let f = flip(&file, idx);
        assert!(
            unlock(&f, &UnlockCreds::master(&SEED), None).is_err(),
            "wrapdir byte {idx}"
        );
    }
}

#[test]
fn int_commit_tag_flip_detected() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let f = flip(&file, file.as_bytes().len() - 1);
    let err = unlock(&f, &UnlockCreds::master(&SEED), None).unwrap_err();
    assert!(err.to_string().contains("commit"), "got: {err}");
}

#[test]
fn int_truncation_and_extension_rejected() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let bytes = file.as_bytes();

    // Below minimum file length.
    let short = VaultFile::new(bytes[..103].to_vec());
    assert!(unlock(&short, &UnlockCreds::master(&SEED), None).is_err());
    // Truncate into the body.
    let cut = VaultFile::new(bytes[..bytes.len() - 40].to_vec());
    assert!(unlock(&cut, &UnlockCreds::master(&SEED), None).is_err());
    // Drop exactly the commit.
    let no_commit = VaultFile::new(bytes[..bytes.len() - 32].to_vec());
    assert!(unlock(&no_commit, &UnlockCreds::master(&SEED), None).is_err());
    // Append junk: commit is the last 32 bytes, so it shifts.
    let mut long = bytes.to_vec();
    long.push(0);
    assert!(unlock(&VaultFile::new(long), &UnlockCreds::master(&SEED), None).is_err());
}

#[test]
fn int_wrapdir_invariants_enforced() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    // A second password entry must not parse (exactly one is required).
    let pw_rec = file.as_bytes()[OFF_ENTRY..ENTRY_END].to_vec();
    let bytes = file.as_bytes().to_vec();
    let mut duplicated = bytes[..ENTRY_END].to_vec();
    duplicated.extend_from_slice(&pw_rec);
    duplicated.extend_from_slice(&bytes[ENTRY_END..]);
    assert!(unlock(
        &VaultFile::new(duplicated),
        &UnlockCreds::master(&SEED),
        None
    )
    .is_err());

    // A repeated device id does not parse.
    let (publics, _key) = common::device();
    assert!(add_chip_unlock(&mut session, &mut file, &publics).is_ok());
    assert!(add_chip_unlock(&mut session, &mut file, &publics).is_err());
}

// ---------------------------------------------------------------------------
// KCI — committing (§2.1, Albertini et al.): key-committing wraps; HKDF
// domain separation must yield independent keys from one DEK.
// ---------------------------------------------------------------------------

#[test]
fn kci_hkdf_domains_distinct_keys() {
    let vk: [u8; 32] = core::array::from_fn(|i| i as u8);
    let vault_a: [u8; 16] = core::array::from_fn(|i| i as u8);
    let vault_b: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0xAA);
    let (k_body, k_bmac, k_commit) = derive_vault_keys(&vk, &vault_a).unwrap();
    assert_ne!(k_body.expose(), k_bmac.expose());
    assert_ne!(k_bmac.expose(), k_commit.expose());
    assert_ne!(k_body.expose(), k_commit.expose());
    assert_ne!(k_body.expose(), &vk);
    let (k_body_b, _m, _c) = derive_vault_keys(&vk, &vault_b).unwrap();
    assert_ne!(
        k_body.expose(),
        k_body_b.expose(),
        "vault_id is the HKDF salt"
    );
}

#[test]
fn kci_no_key_ambiguity_cross_body_with_own_keys() {
    // B's session keys must not decrypt A's body even with B's commit intact
    // at B's tail layout: swap bodies but keep B's commit.
    let (file_a, _sa) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (file_b, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (ab, ae) = body_span(&file_a);
    let (bb, _be) = body_span(&file_b);
    let mut bytes_b = file_b.as_bytes().to_vec();
    bytes_b[bb..bb + (ae - ab)].copy_from_slice(&file_a.as_bytes()[ab..ae]);
    let swapped = VaultFile::new(bytes_b);
    // Body is authenticated under k_body derived from B's vk: must fail.
    assert!(unlock(&swapped, &UnlockCreds::master(&SEED2), None).is_err());
}

// ---------------------------------------------------------------------------
// MU-UNLKAG — §5: multiple wraps, independent Dec per KEK, revocation.
// ---------------------------------------------------------------------------

#[test]
fn mu_three_devices_interleaved_unlocks() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let mut devs = Vec::new();
    for _ in 0..3 {
        devs.push(common::enroll(&mut session, &mut file));
        // Every KEK added so far must open the current file (benign multi-user).
        for key in &devs {
            common::unlock_device(&file, key)
                .unwrap_or_else(|e| panic!("device {:?} failed after add: {e}", &key.id()[..2]));
        }
        unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
    }
    // Revoke the middle device; the others keep working.
    remove_chip_unlock(&mut session, &mut file, devs[1].id()).unwrap();
    assert!(common::unlock_device(&file, &devs[1]).is_err());
    common::unlock_device(&file, &devs[0]).unwrap();
    common::unlock_device(&file, &devs[2]).unwrap();
}

// ---------------------------------------------------------------------------
// POLICY — container limits: Argon2id floor/ceiling, rejected before KDF.
// ---------------------------------------------------------------------------

#[test]
fn policy_kdf_bounds_rejected_pre_argon() {
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    // Below floor: 19 MiB - 1 KiB and t = 1.
    let f = set_u32_le(&file, 8, KDF_M_KIB_MIN - 1);
    let err = unlock(&f, &UnlockCreds::master(&SEED), None).unwrap_err();
    assert!(err.to_string().contains("kdf parameters rejected"));
    let f = set_u32_le(&file, 8, KDF_M_KIB_MAX + 1);
    assert!(unlock(&f, &UnlockCreds::master(&SEED), None).is_err());
    let f = set_u32_le(&file, 12, KDF_T_MIN - 1);
    assert!(unlock(&f, &UnlockCreds::master(&SEED), None).is_err());
}

#[test]
fn policy_kuzmgm_rejected_pre_kdf() {
    // Rejections must bail before any Argon2 work (fast). KuzMgm is
    // recognized on the wire but not sealable in this build, and a master
    // seed is `&[u8; 64]` — an empty master is unrepresentable, so no
    // factor at all is the remaining pre-KDF rejection path.
    let t0 = std::time::Instant::now();
    assert!(create(&SEED, KdfProfile::Fast, BodyAlg::KuzMgm).is_err());
    let (file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    assert!(unlock(&file, &UnlockCreds::default(), None).is_err());
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(30),
        "pre-KDF rejections must not run Argon2"
    );
}

// ---------------------------------------------------------------------------
// FRESHNESS — fresh nonces/kids per seal (nonce misuse resistance baseline).
// ---------------------------------------------------------------------------

#[test]
fn rnd_two_vaults_distinct_kid_nonce_body() {
    let (fa, _sa) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let (fb, _sb) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let a = fa.as_bytes();
    let b = fb.as_bytes();
    assert_ne!(&a[OFF_KID..OFF_NONCE], &b[OFF_KID..OFF_NONCE], "kid");
    assert_ne!(&a[OFF_NONCE..OFF_CT], &b[OFF_NONCE..OFF_CT], "wrap nonce");
    assert_ne!(
        &a[OFF_CT..OFF_TAG],
        &b[OFF_CT..OFF_TAG],
        "wrapping the same password and salt? salt differs, but ct must differ too"
    );
    let (ab, ae) = body_span(&fa);
    let (bb, be) = body_span(&fb);
    assert_ne!(&a[ab..ae], &b[bb..be], "body nonce");
}
