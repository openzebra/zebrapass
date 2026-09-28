#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    reason = "tests may unwrap, index, and build sntrup keys"
)]

use aead::BodyAlg;
mod common;

use container::{
    assemble, encode_password_entry, encode_wrap_dir, StaticHeader, VaultFile, WrapEntry,
    BODY_AEGIS256, BODY_KUZ_CTR_HMAC, COMMIT_LEN, HEADER_LEN, KDF_ARGON2ID, KDF_M_KIB_MAX,
    KDF_P_MIN, KDF_T_MIN, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN, WRAP_AEGIS256,
};
use kdf::KdfProfile;
use local::DeviceKey;
use record::Document;
use session::{
    add_chip_unlock, add_prf_unlock, change_master, create, list_records, reencrypt_body,
    remove_chip_unlock, remove_prf_unlock, revoke, unlock, write_record, ChipPublics, Revoke,
    RotateCreds, Seen, Session, UnlockCreds,
};
use wraps::PrfPublics;

const SEED_AEGIS: [u8; 64] = [0xA1; 64];
const SEED_KUZ: [u8; 64] = [0xB2; 64];
const SEED_ROTATED: [u8; 64] = [0xC3; 64];
const SEED_NEXT: [u8; 64] = [0xD4; 64];
const SEED_DESKTOP: [u8; 64] = [0xE5; 64];

const PASSWORD_CT_OFFSET: usize =
    HEADER_LEN + 2 + 8 + (PASSWORD_RECORD_LEN - PASSWORD_PAYLOAD_LEN) + 8 + 32;

#[test]
fn vault_operations_mobile_and_one_desktop() {
    // One function so cargo does not run these Argon2 allocations in parallel.
    // Fast (64 MiB) covers tamper and mutation. Balanced (256 MiB) runs once.
    reject_before_argon();
    let (aegis, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let (kuz, _kuz_session) = round_trip(&SEED_KUZ, BodyAlg::KuzCtrHmac);
    tamper(&aegis, &SEED_AEGIS);
    transplant(&aegis, &kuz);
    let mut file = aegis;
    reject_invalid_device_key(&mut session, &mut file);
    let device = add_and_check(&mut session, &mut file);
    reencrypt_and_check(&mut session, &mut file, &device);
    change_master_and_check(&mut session, &mut file);
    write_and_check(&mut session, &mut file);
    remove_and_check(&mut session, &mut file, device.id());
    desktop_once();
}

fn reject_before_argon() {
    assert_eq!(
        create(&SEED_KUZ, KdfProfile::Fast, BodyAlg::KuzMgm)
            .unwrap_err()
            .to_string(),
        "unsupported body algorithm 0xa002"
    );
    let header = StaticHeader {
        kdf_alg: KDF_ARGON2ID,
        kdf_m_kib: KDF_M_KIB_MAX + 1,
        kdf_t: KDF_T_MIN,
        kdf_p: KDF_P_MIN,
        kdf_salt: [1; 32],
        vault_id: [2; 16],
        body_alg: BODY_AEGIS256,
        wrap_alg: WRAP_AEGIS256,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; COMMIT_LEN]);
    assert_eq!(
        unlock(
            &VaultFile::new(bytes),
            &UnlockCreds::master(&SEED_AEGIS),
            None
        )
        .unwrap_err()
        .to_string(),
        "kdf parameters rejected"
    );
    // Non-BRBY bytes are rejected before Argon2 runs.
    assert_eq!(
        unlock(
            &VaultFile::new(b"v1-vault-no-magic".to_vec()),
            &UnlockCreds::master(&SEED_AEGIS),
            None
        )
        .unwrap_err()
        .to_string(),
        "bad magic"
    );
}

fn round_trip(master: &[u8; 64], alg: BodyAlg) -> (VaultFile, Session) {
    let (file, session) = create(master, KdfProfile::Fast, alg).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, &UnlockCreds::master(master), None).unwrap();
    assert_eq!(opened.generation(), session.generation());
    assert_eq!(opened.commit_tag(), session.commit_tag());
    (file, session)
}

fn tamper(file: &VaultFile, master: &[u8; 64]) {
    assert_eq!(
        unlock(file, &UnlockCreds::master(&SEED_KUZ), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    let flipped_header = flip_at(file, 20);
    assert_eq!(
        unlock(&flipped_header, &UnlockCreds::master(master), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    let flipped_body = flip_at(file, body_offset(file));
    assert_eq!(
        unlock(&flipped_body, &UnlockCreds::master(master), None)
            .unwrap_err()
            .to_string(),
        "commit mismatch"
    );
    let parsed = file.parse().unwrap();
    let WrapEntry::Password(wrap) = &parsed.entries[0] else {
        panic!("password wrap");
    };
    assert_eq!(file.as_bytes()[PASSWORD_CT_OFFSET], wrap.ct[0]);
    let flipped_ct = flip_at(file, PASSWORD_CT_OFFSET);
    assert_eq!(
        unlock(&flipped_ct, &UnlockCreds::master(master), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    let swapped_alg = set_body_alg(file, BODY_KUZ_CTR_HMAC);
    assert_eq!(
        unlock(&swapped_alg, &UnlockCreds::master(master), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
}

fn transplant(aegis: &VaultFile, kuz: &VaultFile) {
    let foreign = password_record(aegis);
    let mixed = with_password_record(kuz, &foreign);
    assert_eq!(
        unlock(&mixed, &UnlockCreds::master(&SEED_AEGIS), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    // B's password wrap stays. A's record replaces the body, so the commit is stale.
    let spliced = replace_body(kuz, &foreign);
    assert_eq!(
        unlock(&spliced, &UnlockCreds::master(&SEED_KUZ), None)
            .unwrap_err()
            .to_string(),
        "commit mismatch"
    );
}

fn reject_invalid_device_key(session: &mut Session, file: &mut VaultFile) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let tag = *session.commit_tag();
    let (valid, _) = common::device();
    let dev = ChipPublics {
        chip_pub: [0; 65],
        ..valid
    };
    assert_eq!(
        add_chip_unlock(session, file, &dev)
            .unwrap_err()
            .to_string(),
        "kem length"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
    assert_eq!(session.generation(), generation);
    assert_eq!(session.commit_tag(), &tag);
}

fn add_and_check(session: &mut Session, file: &mut VaultFile) -> DeviceKey {
    let body_before = body_of(file);
    let generation = session.generation();
    let (publics, device) = common::device();
    let grant = add_chip_unlock(session, file, &publics).unwrap();
    assert_eq!(body_of(file), body_before);
    assert_eq!(session.generation(), generation + 1);
    assert_eq!(file.parse().unwrap().generation, generation + 1);
    assert!(grant.as_bytes().starts_with(&header_bytes(file)));
    let after_add = file.as_bytes().to_vec();
    let generation_after = session.generation();
    let tag_after = *session.commit_tag();
    assert_eq!(
        add_chip_unlock(session, file, &publics)
            .unwrap_err()
            .to_string(),
        "corrupted length"
    );
    assert_eq!(file.as_bytes(), after_add.as_slice());
    assert_eq!(session.generation(), generation_after);
    assert_eq!(session.commit_tag(), &tag_after);
    let opened = unlock(file, &UnlockCreds::master(&SEED_AEGIS), None).unwrap();
    assert_eq!(opened.generation(), session.generation());
    assert_eq!(opened.commit_tag(), session.commit_tag());
    device
}

fn reencrypt_and_check(session: &mut Session, file: &mut VaultFile, device: &DeviceKey) {
    // One real record so the rotated log is a well-formed frame log
    // (write_record below indexes the session log).
    write_record(session, file, None, &doc("pre-rotation")).unwrap();
    reencrypt_body(session, file, &SEED_ROTATED, &[]).unwrap();
    assert_eq!(
        unlock(file, &UnlockCreds::master(&SEED_AEGIS), None)
            .unwrap_err()
            .to_string(),
        "wrap authentication failed"
    );
    let opened = unlock(file, &UnlockCreds::master(&SEED_ROTATED), None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
    assert_eq!(
        list_records(&opened).unwrap().len(),
        1,
        "reencrypt keeps records"
    );
    let via_device = common::unlock_device(file, device).unwrap();
    assert_eq!(via_device.generation(), session.generation());
    assert_eq!(via_device.commit_tag(), session.commit_tag());
}

fn change_master_and_check(session: &mut Session, file: &mut VaultFile) {
    let header_before = header_bytes(file);
    let body_before = body_of(file);
    let old = VaultFile::new(file.as_bytes().to_vec());
    change_master(session, file, &SEED_NEXT, &[]).unwrap();
    assert_eq!(header_bytes(file), header_before);
    assert_eq!(body_of(file), body_before);
    let seen = Seen {
        generation: session.generation(),
        commit_tag: *session.commit_tag(),
    };
    assert_eq!(
        unlock(&old, &UnlockCreds::master(&SEED_ROTATED), Some(seen))
            .unwrap_err()
            .to_string(),
        "rollback"
    );
    let opened_old = unlock(&old, &UnlockCreds::master(&SEED_ROTATED), None).unwrap();
    assert_eq!(opened_old.generation() + 1, session.generation());
    unlock(file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
}

fn doc(title: &str) -> record::Document {
    let mut doc = record::Document::new();
    doc.set_text(record::TAG_TITLE, title);
    doc
}

fn reopened_len(file: &VaultFile, master: &[u8; 64]) -> usize {
    list_records(&unlock(file, &UnlockCreds::master(master), None).unwrap())
        .unwrap()
        .len()
}

/// Reopening from disk must show exactly what the live session shows, for
/// every body algorithm (regression: whole-body vaults used to keep only
/// the last write; revoke used to drop every record).
#[test]
fn mutations_survive_reopen_for_every_body_alg() {
    for (master, alg) in [
        (&SEED_AEGIS, BodyAlg::Aegis256),
        (&SEED_KUZ, BodyAlg::KuzCtrHmac),
    ] {
        let (mut file, mut session) = round_trip(master, alg);
        for title in ["first", "second", "third"] {
            write_record(&mut session, &mut file, None, &doc(title)).unwrap();
        }
        assert_eq!(list_records(&session).unwrap().len(), 3);
        assert_eq!(reopened_len(&file, master), 3, "{alg:?}: writes");

        // The full rotation path (rotate_all, drop = None) must keep every
        // record — revoke used to publish an empty log (A2).
        change_master(&mut session, &mut file, &SEED_ROTATED, &[]).unwrap();
        assert_eq!(
            list_records(&session).unwrap().len(),
            3,
            "{alg:?}: rotate live"
        );
        assert_eq!(
            reopened_len(&file, &SEED_ROTATED),
            3,
            "{alg:?}: rotate reopen"
        );
    }
}

fn write_and_check(session: &mut Session, file: &mut VaultFile) {
    let wraps_before = entry_wire(file);
    let generation = session.generation();
    write_record(session, file, None, &doc("write-and-check")).unwrap();
    assert_eq!(entry_wire(file), wraps_before);
    assert_eq!(session.generation(), generation + 1);
    assert_eq!(file.parse().unwrap().generation, session.generation());
    let opened = unlock(file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
    // Reopen regression (audit A5): the written record must survive disk.
    assert_eq!(reopened_len(file, &SEED_NEXT), 2);
}

fn remove_and_check(session: &mut Session, file: &mut VaultFile, device_id: &[u8; 16]) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let missing = [0x11; 16];
    assert_eq!(
        remove_chip_unlock(session, file, &missing)
            .unwrap_err()
            .to_string(),
        "wrap not found"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
    assert_eq!(session.generation(), generation);
    let body_before = body_of(file);
    remove_chip_unlock(session, file, device_id).unwrap();
    assert_eq!(body_of(file), body_before);
    assert_eq!(session.generation(), generation + 1);
    let parsed = file.parse().unwrap();
    assert!(parsed
        .entries
        .iter()
        .any(|entry| matches!(entry, WrapEntry::Password(_))));
    assert!(parsed
        .entries
        .iter()
        .all(|entry| { !matches!(entry, WrapEntry::Chip(chip) if chip.id == *device_id) }));
}

fn desktop_once() {
    let (file, session) = create(&SEED_DESKTOP, KdfProfile::Balanced, BodyAlg::Aegis256).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, &UnlockCreds::master(&SEED_DESKTOP), None).unwrap();
    assert_eq!(opened.generation(), 1);
    assert_eq!(opened.commit_tag(), session.commit_tag());
}

fn flip_at(file: &VaultFile, index: usize) -> VaultFile {
    let mut bytes = file.as_bytes().to_vec();
    let byte = bytes.get_mut(index).unwrap();
    *byte ^= 0x01;
    VaultFile::new(bytes)
}

fn set_body_alg(file: &VaultFile, alg: u16) -> VaultFile {
    let mut bytes = file.as_bytes().to_vec();
    let encoded = alg.to_le_bytes();
    bytes[68..70].copy_from_slice(&encoded);
    VaultFile::new(bytes)
}

fn body_offset(file: &VaultFile) -> usize {
    let parsed = file.parse().unwrap();
    file.as_bytes().len() - parsed.body.len() - COMMIT_LEN
}

fn body_of(file: &VaultFile) -> Vec<u8> {
    file.parse().unwrap().body.to_vec()
}

fn header_bytes(file: &VaultFile) -> [u8; HEADER_LEN] {
    file.as_bytes()[..HEADER_LEN].try_into().unwrap()
}

fn entry_wire(file: &VaultFile) -> Vec<u8> {
    let parsed = file.parse().unwrap();
    let bytes = file.as_bytes();
    let start = HEADER_LEN + 2 + 8;
    let end = bytes.len() - COMMIT_LEN - parsed.body.len();
    bytes[start..end].to_vec()
}

fn password_record(file: &VaultFile) -> Vec<u8> {
    let parsed = file.parse().unwrap();
    let WrapEntry::Password(wrap) = &parsed.entries[0] else {
        panic!("password wrap");
    };
    encode_password_entry(wrap.kid, wrap.nonce, wrap.ct, wrap.tag).to_vec()
}

fn with_password_record(file: &VaultFile, record: &[u8]) -> VaultFile {
    let parsed = file.parse().unwrap();
    let refs = [record];
    let dir = encode_wrap_dir(parsed.generation, &refs).unwrap();
    assemble(&parsed.header, &dir, parsed.body, &parsed.commit)
}

fn replace_body(file: &VaultFile, new_body: &[u8]) -> VaultFile {
    let bytes = file.as_bytes();
    let body_at = body_offset(file);
    let mut out = Vec::with_capacity(body_at + new_body.len() + COMMIT_LEN);
    out.extend_from_slice(&bytes[..body_at]);
    out.extend_from_slice(new_body);
    out.extend_from_slice(&bytes[bytes.len() - COMMIT_LEN..]);
    VaultFile::new(out)
}

fn prf_publics() -> PrfPublics {
    PrfPublics {
        id: [0x5A; 16],
        cred_id: vec![0x51; 32],
        salt: [0x33; 32],
    }
}

fn count_prf_id(file: &VaultFile, id: [u8; 16]) -> usize {
    file.parse()
        .unwrap()
        .entries
        .iter()
        .filter(|entry| matches!(entry, WrapEntry::Prf(wrap) if wrap.id == id))
        .count()
}

#[test]
fn change_master_keeps_single_prf_wrap() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let publics = prf_publics();
    add_prf_unlock(&mut session, &mut file, &publics, &[0x44; 32]).unwrap();
    assert_eq!(count_prf_id(&file, publics.id), 1);

    change_master(
        &mut session,
        &mut file,
        &SEED_NEXT,
        &[(prf_publics(), [0x44; 32])],
    )
    .unwrap();
    // The re-sealed wrap replaces the old one: the grant id stays unique and
    // the directory does not grow on every master change.
    assert_eq!(count_prf_id(&file, [0x5A; 16]), 1);

    // The re-sealed grant still authenticates with the same PRF output.
    let prf_out = [0x44; 32];
    unlock(
        &file,
        &UnlockCreds::default().with_prf(&prf_publics(), &prf_out),
        None,
    )
    .unwrap();
}

#[test]
fn removed_prf_cannot_unlock() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let publics = prf_publics();
    let prf_out = [0x44; 32];
    add_prf_unlock(&mut session, &mut file, &publics, &prf_out).unwrap();

    remove_prf_unlock(&mut session, &mut file, &publics.id).unwrap();
    assert_eq!(count_prf_id(&file, publics.id), 0);

    // The stolen hardware key no longer opens anything.
    let creds = UnlockCreds::default().with_prf(&publics, &prf_out);
    assert!(unlock(&file, &creds, None).is_err());

    // A second removal has nothing left to remove.
    assert!(remove_prf_unlock(&mut session, &mut file, &publics.id).is_err());

    // The removal did not touch the password wrap: the vault stays openable.
    let next = [9u8; 64];
    change_master(&mut session, &mut file, &next, &[]).unwrap();
}

const fn revoke_creds<'a>(
    master: &'a [u8; 64],
    prfs: &'a [(PrfPublics, [u8; 32])],
) -> RotateCreds<'a> {
    RotateCreds {
        master,
        human_password: None,
        prfs,
    }
}

#[test]
fn revoked_device_cannot_read_new_frames() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let device = common::enroll(&mut session, &mut file);

    // The attacker copies the file while the device is still enrolled.
    let stolen = VaultFile::new(file.as_bytes().to_vec());
    let attacker = common::unlock_device(&stolen, &device).unwrap();
    // The shared secret the stolen key derives against its enrolled wrap.
    let ss = device
        .ecdh(&common::eph_pub(&stolen, device.id()).unwrap())
        .unwrap();

    let creds = revoke_creds(&SEED_NEXT, &[]);
    revoke(&mut session, &mut file, &Revoke::Chip(device.id()), &creds).unwrap();

    // The stolen device keys open nothing: its wrap is gone and the vault key
    // underneath has been replaced.
    let stolen_creds = UnlockCreds::default().with_chip(device.chip_keys(), *ss.expose());
    assert!(unlock(&file, &stolen_creds, None).is_err());
    assert!(common::unlock_device(&file, &device).is_err());
    // The owner keeps full access under the new master wrap.
    let mut owner = unlock(&file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
    assert_eq!(owner.generation(), session.generation());
    assert_eq!(owner.commit_tag(), session.commit_tag());
    // The owner writes fresh records under the rotated vault key.
    write_record(&mut owner, &mut file, None, &Document::new()).unwrap();
    // The revoked device's live session still holds the pre-revoke keys. It
    // can scribble bytes, but its frames are sealed under the old vault key:
    // the next honest unlock must refuse the blob (commit check) instead of
    // mixing attacker frames into the rotated vault.
    let mut stale = attacker;
    write_record(&mut stale, &mut file, None, &Document::new()).unwrap();
    assert!(
        unlock(&file, &UnlockCreds::master(&SEED_NEXT), None).is_err(),
        "frames sealed under the revoked key must fail the commit check"
    );
}

#[test]
fn remaining_factors_still_unlock_after_revoke() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let gone = common::enroll(&mut session, &mut file);
    let kept = common::enroll(&mut session, &mut file);
    let publics = prf_publics();
    let prf_out = [0x45; 32];
    add_prf_unlock(&mut session, &mut file, &publics, &prf_out).unwrap();

    let prfs = [(prf_publics(), prf_out)];
    let creds = revoke_creds(&SEED_NEXT, &prfs);
    revoke(&mut session, &mut file, &Revoke::Chip(gone.id()), &creds).unwrap();

    assert!(common::unlock_device(&file, &kept).is_ok());
    assert!(unlock(
        &file,
        &UnlockCreds::default().with_prf(&publics, &prf_out),
        None
    )
    .is_ok());
    assert!(unlock(&file, &UnlockCreds::master(&SEED_NEXT), None).is_ok());
    assert!(common::unlock_device(&file, &gone).is_err());
}

#[test]
fn revoke_without_prf_output_fails() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let device = common::enroll(&mut session, &mut file);
    let publics = prf_publics();
    add_prf_unlock(&mut session, &mut file, &publics, &[0x46; 32]).unwrap();

    // Rotating without the PRF output would brick the hardware factor: refuse
    // and leave the file exactly as it was.
    let before = file.as_bytes().to_vec();
    let creds = revoke_creds(&SEED_NEXT, &[]);
    assert_eq!(
        revoke(&mut session, &mut file, &Revoke::Chip(device.id()), &creds)
            .unwrap_err()
            .to_string(),
        "prf factor required"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
}

// ---- Phase 6: human password wrap + recovery-drop policy ------------------

use session::{add_human_password, drop_recovery_wrap};
use wraps::HumanPasswordPublics;

const HUMAN_PW: &[u8] = b"correct horse battery staple";

fn human_publics() -> HumanPasswordPublics {
    HumanPasswordPublics {
        kid: [0x11; 8],
        password: HUMAN_PW.to_vec(),
        // Deliberately below the wire floor; the seal path raises it.
        m_kib: 1,
        t: 1,
        p: 1,
    }
}

#[test]
fn human_password_unlocks_and_wrong_password_fails() {
    let (mut file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    add_human_password(&mut session, &mut file, &human_publics()).unwrap();

    let ok = unlock(&file, &UnlockCreds::default().with_human(HUMAN_PW), None).unwrap();
    assert_eq!(ok.generation(), session.generation());
    assert_eq!(ok.commit_tag(), session.commit_tag());

    assert!(unlock(&file, &UnlockCreds::default().with_human(b"wrong"), None).is_err());
    // The seal path raised the cost to the parse floor.
    let parsed = file.parse().unwrap();
    let human = parsed.entries.iter().find_map(|e| match e {
        WrapEntry::HumanPassword(h) => Some(*h),
        _ => None,
    });
    assert!(human.is_some());
}

#[test]
fn seed_cannot_unlock_local_copy_after_drop() {
    let (mut file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    // The backup keeps everything, including the seed wrap.
    let backup = VaultFile::new(file.as_bytes().to_vec());
    add_human_password(&mut session, &mut file, &human_publics()).unwrap();

    drop_recovery_wrap(&mut session, &mut file).unwrap();

    // The local copy no longer opens with the phrase.
    assert!(unlock(&file, &UnlockCreds::master(&SEED_AEGIS), None).is_err());
    // It still opens with the human password.
    unlock(&file, &UnlockCreds::default().with_human(HUMAN_PW), None).unwrap();
    // A second drop has nothing left to drop.
    assert!(drop_recovery_wrap(&mut session, &mut file).is_err());

    // The backup copy still restores with the phrase.
    unlock(&backup, &UnlockCreds::master(&SEED_AEGIS), None).unwrap();
}

#[test]
fn drop_refuses_when_no_factor_would_remain() {
    let (mut file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    // No human wrap, no devices: dropping the seed wrap would brick the copy.
    let before = file.as_bytes().to_vec();
    let err = drop_recovery_wrap(&mut session, &mut file).unwrap_err();
    assert_eq!(err.to_string(), "no usable wrap");
    // The file is unchanged.
    assert_eq!(file.as_bytes(), before.as_slice());
}

#[test]
fn origin_device_is_stable_across_unlocks() {
    let (mut file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let device = common::enroll(&mut session, &mut file);

    // Two unlocks with the same wrap: the stamped origin must be identical
    // (the wrap id, not a fresh random id per unlock).
    let first = common::unlock_device(&file, &device).unwrap();
    let second = common::unlock_device(&file, &device).unwrap();
    assert_eq!(first.origin_device(), second.origin_device());
    assert_eq!(first.origin_device(), *device.id());

    // A seed unlock carries no enrolled wrap: a random non-zero origin, so
    // its frames never masquerade as a registered device's frames.
    let master = unlock(&file, &UnlockCreds::master(&SEED_AEGIS), None).unwrap();
    assert_ne!(master.origin_device(), [0u8; 16]);
    assert_ne!(master.origin_device(), *device.id());
}

#[test]
fn append_is_constant_time_vs_vault_size() {
    use aead::BodyAlg;
    use kdf::KdfProfile;
    use record::Document;
    use std::time::Instant;

    let fill = |count: usize| -> (VaultFile, session::Session) {
        let (mut file, mut s) =
            session::create(&[0x2Au8; 64], KdfProfile::Balanced, BodyAlg::Frames).unwrap();
        for _ in 0..count {
            session::write_record(&mut s, &mut file, None, &Document::new()).unwrap();
        }
        (file, s)
    };

    let (mut file10, mut s10) = fill(10);
    let (mut file5k, mut s5k) = fill(5_000);

    let t10 = Instant::now();
    session::write_record(&mut s10, &mut file10, None, &Document::new()).unwrap();
    let d10 = t10.elapsed();

    let t5k = Instant::now();
    session::write_record(&mut s5k, &mut file5k, None, &Document::new()).unwrap();
    let d5k = t5k.elapsed();

    // 500x more records, same order of magnitude of append cost. Generous
    // bound: the append must not scale with vault size. The padded 256-byte
    // frame floor makes the 5k vault ~1.3 MB (vs ~35-byte frames before
    // padding), so the absolute constant is ~50x larger; the bound keeps
    // the original per-record proportion, and any accidental O(n) re-verify
    // per frame would blow past it by two orders of magnitude.
    assert!(
        d5k.as_millis() < d10.as_millis().max(1) * 500,
        "append at 5k records ({d5k:?}) must be O(1) vs 10 records ({d10:?})"
    );
}
