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
use container::{
    assemble, encode_password_entry, encode_wrap_dir, StaticHeader, VaultFile, WrapEntry,
    BODY_AEGIS256, BODY_KUZ_CTR_HMAC, COMMIT_LEN, HEADER_LEN, KDF_ARGON2ID,
    KDF_M_KIB_MAX, KDF_P_MIN, KDF_T_MIN, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN, WRAP_AEGIS256,
};
use kdf::KdfProfile;
use pq::keypair;
use secret::Secret;
use session::{
    add_device, add_prf_unlock, change_master, create, reencrypt_body, remove_device,
    remove_prf_unlock, revoke, unlock, write_records, Revoke, RotateCreds, Seen, Session,
    UnlockCreds,
};
use wraps::{DeviceKeys, DevicePublics, PrfPublics};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

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
    // Mobile (64 MiB) covers tamper and mutation. Desktop (256 MiB) runs once.
    reject_before_argon();
    let (aegis, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let (kuz, _kuz_session) = round_trip(&SEED_KUZ, BodyAlg::KuzCtrHmac);
    tamper(&aegis, &SEED_AEGIS);
    transplant(&aegis, &kuz);
    let mut file = aegis;
    reject_zero_x25519(&mut session, &mut file);
    let device = add_and_check(&mut session, &mut file);
    reencrypt_and_check(&mut session, &mut file, &device);
    change_master_and_check(&mut session, &mut file);
    write_and_check(&mut session, &mut file);
    remove_and_check(&mut session, &mut file, &device.0.id);
    desktop_once();
}

fn reject_before_argon() {
    assert_eq!(
        create(&SEED_KUZ, KdfProfile::Mobile, BodyAlg::KuzMgm).unwrap_err().to_string(),
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
        unlock(&VaultFile::new(bytes), &UnlockCreds::master(&SEED_AEGIS), None).unwrap_err().to_string(),
        "kdf parameters rejected"
    );
    // Non-BRBY bytes are rejected before Argon2 runs.
    assert_eq!(
        unlock(
            &VaultFile::new(b"v1-vault-no-magic".to_vec()),
            &UnlockCreds::master(&SEED_AEGIS),
            None
        )
        .unwrap_err().to_string(),
        "bad magic"
    );
}

fn round_trip(master: &[u8; 64], alg: BodyAlg) -> (VaultFile, Session) {
    let (file, session) = create(master, KdfProfile::Mobile, alg).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, &UnlockCreds::master(master), None).unwrap();
    assert_eq!(opened.generation(), session.generation());
    assert_eq!(opened.commit_tag(), session.commit_tag());
    (file, session)
}

fn tamper(file: &VaultFile, master: &[u8; 64]) {
    assert_eq!(
        unlock(file, &UnlockCreds::master(&SEED_KUZ), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
    let flipped_header = flip_at(file, 20);
    assert_eq!(
        unlock(&flipped_header, &UnlockCreds::master(master), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
    let flipped_body = flip_at(file, body_offset(file));
    assert_eq!(
        unlock(&flipped_body, &UnlockCreds::master(master), None).unwrap_err().to_string(),
        "commit mismatch"
    );
    let parsed = file.parse().unwrap();
    let WrapEntry::Password(wrap) = &parsed.entries[0] else {
        panic!("password wrap");
    };
    assert_eq!(file.as_bytes()[PASSWORD_CT_OFFSET], wrap.ct[0]);
    let flipped_ct = flip_at(file, PASSWORD_CT_OFFSET);
    assert_eq!(
        unlock(&flipped_ct, &UnlockCreds::master(master), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
    let swapped_alg = set_body_alg(file, BODY_KUZ_CTR_HMAC);
    assert_eq!(
        unlock(&swapped_alg, &UnlockCreds::master(master), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
}

fn transplant(aegis: &VaultFile, kuz: &VaultFile) {
    let foreign = password_record(aegis);
    let mixed = with_password_record(kuz, &foreign);
    assert_eq!(
        unlock(&mixed, &UnlockCreds::master(&SEED_AEGIS), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
    // B's password wrap stays. A's record replaces the body, so the commit is stale.
    let spliced = replace_body(kuz, &foreign);
    assert_eq!(
        unlock(&spliced, &UnlockCreds::master(&SEED_KUZ), None).unwrap_err().to_string(),
        "commit mismatch"
    );
}

fn reject_zero_x25519(session: &mut Session, file: &mut VaultFile) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let tag = *session.commit_tag();
    let dev = DevicePublics {
        id: [9; 16],
        x_pk: [0; 32],
        pq_pk: [0; pq::PQ_PK_LEN],
    };
    assert_eq!(
        add_device(session, file, &dev).unwrap_err().to_string(),
        "zero shared secret"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
    assert_eq!(session.generation(), generation);
    assert_eq!(session.commit_tag(), &tag);
}

fn add_and_check(session: &mut Session, file: &mut VaultFile) -> (DevicePublics, DeviceKeys) {
    let body_before = body_of(file);
    let generation = session.generation();
    let device = device_identity(0x42);
    let grant = add_device(session, file, &device.0).unwrap();
    assert_eq!(body_of(file), body_before);
    assert_eq!(session.generation(), generation + 1);
    assert_eq!(file.parse().unwrap().generation, generation + 1);
    assert!(grant.as_bytes().starts_with(&header_bytes(file)));
    let after_add = file.as_bytes().to_vec();
    let generation_after = session.generation();
    let tag_after = *session.commit_tag();
    assert_eq!(
        add_device(session, file, &device.0).unwrap_err().to_string(),
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

fn reencrypt_and_check(
    session: &mut Session,
    file: &mut VaultFile,
    device: &(DevicePublics, DeviceKeys),
) {
    reencrypt_body(session, file, b"rotated-records", &SEED_ROTATED, &[device.0], &[], &[]).unwrap();
    assert_eq!(
        unlock(file, &UnlockCreds::master(&SEED_AEGIS), None).unwrap_err().to_string(),
        "wrap authentication failed"
    );
    let opened = unlock(file, &UnlockCreds::master(&SEED_ROTATED), None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
    let via_device = unlock(file, &UnlockCreds::default().with_device(&device.1), None).unwrap();
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
        unlock(&old, &UnlockCreds::master(&SEED_ROTATED), Some(seen)).unwrap_err().to_string(),
        "rollback"
    );
    let opened_old = unlock(&old, &UnlockCreds::master(&SEED_ROTATED), None).unwrap();
    assert_eq!(opened_old.generation() + 1, session.generation());
    unlock(file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
}

fn write_and_check(session: &mut Session, file: &mut VaultFile) {
    let wraps_before = entry_wire(file);
    let generation = session.generation();
    write_records(session, file, b"record-bytes").unwrap();
    assert_eq!(entry_wire(file), wraps_before);
    assert_eq!(session.generation(), generation + 1);
    assert_eq!(file.parse().unwrap().generation, session.generation());
    let opened = unlock(file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
}

fn remove_and_check(session: &mut Session, file: &mut VaultFile, device_id: &[u8; 16]) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let missing = [0x11; 16];
    assert_eq!(
        remove_device(session, file, &missing).unwrap_err().to_string(),
        "wrap not found"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
    assert_eq!(session.generation(), generation);
    let body_before = body_of(file);
    remove_device(session, file, device_id).unwrap();
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
        .all(|entry| { !matches!(entry, WrapEntry::Device(dev) if dev.device_id == *device_id) }));
}

fn desktop_once() {
    let (file, session) = create(&SEED_DESKTOP, KdfProfile::Desktop, BodyAlg::Aegis256).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, &UnlockCreds::master(&SEED_DESKTOP), None).unwrap();
    assert_eq!(opened.generation(), 1);
    assert_eq!(opened.commit_tag(), session.commit_tag());
}

fn device_identity(id_byte: u8) -> (DevicePublics, DeviceKeys) {
    let (ntru_bytes, kem_secret) = keypair().unwrap();
    let ntru_pk: [u8; pq::PQ_PK_LEN] = ntru_bytes.as_slice().try_into().unwrap();
    let mut scalar = [0u8; 32];
    getrandom::fill(&mut scalar).unwrap();
    let x_pk = x25519(scalar, X25519_BASEPOINT_BYTES);
    let id = [id_byte; 16];
    let publics = DevicePublics {
        id,
        x_pk,
        pq_pk: ntru_pk,
    };
    let keys = DeviceKeys {
        id,
        x_sk: Secret::new(scalar),
        pq_sk: kem_secret,
    };
    scalar.zeroize();
    (publics, keys)
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
    PrfPublics { id: [0x5A; 16], cred_id: vec![0x51; 32], salt: [0x33; 32] }
}

fn count_prf_id(file: &VaultFile, id: [u8; 16]) -> usize {
    file.parse().unwrap().entries.iter().filter(|entry| {
        matches!(entry, WrapEntry::Prf(wrap) if wrap.id == id)
    }).count()
}

#[test]
fn change_master_keeps_single_prf_wrap() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let publics = prf_publics();
    add_prf_unlock(&mut session, &mut file, &publics, &[0x44; 32]).unwrap();
    assert_eq!(count_prf_id(&file, publics.id), 1);

    change_master(&mut session, &mut file, &SEED_NEXT, &[(prf_publics(), [0x44; 32])])
        .unwrap();
    // The re-sealed wrap replaces the old one: the grant id stays unique and
    // the directory does not grow on every master change.
    assert_eq!(count_prf_id(&file, [0x5A; 16]), 1);

    // The re-sealed grant still authenticates with the same PRF output.
    let prf_out = [0x44; 32];
    unlock(&file, &UnlockCreds::default().with_prf(&prf_publics(), &prf_out), None).unwrap();
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
    devices: &'a [DevicePublics],
    prfs: &'a [(PrfPublics, [u8; 32])],
) -> RotateCreds<'a> {
    RotateCreds { master, devices, chips: &[], prfs }
}

#[test]
fn revoked_device_cannot_read_new_frames() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let device = device_identity(0x71);
    add_device(&mut session, &mut file, &device.0).unwrap();

    // The attacker copies the file while the device is still enrolled.
    let stolen = VaultFile::new(file.as_bytes().to_vec());
    let _attacker =
        unlock(&stolen, &UnlockCreds::default().with_device(&device.1), None).unwrap();

    let devices = [device.0];
    let creds = revoke_creds(&SEED_NEXT, &devices, &[]);
    revoke(&mut session, &mut file, &Revoke::Device(&device.0.id), &creds).unwrap();

    // The stolen device keys open nothing: its wrap is gone and the vault key
    // underneath has been replaced.
    assert!(unlock(&file, &UnlockCreds::default().with_device(&device.1), None).is_err());
    // The owner keeps full access under the new master wrap.
    let owner = unlock(&file, &UnlockCreds::master(&SEED_NEXT), None).unwrap();
    assert_eq!(owner.generation(), session.generation());
    assert_eq!(owner.commit_tag(), session.commit_tag());
}

#[test]
fn remaining_factors_still_unlock_after_revoke() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let gone = device_identity(0x72);
    let kept = device_identity(0x73);
    add_device(&mut session, &mut file, &gone.0).unwrap();
    add_device(&mut session, &mut file, &kept.0).unwrap();
    let publics = prf_publics();
    let prf_out = [0x45; 32];
    add_prf_unlock(&mut session, &mut file, &publics, &prf_out).unwrap();

    let devices = [gone.0, kept.0];
    let prfs = [(prf_publics(), prf_out)];
    let creds = revoke_creds(&SEED_NEXT, &devices, &prfs);
    revoke(&mut session, &mut file, &Revoke::Device(&gone.0.id), &creds).unwrap();

    assert!(unlock(&file, &UnlockCreds::default().with_device(&kept.1), None).is_ok());
    assert!(unlock(&file, &UnlockCreds::default().with_prf(&publics, &prf_out), None).is_ok());
    assert!(unlock(&file, &UnlockCreds::master(&SEED_NEXT), None).is_ok());
    assert!(unlock(&file, &UnlockCreds::default().with_device(&gone.1), None).is_err());
}

#[test]
fn revoke_without_prf_output_fails() {
    let (file, mut session) = round_trip(&SEED_AEGIS, BodyAlg::Aegis256);
    let mut file = file;
    let device = device_identity(0x74);
    add_device(&mut session, &mut file, &device.0).unwrap();
    let publics = prf_publics();
    add_prf_unlock(&mut session, &mut file, &publics, &[0x46; 32]).unwrap();

    // Rotating without the PRF output would brick the hardware factor: refuse
    // and leave the file exactly as it was.
    let before = file.as_bytes().to_vec();
    let devices = [device.0];
    let creds = revoke_creds(&SEED_NEXT, &devices, &[]);
    assert_eq!(
        revoke(&mut session, &mut file, &Revoke::Device(&device.0.id), &creds)
            .unwrap_err()
            .to_string(),
        "prf factor required"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
}
