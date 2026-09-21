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
    BODY_AEGIS256, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, HEADER_LEN, KDF_ARGON2ID,
    KDF_M_KIB_MAX, KDF_P_MIN, KDF_T_MIN, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN, WRAP_AEGIS256,
};
use kdf::KdfProfile;
use pq::keypair;
use secret::Secret;
use session::{
    add_device, change_password, create, reencrypt_body, remove_device, unlock, write_records,
    Seen, Session, VaultV2Error,
};
use wraps::{DeviceKeys, DevicePublics};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

const PW_AEGIS: &str = "mobile-aegis-password";
const PW_KUZ: &str = "mobile-kuz-password";
const PW_ROTATED: &str = "mobile-aegis-rotated";
const PW_NEXT: &str = "mobile-aegis-next";
const PW_DESKTOP: &str = "desktop-password";

const PASSWORD_CT_OFFSET: usize =
    HEADER_LEN + 2 + 8 + (PASSWORD_RECORD_LEN - PASSWORD_PAYLOAD_LEN) + 8 + 32;

#[test]
fn vault_operations_mobile_and_one_desktop() {
    // One function so cargo does not run these Argon2 allocations in parallel.
    // Mobile (64 MiB) covers tamper and mutation. Desktop (256 MiB) runs once.
    reject_before_argon();
    let (aegis, mut session) = round_trip(PW_AEGIS, BodyAlg::Aegis256);
    let (kuz, _kuz_session) = round_trip(PW_KUZ, BodyAlg::KuzCtrHmac);
    tamper(&aegis, PW_AEGIS);
    transplant(&aegis, &kuz);
    let mut file = aegis;
    reject_zero_x25519(&mut session, &mut file);
    let device = add_and_check(&mut session, &mut file);
    reencrypt_and_check(&mut session, &mut file, &device);
    change_password_and_check(&mut session, &mut file);
    write_and_check(&mut session, &mut file);
    remove_and_check(&mut session, &mut file, &device.0.id);
    desktop_once();
}

fn reject_before_argon() {
    assert_eq!(
        create("", KdfProfile::Mobile, BodyAlg::Aegis256).unwrap_err(),
        VaultV2Error::EmptyPassword
    );
    assert_eq!(
        create("not-empty", KdfProfile::Mobile, BodyAlg::KuzMgm).unwrap_err(),
        VaultV2Error::UnsupportedBodyAlg(BODY_KUZ_MGM)
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
        unlock(&VaultFile::new(bytes), "password", None, None).unwrap_err(),
        VaultV2Error::KdfParamsRejected
    );
}

fn round_trip(password: &str, alg: BodyAlg) -> (VaultFile, Session) {
    let (file, session) = create(password, KdfProfile::Mobile, alg).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, password, None, None).unwrap();
    assert_eq!(opened.generation(), session.generation());
    assert_eq!(opened.commit_tag(), session.commit_tag());
    (file, session)
}

fn tamper(file: &VaultFile, password: &str) {
    assert_eq!(
        unlock(file, "wrong-password", None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
    let flipped_header = flip_at(file, 20);
    assert_eq!(
        unlock(&flipped_header, password, None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
    let flipped_body = flip_at(file, body_offset(file));
    assert_eq!(
        unlock(&flipped_body, password, None, None).unwrap_err(),
        VaultV2Error::CommitMismatch
    );
    let parsed = file.parse().unwrap();
    let WrapEntry::Password(wrap) = &parsed.entries[0] else {
        panic!("password wrap");
    };
    assert_eq!(file.as_bytes()[PASSWORD_CT_OFFSET], wrap.ct[0]);
    let flipped_ct = flip_at(file, PASSWORD_CT_OFFSET);
    assert_eq!(
        unlock(&flipped_ct, password, None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
    let swapped_alg = set_body_alg(file, BODY_KUZ_CTR_HMAC);
    assert_eq!(
        unlock(&swapped_alg, password, None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
}

fn transplant(aegis: &VaultFile, kuz: &VaultFile) {
    let foreign = password_record(aegis);
    let mixed = with_password_record(kuz, &foreign);
    assert_eq!(
        unlock(&mixed, PW_AEGIS, None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
    // B's password wrap stays. A's record replaces the body, so the commit is stale.
    let spliced = replace_body(kuz, &foreign);
    assert_eq!(
        unlock(&spliced, PW_KUZ, None, None).unwrap_err(),
        VaultV2Error::CommitMismatch
    );
}

fn reject_zero_x25519(session: &mut Session, file: &mut VaultFile) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let tag = *session.commit_tag();
    let dev = DevicePublics {
        id: [9; 16],
        x_pk: [0; 32],
        pq_pk: [0; 2067],
    };
    assert_eq!(
        add_device(session, file, &dev).unwrap_err(),
        VaultV2Error::ZeroSharedSecret
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
        add_device(session, file, &device.0).unwrap_err(),
        VaultV2Error::CorruptedLength
    );
    assert_eq!(file.as_bytes(), after_add.as_slice());
    assert_eq!(session.generation(), generation_after);
    assert_eq!(session.commit_tag(), &tag_after);
    let opened = unlock(file, PW_AEGIS, None, None).unwrap();
    assert_eq!(opened.generation(), session.generation());
    assert_eq!(opened.commit_tag(), session.commit_tag());
    device
}

fn reencrypt_and_check(
    session: &mut Session,
    file: &mut VaultFile,
    device: &(DevicePublics, DeviceKeys),
) {
    reencrypt_body(session, file, b"rotated-records", PW_ROTATED, &[device.0]).unwrap();
    assert_eq!(
        unlock(file, PW_AEGIS, None, None).unwrap_err(),
        VaultV2Error::WrapAuthFailed
    );
    let opened = unlock(file, PW_ROTATED, None, None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
    let via_device = unlock(file, "", Some(&device.1), None).unwrap();
    assert_eq!(via_device.generation(), session.generation());
    assert_eq!(via_device.commit_tag(), session.commit_tag());
}

fn change_password_and_check(session: &mut Session, file: &mut VaultFile) {
    let header_before = header_bytes(file);
    let body_before = body_of(file);
    let old = VaultFile::new(file.as_bytes().to_vec());
    change_password(session, file, PW_NEXT).unwrap();
    assert_eq!(header_bytes(file), header_before);
    assert_eq!(body_of(file), body_before);
    let seen = Seen {
        generation: session.generation(),
        commit_tag: *session.commit_tag(),
    };
    assert_eq!(
        unlock(&old, PW_ROTATED, None, Some(seen)).unwrap_err(),
        VaultV2Error::Rollback
    );
    let opened_old = unlock(&old, PW_ROTATED, None, None).unwrap();
    assert_eq!(opened_old.generation() + 1, session.generation());
    unlock(file, PW_NEXT, None, None).unwrap();
}

fn write_and_check(session: &mut Session, file: &mut VaultFile) {
    let wraps_before = entry_wire(file);
    let generation = session.generation();
    write_records(session, file, b"record-bytes").unwrap();
    assert_eq!(entry_wire(file), wraps_before);
    assert_eq!(session.generation(), generation + 1);
    assert_eq!(file.parse().unwrap().generation, session.generation());
    let opened = unlock(file, PW_NEXT, None, None).unwrap();
    assert_eq!(opened.commit_tag(), session.commit_tag());
}

fn remove_and_check(session: &mut Session, file: &mut VaultFile, device_id: &[u8; 16]) {
    let before = file.as_bytes().to_vec();
    let generation = session.generation();
    let missing = [0x11; 16];
    assert_eq!(
        remove_device(session, file, &missing).unwrap_err(),
        VaultV2Error::WrapNotFound
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
    let (file, session) = create(PW_DESKTOP, KdfProfile::Desktop, BodyAlg::Aegis256).unwrap();
    assert_eq!(session.generation(), 1);
    let opened = unlock(&file, PW_DESKTOP, None, None).unwrap();
    assert_eq!(opened.generation(), 1);
    assert_eq!(opened.commit_tag(), session.commit_tag());
}

fn device_identity(id_byte: u8) -> (DevicePublics, DeviceKeys) {
    let (ntru_bytes, kem_secret) = keypair().unwrap();
    let ntru_pk: [u8; 2067] = ntru_bytes.as_slice().try_into().unwrap();
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
