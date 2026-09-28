//! Factor management without the phrase: human password replace/remove,
//! the device book, chip re-seal from the file, and cascade record frames.

#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use container::WrapEntry;
use platform::{ChipBackend, SoftwareChip};
use session::{
    add_chip_unlock, add_device, add_human_password, create, drop_recovery_wrap, enroll_device,
    known_devices, open_record, remove_human_password, replace_human_password, revoke, unlock,
    write_record, BodyAlg, ChipKeys, ChipPublics, DeviceKeys, DevicePublics, HumanPasswordPublics,
    KdfProfile, Revoke, RotateCreds, UnlockCreds,
};

const SEED: [u8; 64] = [0x6B; 64];
const OLD_PW: &[u8] = b"correct horse battery staple";
const NEW_PW: &[u8] = b"a whole new passphrase";

fn human(password: &[u8]) -> HumanPasswordPublics {
    HumanPasswordPublics {
        kid: [0x44; 8],
        password: password.to_vec(),
        m_kib: KdfProfile::Fast.m_kib(),
        t: KdfProfile::Fast.t(),
        p: KdfProfile::Fast.p(),
    }
}

fn titled(title: &str) -> record::Document {
    let mut doc = record::Document::new();
    doc.set_text(record::TAG_TITLE, title);
    doc
}

fn device(id_byte: u8) -> (DevicePublics, DeviceKeys) {
    let (pq_bytes, pq_sk) = pq::keypair().unwrap();
    let scalar = [id_byte; 32];
    let publics = DevicePublics {
        id: [id_byte; 16],
        x_pk: x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES),
        pq_pk: pq_bytes.as_slice().try_into().unwrap(),
    };
    let keys = DeviceKeys {
        id: publics.id,
        x_sk: secret::Secret::new(scalar),
        pq_sk,
    };
    (publics, keys)
}

const fn no_creds() -> RotateCreds<'static> {
    RotateCreds {
        master: &SEED,
        devices: &[],
        prfs: &[],
        human_password: None,
    }
}

#[test]
fn human_password_is_replaced_and_removed_without_the_phrase() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let id = write_record(&mut session, &mut file, None, &titled("kept")).unwrap();
    add_human_password(&mut session, &mut file, &human(OLD_PW)).unwrap();

    replace_human_password(&mut session, &mut file, &human(NEW_PW)).unwrap();
    assert!(unlock(&file, &UnlockCreds::default().with_human(OLD_PW), None).is_err());
    let reopened = unlock(&file, &UnlockCreds::default().with_human(NEW_PW), None).unwrap();
    let doc = open_record(&reopened, id).unwrap();
    assert_eq!(doc.text(record::TAG_TITLE).unwrap(), Some("kept"));

    remove_human_password(&mut session, &mut file).unwrap();
    assert!(unlock(&file, &UnlockCreds::default().with_human(NEW_PW), None).is_err());
    assert_eq!(
        remove_human_password(&mut session, &mut file)
            .unwrap_err()
            .to_string(),
        "wrap not found"
    );
    assert_eq!(
        replace_human_password(&mut session, &mut file, &human(OLD_PW))
            .unwrap_err()
            .to_string(),
        "wrap not found"
    );
}

#[test]
fn last_factor_human_password_cannot_be_removed() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    add_human_password(&mut session, &mut file, &human(OLD_PW)).unwrap();
    drop_recovery_wrap(&mut session, &mut file).unwrap();
    let before = file.as_bytes().to_vec();
    assert_eq!(
        remove_human_password(&mut session, &mut file)
            .unwrap_err()
            .to_string(),
        "no usable wrap"
    );
    assert_eq!(file.as_bytes(), before.as_slice());
}

#[test]
fn revoke_reseals_booked_devices_and_file_chips_without_creds() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let id = write_record(&mut session, &mut file, None, &titled("survives")).unwrap();
    let (kept, kept_keys) = device(0x21);
    let (lost, _) = device(0x22);
    enroll_device(&mut session, &mut file, &kept).unwrap();
    enroll_device(&mut session, &mut file, &lost).unwrap();
    assert_eq!(known_devices(&session).unwrap().len(), 2);

    let chip = SoftwareChip::new();
    let (pq_bytes, pq_sk) = pq::keypair().unwrap();
    let chip_publics = ChipPublics {
        id: [0x31; 16],
        chip_pub: chip.generate_pair("zp/test").unwrap(),
        pq_pk: pq_bytes.as_slice().try_into().unwrap(),
    };
    add_chip_unlock(&mut session, &mut file, &chip_publics).unwrap();

    revoke(
        &mut session,
        &mut file,
        &Revoke::Device(&lost.id),
        &no_creds(),
    )
    .unwrap();

    let by_device = unlock(&file, &UnlockCreds::default().with_device(&kept_keys), None).unwrap();
    let doc = open_record(&by_device, id).unwrap();
    assert_eq!(doc.text(record::TAG_TITLE).unwrap(), Some("survives"));

    let parsed = file.parse().unwrap();
    let eph_pub = parsed
        .entries
        .iter()
        .find_map(|entry| match entry {
            WrapEntry::Chip(wrap) => Some(wrap.eph_pub),
            _ => None,
        })
        .unwrap();
    let ss = chip.ecdh("zp/test", &eph_pub).unwrap();
    let chip_keys = ChipKeys {
        id: chip_publics.id,
        pq_sk,
    };
    unlock(
        &file,
        &UnlockCreds::default().with_chip(&chip_keys, ss),
        None,
    )
    .unwrap();
}

#[test]
fn unbooked_device_still_needs_its_publics() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let (kept, _) = device(0x41);
    let (lost, _) = device(0x42);
    add_device(&mut session, &mut file, &kept).unwrap();
    add_device(&mut session, &mut file, &lost).unwrap();
    let target = Revoke::Device(&lost.id);
    assert_eq!(
        revoke(&mut session, &mut file, &target, &no_creds())
            .unwrap_err()
            .to_string(),
        "wrap not found"
    );
    let creds = RotateCreds {
        devices: &[kept],
        ..no_creds()
    };
    revoke(&mut session, &mut file, &target, &creds).unwrap();
}

#[test]
fn record_frames_are_cascade_sealed() {
    for alg in [BodyAlg::Frames, BodyAlg::Aegis256, BodyAlg::KuzCtrHmac] {
        let (mut file, mut session) = create(&SEED, KdfProfile::Fast, alg).unwrap();
        let id = write_record(&mut session, &mut file, None, &titled("layered")).unwrap();
        let signer = session::DeviceSignKey::from_seed(&[1u8; 32]);
        let exported = session::export_record(&session, &signer, id, &[0u8; 64], b"").unwrap();
        let header = frame::parse(&exported.frame).unwrap();
        assert_eq!(header.alg, frame::ALG_CASCADE, "{alg:?}");
        let reopened = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
        let doc = open_record(&reopened, id).unwrap();
        assert_eq!(doc.text(record::TAG_TITLE).unwrap(), Some("layered"));
    }
}
