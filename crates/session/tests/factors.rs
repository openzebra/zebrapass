//! Factor management without the phrase: human password replace/remove,
//! device and chip re-seal from the file, and cascade record frames.

#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

mod common;

use container::WrapEntry;
use platform::{ChipBackend, SoftwareChip};
use session::{
    add_chip_unlock, add_human_password, create, drop_recovery_wrap, open_record,
    remove_human_password, replace_human_password, revoke, unlock, write_record, BodyAlg, ChipKeys,
    ChipPublics, HumanPasswordPublics, KdfProfile, Revoke, RotateCreds, UnlockCreds,
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

const fn no_creds() -> RotateCreds<'static> {
    RotateCreds {
        master: &SEED,
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
fn revoke_reseals_remaining_devices_and_chips_from_the_file_alone() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let id = write_record(&mut session, &mut file, None, &titled("survives")).unwrap();
    let kept = common::enroll(&mut session, &mut file);
    let lost = common::enroll(&mut session, &mut file);
    let before_revoke = file.clone();

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
        &Revoke::Chip(lost.id()),
        &no_creds(),
    )
    .unwrap();

    let by_device = common::unlock_device(&file, &kept).unwrap();
    let doc = open_record(&by_device, id).unwrap();
    assert_eq!(doc.text(record::TAG_TITLE).unwrap(), Some("survives"));
    // The revoked key opened the old file but not the rotated one.
    common::unlock_device(&before_revoke, &lost).unwrap();
    assert!(common::unlock_device(&file, &lost).is_err());

    let parsed = file.parse().unwrap();
    let eph_pub = parsed
        .entries
        .iter()
        .find_map(|entry| match entry {
            WrapEntry::Chip(wrap) if wrap.id == chip_publics.id => Some(wrap.eph_pub),
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
