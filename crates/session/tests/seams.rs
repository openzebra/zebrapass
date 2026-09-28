//! Public seams a UI builds on: the wrap directory read, the post-unlock
//! rollback check, and a vault-key rotation that keeps every wrap.

#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use session::{
    add_device, add_human_password, check_seen, create, list_records, open_record, revoke,
    rotate_vault_key, unlock, wrap_directory, write_record, BodyAlg, DevicePublics, Factor,
    HumanPasswordPublics, KdfProfile, Revoke, RotateCreds, Seen, SessionError, UnlockCreds,
    VaultFile,
};

const SEED: [u8; 64] = [0x5A; 64];
const OLD_PW: &[u8] = b"correct horse battery staple";
const NEW_PW: &[u8] = b"a whole new passphrase";

fn human(password: &[u8]) -> HumanPasswordPublics {
    HumanPasswordPublics {
        kid: [0x33; 8],
        password: password.to_vec(),
        m_kib: KdfProfile::Mobile.m_kib(),
        t: KdfProfile::Mobile.t(),
        p: KdfProfile::Mobile.p(),
    }
}

fn titled(title: &str) -> record::Document {
    let mut doc = record::Document::new();
    doc.set_text(record::TAG_TITLE, title);
    doc
}

fn session_error(error: &anyhow::Error) -> Option<SessionError> {
    error.downcast_ref::<SessionError>().copied()
}

#[test]
fn directory_lists_factor_kinds_without_unlocking() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap();
    let fresh = wrap_directory(&file).unwrap();
    assert_eq!(fresh.generation, 1);
    assert_eq!(&*fresh.factors, &[Factor::Recovery]);

    add_human_password(&mut session, &mut file, &human(OLD_PW)).unwrap();
    let listed = wrap_directory(&file).unwrap();
    assert_eq!(listed.generation, 2);
    assert_eq!(listed.factors.len(), 2);
    assert!(matches!(listed.factors.first(), Some(Factor::Recovery)));
    assert!(matches!(
        listed.factors.get(1),
        Some(Factor::Password { m_kib, .. }) if *m_kib == KdfProfile::Mobile.m_kib()
    ));

    // The read goes through the bounded container parse: garbage fails closed.
    assert!(wrap_directory(&VaultFile::new(b"not a vault".to_vec())).is_err());
}

#[test]
fn check_seen_rejects_rollback_and_conflict_after_unlock() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap();
    let old = VaultFile::new(file.as_bytes().to_vec());
    write_record(&mut session, &mut file, None, &titled("newer")).unwrap();
    let seen = Seen {
        generation: session.generation(),
        commit_tag: *session.commit_tag(),
    };

    let stale = unlock(&old, &UnlockCreds::master(&SEED), None).unwrap();
    let error = check_seen(&stale, Some(seen)).unwrap_err();
    assert_eq!(session_error(&error), Some(SessionError::Rollback));

    let current = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
    check_seen(&current, Some(seen)).unwrap();
    check_seen(&current, None).unwrap();

    let forked = Seen {
        commit_tag: [0u8; 32],
        ..seen
    };
    let error = check_seen(&current, Some(forked)).unwrap_err();
    assert_eq!(session_error(&error), Some(SessionError::Conflict));
}

#[test]
fn rotation_reseals_human_wrap_under_the_new_password() {
    let (mut file, mut session) = create(&SEED, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap();
    add_human_password(&mut session, &mut file, &human(OLD_PW)).unwrap();
    let id = write_record(&mut session, &mut file, None, &titled("kept")).unwrap();
    let before = file.as_bytes().to_vec();

    let missing = RotateCreds {
        master: &SEED,
        devices: &[],
        chips: &[],
        prfs: &[],
        human_password: None,
    };
    let error = rotate_vault_key(&mut session, &mut file, &missing).unwrap_err();
    assert_eq!(
        session_error(&error),
        Some(SessionError::HumanFactorRequired)
    );
    assert_eq!(file.as_bytes(), before.as_slice());

    let creds = RotateCreds {
        human_password: Some(NEW_PW),
        ..missing
    };
    rotate_vault_key(&mut session, &mut file, &creds).unwrap();

    assert!(unlock(&file, &UnlockCreds::default().with_human(OLD_PW), None).is_err());
    let reopened = unlock(&file, &UnlockCreds::default().with_human(NEW_PW), None).unwrap();
    assert_eq!(list_records(&reopened).unwrap().len(), 1);
    let doc = open_record(&reopened, id).unwrap();
    assert_eq!(doc.text(record::TAG_TITLE).unwrap(), Some("kept"));
    // The pre-rotation file still opens under its own key: rotation protects
    // new writes, and rollback protection is the job of the seen cursor.
    assert!(unlock(&VaultFile::new(before), &UnlockCreds::master(&SEED), None).is_ok());
}

fn device_publics(id_byte: u8) -> DevicePublics {
    let (pq_bytes, _secret) = pq::keypair().unwrap();
    let pq_pk: [u8; pq::PQ_PK_LEN] = pq_bytes.as_slice().try_into().unwrap();
    let x_pk = x25519_dalek::x25519([id_byte; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
    DevicePublics {
        id: [id_byte; 16],
        x_pk,
        pq_pk,
    }
}

#[test]
fn revoke_keeps_records_readable_in_every_body_mode() {
    for alg in [BodyAlg::Aegis256, BodyAlg::KuzCtrHmac, BodyAlg::Frames] {
        let (mut file, mut session) = create(&SEED, KdfProfile::Mobile, alg).unwrap();
        let id = write_record(&mut session, &mut file, None, &titled("survives")).unwrap();
        let lost = device_publics(0x61);
        add_device(&mut session, &mut file, &lost).unwrap();
        let creds = RotateCreds {
            master: &SEED,
            devices: &[],
            chips: &[],
            prfs: &[],
            human_password: None,
        };
        revoke(&mut session, &mut file, &Revoke::Device(&lost.id), &creds).unwrap();

        let live = open_record(&session, id).unwrap();
        assert_eq!(
            live.text(record::TAG_TITLE).unwrap(),
            Some("survives"),
            "{alg:?}"
        );
        let reopened = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
        let doc = open_record(&reopened, id).unwrap();
        assert_eq!(
            doc.text(record::TAG_TITLE).unwrap(),
            Some("survives"),
            "{alg:?}"
        );
    }
}
