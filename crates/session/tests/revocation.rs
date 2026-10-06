#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use session::{
    issue_device_cert, issue_revocation, DeviceCert, DeviceSignKey, Revocation, SYNC_VK_LEN,
};

const ROOT: [u8; 32] = [0x07; 32];
const NOW: u64 = 1_700_000_000_000;

fn root_vk(seed: &[u8; 32]) -> [u8; SYNC_VK_LEN] {
    session::sync_verifying_key(seed)
        .unwrap()
        .try_into()
        .unwrap()
}

fn device(root: &[u8; 32], client: u8, id: u8, not_after: u64) -> (DeviceSignKey, DeviceCert) {
    let key = DeviceSignKey::from_seed(&[id; 32]);
    let cert = issue_device_cert(
        root,
        &[client; 64],
        &[id; 16],
        &key.verifying_key().unwrap(),
        not_after,
        u64::from(id),
    )
    .unwrap();
    (key, cert)
}

fn revoke(signer: &(DeviceSignKey, DeviceCert), target: &DeviceCert) -> Revocation {
    issue_revocation(&signer.0, &signer.1, target, NOW).unwrap()
}

#[test]
fn any_enrolled_device_can_revoke_another_and_it_verifies() {
    let alice = device(&ROOT, 1, 0xA1, u64::MAX);
    let bob = device(&ROOT, 1, 0xB2, u64::MAX);
    let revocation = revoke(&alice, &bob.1);
    revocation.verify(&root_vk(&ROOT), NOW).unwrap();
    assert!(revocation.covers(&bob.1));
    assert!(!revocation.covers(&alice.1));
}

#[test]
fn a_new_certificate_for_the_same_device_is_not_covered() {
    let alice = device(&ROOT, 1, 0xA1, u64::MAX);
    let bob = device(&ROOT, 1, 0xB2, u64::MAX);
    let revocation = revoke(&alice, &bob.1);
    let reissued = issue_device_cert(
        &ROOT,
        &[1; 64],
        &bob.1.device_id,
        &bob.1.device_vk,
        u64::MAX,
        999,
    )
    .unwrap();
    assert!(!revocation.covers(&reissued));
}

#[test]
fn a_foreign_account_cannot_revoke_and_cannot_be_revoked() {
    let alice = device(&ROOT, 1, 0xA1, u64::MAX);
    let outsider_root = [0x08; 32];
    let outsider = device(&outsider_root, 2, 0xC3, u64::MAX);
    assert!(issue_revocation(&outsider.0, &outsider.1, &alice.1, NOW).is_err());
    let forged = Revocation {
        client_id: alice.1.client_id,
        device_id: alice.1.device_id,
        serial: alice.1.serial,
        ..revoke(&outsider, &outsider.1)
    };
    assert!(forged.verify(&root_vk(&ROOT), NOW).is_err());
    assert!(forged.verify(&root_vk(&outsider_root), NOW).is_err());
}

#[test]
fn every_signed_field_breaks_the_signature() {
    let alice = device(&ROOT, 1, 0xA1, u64::MAX);
    let bob = device(&ROOT, 1, 0xB2, u64::MAX);
    let base = revoke(&alice, &bob.1);
    let vk = root_vk(&ROOT);
    let variants = [
        Revocation {
            device_id: [0x01; 16],
            ..base.clone()
        },
        Revocation {
            serial: base.serial + 1,
            ..base.clone()
        },
        Revocation {
            revoked_at_ms: NOW + 1,
            ..base.clone()
        },
        Revocation {
            client_id: [9; 64],
            ..base.clone()
        },
        Revocation {
            signature: vec![0; base.signature.len()],
            ..base.clone()
        },
        Revocation {
            signature: base.signature[..100].to_vec(),
            ..base.clone()
        },
    ];
    for variant in &variants {
        assert!(variant.verify(&vk, NOW).is_err());
    }
}

#[test]
fn an_expired_signer_cannot_revoke() {
    let alice = device(&ROOT, 1, 0xA1, NOW - 1);
    let bob = device(&ROOT, 1, 0xB2, u64::MAX);
    let revocation = revoke(&alice, &bob.1);
    assert!(revocation.verify(&root_vk(&ROOT), NOW).is_err());
    assert!(revocation.verify(&root_vk(&ROOT), NOW - 2).is_ok());
}

#[test]
fn a_revocation_is_not_a_record_or_certificate_signature() {
    assert_ne!(session::REVOKE_CTX, session::SYNC_CTX);
    assert_ne!(session::REVOKE_CTX, session::DEVICE_CERT_CTX);
}
