#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use local::{Introduction, SharedRef};
use pq::SYNC_VK_LEN;
use record::{TAG_SHARED_HEAD, TAG_SHARED_INTRODUCER};
use secret::Secret;

fn reference(introduction: Option<Introduction>) -> SharedRef {
    SharedRef {
        vault_id: [3; 16],
        anchor: [4; 32],
        seed: Secret::new([5; 64]),
        name: "Family".into(),
        hints: vec!["10.0.0.2:7447".into()],
        epoch: 0,
        retired: Vec::new(),
        introduction,
    }
}

#[test]
fn an_introduction_survives_the_record() {
    let intro = Introduction {
        head: [9; 32],
        inviter_id: [1; 64],
        inviter_vk: Box::new([2; SYNC_VK_LEN]),
    };
    let doc = reference(Some(intro.clone())).to_document();
    let read = SharedRef::from_document(&doc).unwrap().unwrap();
    assert_eq!(read.introduction, Some(intro));
    assert!(SharedRef::from_document(&reference(None).to_document())
        .unwrap()
        .unwrap()
        .introduction
        .is_none());
}

#[test]
fn half_an_introduction_is_corrupt() {
    let intro = Introduction {
        head: [9; 32],
        inviter_id: [1; 64],
        inviter_vk: Box::new([2; SYNC_VK_LEN]),
    };
    for missing in [TAG_SHARED_HEAD, TAG_SHARED_INTRODUCER] {
        let mut doc = reference(Some(intro.clone())).to_document();
        doc.remove(missing);
        assert!(SharedRef::from_document(&doc).is_err());
    }
}

#[test]
fn a_settled_reference_forgets_its_introduction_and_keeps_the_rest() {
    let intro = Introduction {
        head: [9; 32],
        inviter_id: [1; 64],
        inviter_vk: Box::new([2; SYNC_VK_LEN]),
    };
    let held = reference(Some(intro));
    let settled = held.settled();
    assert!(settled.introduction.is_none());
    assert_eq!(settled.vault_id, held.vault_id);
    assert_eq!(settled.anchor, held.anchor);
    assert_eq!(settled.seed.expose(), held.seed.expose());
    assert_eq!(settled.hints, held.hints);
}
