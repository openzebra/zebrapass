#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use p2p_core::{open_beacon, seal_beacon, BEACON_WINDOW_MS, MAX_BEACON};
use secret::Secret;
use syncwire::BEACON_WIRE_MAX;

const NOW: u64 = 1_700_000_000_000;

const fn key(byte: u8) -> Secret<[u8; 32]> {
    Secret::new([byte; 32])
}

#[test]
fn a_beacon_opens_for_the_account_and_names_its_sender() {
    let wire = seal_beacon(&key(1), [7; 16], NOW, b"hello").unwrap();
    let (sender, payload) = open_beacon(&key(1), &wire, NOW + 5_000).unwrap();
    assert_eq!(sender, [7; 16]);
    assert_eq!(payload.expose(), b"hello");
    assert!(wire.len() <= MAX_BEACON);
    let most = seal_beacon(&key(1), [7; 16], NOW, &[0; BEACON_WIRE_MAX]).unwrap();
    assert_eq!(most.len(), MAX_BEACON);
}

#[test]
fn every_wrong_beacon_is_rejected_alike() {
    let wire = seal_beacon(&key(1), [7; 16], NOW, b"hello").unwrap();
    assert!(open_beacon(&key(2), &wire, NOW).is_err(), "another account");
    for at in [0, 20, 40, 60, 80, wire.len() - 1] {
        let mut flipped = wire.clone();
        flipped[at] ^= 1;
        assert!(open_beacon(&key(1), &flipped, NOW).is_err(), "byte {at}");
    }
    assert!(open_beacon(&key(1), &wire[..wire.len() - 1], NOW).is_err());
    assert!(open_beacon(&key(1), &[], NOW).is_err());
    assert!(open_beacon(&key(1), &vec![0; MAX_BEACON + 1], NOW).is_err());
    assert!(seal_beacon(&key(1), [7; 16], NOW, &[0; BEACON_WIRE_MAX + 1]).is_err());
}

#[test]
fn a_beacon_is_fresh_only_within_the_window() {
    let wire = seal_beacon(&key(1), [7; 16], NOW, b"x").unwrap();
    assert!(open_beacon(&key(1), &wire, NOW + BEACON_WINDOW_MS).is_ok());
    assert!(open_beacon(&key(1), &wire, NOW + BEACON_WINDOW_MS + 1).is_err());
    assert!(open_beacon(&key(1), &wire, NOW - BEACON_WINDOW_MS).is_ok());
    assert!(open_beacon(&key(1), &wire, NOW - BEACON_WINDOW_MS - 1).is_err());
}

#[test]
fn a_frame_that_is_not_a_beacon_is_not_one_even_under_the_same_key() {
    let meta = frame::FrameMeta {
        kind: frame::KIND_REVISION,
        record_id: 1,
        revision: 0,
        origin_device: [7; 16],
        timestamp_ms: NOW,
        alg: frame::ALG_CASCADE,
    };
    let other = frame::seal(&key(1), &meta, b"x").unwrap();
    assert!(open_beacon(&key(1), &other, NOW).is_err());
    let nobody = seal_beacon(&key(1), [0; 16], NOW, b"x").unwrap();
    assert!(open_beacon(&key(1), &nobody, NOW).is_err(), "no sender");
}
