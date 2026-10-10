#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use p2p_core::{relay_pow_ok, relay_pow_solve};

#[test]
fn a_solution_is_found_and_checks_at_its_difficulty_only_for_its_own_request() {
    let (salt, id) = ([7u8; 16], [9u8; 16]);
    for difficulty in [0, 1, 6, 12] {
        let nonce = relay_pow_solve(&salt, &id, difficulty).unwrap();
        assert!(relay_pow_ok(&salt, &id, nonce, difficulty));
    }
    let nonce = relay_pow_solve(&salt, &id, 12).unwrap();
    let other_requests = (0u8..64)
        .filter(|n| relay_pow_ok(&salt, &[*n; 16], nonce, 12))
        .count();
    assert!(other_requests <= 2, "a solution is for one request");
    let other_salts = (0u8..64)
        .filter(|n| relay_pow_ok(&[*n; 16], &id, nonce, 12))
        .count();
    assert!(other_salts <= 2, "and one connection");
}

#[test]
fn difficulty_zero_accepts_anything_and_a_harder_puzzle_needs_more_bits() {
    let (salt, id) = ([1u8; 16], [2u8; 16]);
    assert!(relay_pow_ok(&salt, &id, 0, 0));
    assert!(relay_pow_ok(&salt, &id, 12345, 0));
    let nonce = relay_pow_solve(&salt, &id, 10).unwrap();
    let mut hard = 10;
    while relay_pow_ok(&salt, &id, nonce, hard) {
        hard += 1;
    }
    assert!(
        hard > 10 && hard < 40,
        "the nonce stops solving somewhere above its bits"
    );
}
