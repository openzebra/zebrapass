#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

mod common;

use common::{accept, gate_key, node, run_under, NOW};
use p2p_core::suite::{CHALLENGE_LEN, HELLO_LEN, KIND_OFFSET, SOLVED_LEN};
use p2p_core::{
    Accept, CookieSecret, Initiator, Load, Responder, COOKIE_WINDOW_MS, GATE_WINDOW_MS,
    MAX_DIFFICULTY,
};

const BUSY: Load = Load { difficulty: 8 };

fn hello_from(secret: u8, at: u64) -> (Initiator, Vec<u8>) {
    Initiator::start(&gate_key(secret), at).unwrap()
}

/// Leading zero bits of the puzzle hash of `counter` for the solved message
/// `solved` (header, cookie, counter, hello), worked out here and not by the
/// code under test: `SHA-256("brby/v2/p2p-pow" ‖ cookie mac ‖ H(hello) ‖ counter)`
/// with `H(hello) = SHA-256("brby/v2/p2p-hello" ‖ hello)`.
fn zero_bits(solved: &[u8], counter: u64) -> u32 {
    use sha2::{Digest, Sha256};
    let counter_at = SOLVED_LEN - HELLO_LEN - 8;
    let mac = &solved[18..counter_at];
    let hello = &solved[SOLVED_LEN - HELLO_LEN..];
    let hello_hash = Sha256::new()
        .chain_update(b"brby/v2/p2p-hello")
        .chain_update(hello)
        .finalize();
    let digest = Sha256::new()
        .chain_update(b"brby/v2/p2p-pow")
        .chain_update(mac)
        .chain_update(hello_hash)
        .chain_update(counter.to_be_bytes())
        .finalize();
    let mut bits = 0;
    for byte in digest {
        if byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

fn challenge_for(hello: &[u8], load: Load) -> Vec<u8> {
    match accept(&node(0xB2), load, hello, NOW).unwrap() {
        Accept::Challenge(challenge) => challenge,
        Accept::Reply(..) => panic!("expected a challenge"),
    }
}

#[test]
fn a_stranger_is_dropped_by_the_gate_and_never_given_a_puzzle() {
    let (_, hello) = hello_from(2, NOW);
    for load in [Load::default(), BUSY] {
        let error = accept(&node(0xB2), load, &hello, NOW).unwrap_err();
        assert_eq!(error.to_string(), "handshake failed");
    }
}

#[test]
fn a_tampered_hello_body_fails_the_gate() {
    let (_, hello) = hello_from(1, NOW);
    for at in [9, 80, 600, HELLO_LEN - 33, HELLO_LEN - 32, HELLO_LEN - 1] {
        let mut bad = hello.clone();
        bad[at] ^= 1;
        let error = accept(&node(0xB2), Load::default(), &bad, NOW).unwrap_err();
        assert!(
            ["handshake failed", "malformed handshake message"]
                .contains(&error.to_string().as_str()),
            "byte {at}"
        );
    }
}

#[test]
fn the_timestamp_window_is_enforced_in_both_directions() {
    let listener = node(0xB2);
    for (stamp, ok) in [
        (NOW, true),
        (NOW - GATE_WINDOW_MS, true),
        (NOW + GATE_WINDOW_MS, true),
        (NOW - GATE_WINDOW_MS - 1, false),
        (NOW + GATE_WINDOW_MS + 1, false),
    ] {
        let (_, hello) = hello_from(1, stamp);
        assert_eq!(
            accept(&listener, Load::default(), &hello, NOW).is_ok(),
            ok,
            "{stamp}"
        );
    }
}

#[test]
fn a_device_that_missed_one_key_rotation_still_gets_through() {
    let mut listener = node(0xB2);
    listener.gate = vec![gate_key(5), gate_key(1)];
    let (_, current) = hello_from(5, NOW);
    let (_, previous) = hello_from(1, NOW);
    let (_, ancient) = hello_from(9, NOW);
    assert!(accept(&listener, Load::default(), &current, NOW).is_ok());
    assert!(accept(&listener, Load::default(), &previous, NOW).is_ok());
    assert!(accept(&listener, Load::default(), &ancient, NOW).is_err());
}

#[test]
fn an_idle_responder_issues_no_puzzle() {
    let (_, hello) = hello_from(1, NOW);
    assert!(matches!(
        accept(&node(0xB2), Load::default(), &hello, NOW).unwrap(),
        Accept::Reply(..)
    ));
}

#[test]
fn a_busy_responder_answers_with_a_stateless_challenge_and_a_solution_unlocks_it() {
    let (initiator, hello) = hello_from(1, NOW);
    let challenge = challenge_for(&hello, BUSY);
    assert_eq!(challenge.len(), CHALLENGE_LEN);
    let solved = initiator.solve(&challenge).unwrap();
    assert_eq!(solved.len(), SOLVED_LEN);
    let cookies = CookieSecret::generate().unwrap();
    let listener = node(0xB2);
    // A different cookie secret means a different responder instance: the
    // challenge was stateless, but it only verifies under its own secret.
    assert!(Responder::accept(&listener.local(), &cookies, BUSY, &solved, NOW).is_err());
}

#[test]
fn the_whole_handshake_works_through_a_puzzle() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (mut outbound, mut inbound) = run_under(&alice, &bob, BUSY).unwrap();
    let message = outbound.channel.seal(b"after the puzzle").unwrap();
    assert_eq!(
        inbound.channel.open(&message).unwrap().expose(),
        b"after the puzzle"
    );
}

fn issue(secret: &CookieSecret, load: Load, hello: &[u8], at: u64) -> Vec<u8> {
    match Responder::accept(&node(0xB2).local(), secret, load, hello, at).unwrap() {
        Accept::Challenge(challenge) => challenge,
        Accept::Reply(..) => panic!("expected a challenge"),
    }
}

#[test]
fn a_solution_is_bound_to_its_hello_its_cookie_and_the_clock() {
    let listener = node(0xB2);
    let cookies = CookieSecret::generate().unwrap();
    let try_it = |input: &[u8], load: Load, at: u64| {
        Responder::accept(&listener.local(), &cookies, load, input, at).is_ok()
    };

    let (initiator, hello) = hello_from(1, NOW);
    let solved = initiator
        .solve(&issue(&cookies, BUSY, &hello, NOW))
        .unwrap();
    assert!(try_it(&solved, BUSY, NOW));
    assert!(try_it(&solved, BUSY, NOW + COOKIE_WINDOW_MS));
    assert!(
        !try_it(&solved, BUSY, NOW + COOKIE_WINDOW_MS + 1),
        "expired cookie"
    );

    // Another hello cannot ride on this solution.
    let (_, other_hello) = hello_from(1, NOW);
    let mut spliced = solved.clone();
    spliced[SOLVED_LEN - HELLO_LEN..].copy_from_slice(&other_hello);
    assert!(
        !try_it(&spliced, BUSY, NOW),
        "solution moved to another hello"
    );

    // The cookie MAC, the claimed difficulty and the counter are all checked.
    for at in [9 + 1 + 8, 9 + 1 + 8 + 31] {
        let mut bad = solved.clone();
        bad[at] ^= 1;
        assert!(!try_it(&bad, BUSY, NOW), "mac byte {at}");
    }
    let mut easier = solved.clone();
    easier[9] = 0;
    assert!(
        !try_it(&easier, BUSY, NOW),
        "difficulty lowered by the client"
    );
    // A counter that is not a solution, found by looking: most counters fail
    // by a wide margin, but flipping bits of the real one could land on
    // another that solves it, so the search says which one fails.
    let at = SOLVED_LEN - HELLO_LEN - 8;
    let real = u64::from_be_bytes(solved[at..at + 8].try_into().unwrap());
    assert!(
        zero_bits(&solved, real) >= u32::from(BUSY.difficulty),
        "the real counter solves it, by this test's own hash"
    );
    let wrong = (1..=1_000_000u64)
        .map(|step| real.wrapping_add(step))
        .find(|counter| zero_bits(&solved, *counter) < u32::from(BUSY.difficulty))
        .unwrap();
    let mut wrong_counter = solved.clone();
    wrong_counter[at..at + 8].copy_from_slice(&wrong.to_be_bytes());
    assert!(!try_it(&wrong_counter, BUSY, NOW), "wrong counter");

    // A cookie from an easier moment does not satisfy a harder demand.
    assert!(
        !try_it(&solved, Load { difficulty: 20 }, NOW),
        "below the current demand"
    );
    assert!(
        try_it(&solved, Load { difficulty: 4 }, NOW),
        "above a lighter demand"
    );
}

#[test]
fn a_cookie_from_another_responder_secret_is_refused() {
    let listener = node(0xB2);
    let (initiator, hello) = hello_from(1, NOW);
    let first = CookieSecret::generate().unwrap();
    let second = CookieSecret::generate().unwrap();
    let solved = initiator.solve(&issue(&first, BUSY, &hello, NOW)).unwrap();
    assert!(Responder::accept(&listener.local(), &second, BUSY, &solved, NOW).is_err());
    assert!(Responder::accept(&listener.local(), &first, BUSY, &solved, NOW).is_ok());
}

#[test]
fn a_client_refuses_a_puzzle_harder_than_the_cap() {
    let (initiator, hello) = hello_from(1, NOW);
    let mut challenge = challenge_for(&hello, BUSY);
    challenge[KIND_OFFSET + 1] = MAX_DIFFICULTY + 1;
    assert_eq!(
        initiator.solve(&challenge).unwrap_err().to_string(),
        "puzzle too hard"
    );
}

#[test]
fn the_responder_never_asks_for_more_than_the_cap() {
    let (initiator, hello) = hello_from(1, NOW);
    let greedy = Load {
        difficulty: u8::MAX,
    };
    let challenge = challenge_for(&hello, greedy);
    assert_eq!(challenge[KIND_OFFSET + 1], MAX_DIFFICULTY);
    drop(initiator);
}

#[test]
fn the_same_hello_always_has_the_same_id_so_a_transport_can_refuse_replays() {
    let (_, hello) = hello_from(1, NOW);
    let listener = node(0xB2);
    let id_of = |input: &[u8]| match accept(&listener, Load::default(), input, NOW).unwrap() {
        Accept::Reply(responder, _) => *responder.hello_id(),
        Accept::Challenge(_) => panic!("unexpected challenge"),
    };
    assert_eq!(id_of(&hello), id_of(&hello));
    let (_, another) = hello_from(1, NOW);
    assert_ne!(id_of(&hello), id_of(&another));
}

#[test]
fn a_hello_has_one_id_alone_or_inside_a_solved_puzzle() {
    let (initiator, hello) = hello_from(1, NOW);
    let challenge = challenge_for(&hello, BUSY);
    let solved = initiator.solve(&challenge).unwrap();
    let alone = Responder::first_message_id(&hello).unwrap();
    assert_eq!(
        Responder::first_message_id(&solved).unwrap(),
        alone,
        "a replay cannot dodge the transport's memory by being re-solved"
    );
    let listener = node(0xB2);
    let answered = match accept(&listener, Load::default(), &hello, NOW).unwrap() {
        Accept::Reply(responder, _) => *responder.hello_id(),
        Accept::Challenge(_) => panic!("unexpected challenge"),
    };
    assert_eq!(
        alone, answered,
        "the id before the reply is the id after it"
    );

    let (_, another) = hello_from(1, NOW);
    assert_ne!(Responder::first_message_id(&another).unwrap(), alone);
    assert!(Responder::first_message_id(&hello[..hello.len() - 1]).is_err());
    assert!(Responder::first_message_id(&[]).is_err());
    assert!(Responder::first_message_id(&challenge).is_err());
}

#[test]
fn a_harder_puzzle_takes_more_work_to_solve() {
    let (initiator, hello) = hello_from(1, NOW);
    let cookies = CookieSecret::generate().unwrap();
    let count = |difficulty: u8| {
        let challenge = issue(&cookies, Load { difficulty }, &hello, NOW);
        let solved = initiator.solve(&challenge).unwrap();
        let at = SOLVED_LEN - HELLO_LEN - 8;
        u64::from_be_bytes(solved[at..at + 8].try_into().unwrap())
    };
    let easy: u64 = (0..5).map(|_| count(2)).sum();
    let hard = count(14);
    assert!(hard > 0 || easy == 0);
    assert!(Responder::accept(
        &node(0xB2).local(),
        &cookies,
        Load { difficulty: 14 },
        &initiator
            .solve(&issue(&cookies, Load { difficulty: 14 }, &hello, NOW))
            .unwrap(),
        NOW
    )
    .is_ok());
}

#[test]
fn a_listener_with_several_vaults_routes_a_hello_to_the_right_one() {
    let (mut personal, mut shared) = (node(0xB2), node(0xB2));
    personal.gate = vec![gate_key(1)];
    shared.gate = vec![gate_key(2)];
    let listener = [personal.local(), shared.local()];
    let (_, for_personal) = hello_from(1, NOW);
    let (_, for_shared) = hello_from(2, NOW);
    let (_, for_nobody) = hello_from(3, NOW);
    assert_eq!(Responder::route(&listener, &for_personal, NOW).unwrap(), 0);
    assert_eq!(Responder::route(&listener, &for_shared, NOW).unwrap(), 1);
    assert_eq!(
        Responder::route(&listener, &for_nobody, NOW)
            .unwrap_err()
            .to_string(),
        "handshake failed"
    );
    let (initiator, hello) = hello_from(2, NOW);
    let cookies = CookieSecret::generate().unwrap();
    let Accept::Challenge(challenge) =
        Responder::accept(&shared.local(), &cookies, BUSY, &hello, NOW).unwrap()
    else {
        panic!("expected a challenge")
    };
    let solved = initiator.solve(&challenge).unwrap();
    assert_eq!(
        Responder::route(&listener, &solved, NOW + 40_000).unwrap(),
        1
    );
    assert!(Responder::route(&listener, &hello[..HELLO_LEN - 1], NOW).is_err());
}
