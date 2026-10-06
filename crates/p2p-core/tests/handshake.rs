#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

mod common;

use common::{account, device, gate_key, node, run, Node, NOW, ROOT, VAULT};
use p2p_core::suite::{FINISH_LEN, HELLO_LEN, MAX_HANDSHAKE_MSG, REPLY_FIXED_LEN, REPLY_LEN};
use p2p_core::{Accept, CookieSecret, Initiator, Load, Responder, MAX_PLAINTEXT, OVERHEAD};

fn start(dialer: &Node) -> (Initiator, Vec<u8>) {
    Initiator::start(&dialer.gate[0], NOW).unwrap()
}

fn reply_for(listener: &Node, hello: &[u8]) -> (Responder, Vec<u8>) {
    let cookies = CookieSecret::generate().unwrap();
    match Responder::accept(&listener.local(), &cookies, Load::default(), hello, NOW).unwrap() {
        Accept::Reply(responder, reply) => (responder, reply),
        Accept::Challenge(_) => panic!("unexpected challenge"),
    }
}

#[test]
fn both_sides_authenticate_each_other_and_share_a_channel() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (mut outbound, mut inbound) = run(&alice, &bob).unwrap();
    assert_eq!(outbound.peer.device_id, [0xB2; 16]);
    assert_eq!(inbound.peer.device_id, [0xA1; 16]);
    assert_eq!(outbound.channel.peer_id(), &[0xB2; 16]);
    assert_eq!(inbound.channel.peer_id(), &[0xA1; 16]);
    for round in 0..3u8 {
        let to_bob = outbound.channel.seal(&[round; 100]).unwrap();
        assert_eq!(
            inbound.channel.open(&to_bob).unwrap().expose(),
            &[round; 100]
        );
        let to_alice = inbound.channel.seal(&[round ^ 0xFF; 7]).unwrap();
        assert_eq!(
            outbound.channel.open(&to_alice).unwrap().expose(),
            &[round ^ 0xFF; 7]
        );
    }
}

#[test]
fn message_sizes_are_exact_and_bounded() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (initiator, hello) = start(&alice);
    assert_eq!(hello.len(), HELLO_LEN);
    let (responder, reply) = reply_for(&bob, &hello);
    assert_eq!(reply.len(), REPLY_LEN);
    assert_eq!(MAX_HANDSHAKE_MSG, REPLY_LEN);
    let (finish, _) = initiator.finish(&alice.local(), &reply, NOW).unwrap();
    assert_eq!(finish.len(), FINISH_LEN);
    responder.finish(&bob.local(), &finish, NOW).unwrap();
}

#[test]
fn two_sessions_never_share_keys() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (mut one, _) = run(&alice, &bob).unwrap();
    let (_, mut other) = run(&alice, &bob).unwrap();
    let message = one.channel.seal(b"hello").unwrap();
    assert!(other.channel.open(&message).is_err());
}

#[test]
fn replay_reorder_reflection_and_tampering_are_refused() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (mut outbound, mut inbound) = run(&alice, &bob).unwrap();

    let first = outbound.channel.seal(b"one").unwrap();
    let second = outbound.channel.seal(b"two").unwrap();
    assert!(inbound.channel.open(&second).is_err(), "out of order");
    inbound.channel.open(&first).unwrap();
    assert!(inbound.channel.open(&first).is_err(), "replay");
    inbound.channel.open(&second).unwrap();

    let own = outbound.channel.seal(b"three").unwrap();
    assert!(
        outbound.channel.open(&own).is_err(),
        "reflection to the sender"
    );

    let fourth = outbound.channel.seal(b"four").unwrap();
    for at in (0..fourth.len()).step_by(11) {
        let mut tampered = fourth.clone();
        tampered[at] ^= 1;
        assert!(inbound.channel.open(&tampered).is_err(), "byte {at}");
    }
    assert!(inbound.channel.open(&fourth[..fourth.len() - 1]).is_err());
    inbound.channel.open(&own).unwrap();
    assert_eq!(inbound.channel.open(&fourth).unwrap().expose(), b"four");
}

#[test]
fn channel_bounds_plaintext_and_wire_size() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (mut outbound, mut inbound) = run(&alice, &bob).unwrap();
    assert!(outbound.channel.seal(&vec![0; MAX_PLAINTEXT + 1]).is_err());
    let full = outbound.channel.seal(&vec![1; MAX_PLAINTEXT]).unwrap();
    assert_eq!(full.len(), MAX_PLAINTEXT + OVERHEAD);
    assert_eq!(
        inbound.channel.open(&full).unwrap().expose().len(),
        MAX_PLAINTEXT
    );
    let mut oversized = full;
    oversized.push(0);
    assert!(inbound.channel.open(&oversized).is_err());
}

fn failure(dialer: &Node, listener: &Node) -> String {
    run(dialer, listener).unwrap_err().to_string()
}

#[test]
fn a_foreign_root_a_foreign_account_and_an_expired_cert_fail_identically() {
    let (alice, bob) = (node(0xA1), node(0xB2));

    let intruder_root = [0x08; 32];
    let mut intruder = node(0xC3);
    intruder.dev = device(&intruder_root, 1, 0xC3, u64::MAX);
    let as_listener = failure(&alice, &intruder);
    let as_dialer = failure(&intruder, &bob);

    let mut stranger = node(0xD4);
    stranger.dev = device(&ROOT, 2, 0xD4, u64::MAX);
    let wrong_account = failure(&alice, &stranger);

    let mut expired = node(0xE5);
    expired.dev = device(&ROOT, 1, 0xE5, NOW - 1);
    let stale = failure(&alice, &expired);

    for message in [as_listener, as_dialer, wrong_account, stale] {
        assert_eq!(message, "handshake failed");
    }
}

#[test]
fn a_device_cannot_handshake_with_itself() {
    let alice = node(0xA1);
    assert_eq!(failure(&alice, &alice), "handshake failed");
}

#[test]
fn a_different_vault_cannot_complete_the_handshake() {
    let alice = node(0xA1);
    let mut bob = node(0xB2);
    bob.vault = [0x78; 16];
    bob.gate = vec![kdf::p2p_gate_key(&[1; 32], &bob.vault).unwrap()];
    assert!(run(&alice, &bob).is_err());
}

/// A coarse sweep of `0..len` plus the first and last byte of each region.
fn sampled(len: usize, edges: &[usize]) -> Vec<usize> {
    let mut at: Vec<usize> = (0..len).step_by(331).chain(edges.iter().copied()).collect();
    at.push(len - 1);
    at.sort_unstable();
    at.dedup();
    at
}

#[test]
fn every_tampered_reply_and_finish_byte_is_refused() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let fixed = REPLY_FIXED_LEN;
    let reply_edges = [
        0,
        4,
        6,
        8,
        9,
        73,
        74,
        75,
        fixed - 1,
        fixed,
        fixed + 74,
        fixed + 75,
        fixed + 76,
    ];
    for at in sampled(REPLY_LEN, &reply_edges) {
        let (initiator, hello) = start(&alice);
        let (_, mut reply) = reply_for(&bob, &hello);
        reply[at] ^= 1;
        assert!(
            initiator.finish(&alice.local(), &reply, NOW).is_err(),
            "reply byte {at}"
        );
    }
    let finish_edges = [0, 4, 6, 8, 9, 10, 83, 84, 85];
    for at in sampled(FINISH_LEN, &finish_edges) {
        let (initiator, hello) = start(&alice);
        let (responder, reply) = reply_for(&bob, &hello);
        let (mut finish, _) = initiator.finish(&alice.local(), &reply, NOW).unwrap();
        finish[at] ^= 1;
        assert!(
            responder.finish(&bob.local(), &finish, NOW).is_err(),
            "finish byte {at}"
        );
    }
}

#[test]
fn a_reply_cannot_be_replayed_into_another_handshake() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (_, hello_one) = start(&alice);
    let (_, reply_one) = reply_for(&bob, &hello_one);
    let (initiator_two, _) = start(&alice);
    assert!(initiator_two
        .finish(&alice.local(), &reply_one, NOW)
        .is_err());
}

#[test]
fn a_finish_cannot_be_replayed_to_a_new_responder() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (initiator, hello) = start(&alice);
    let (_, reply) = reply_for(&bob, &hello);
    let (finish, _) = initiator.finish(&alice.local(), &reply, NOW).unwrap();
    let (_, hello_two) = start(&alice);
    let (fresh, _) = reply_for(&bob, &hello_two);
    assert!(fresh.finish(&bob.local(), &finish, NOW).is_err());
}

#[test]
fn wrong_shape_wrong_suite_and_wrong_version_are_malformed() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (_, hello) = start(&alice);
    let cookies = CookieSecret::generate().unwrap();
    let probe = |bytes: &[u8]| {
        Responder::accept(&bob.local(), &cookies, Load::default(), bytes, NOW)
            .err()
            .unwrap()
            .to_string()
    };
    for bad in [
        hello[..HELLO_LEN - 1].to_vec(),
        [hello.clone(), vec![0]].concat(),
        Vec::new(),
    ] {
        assert_eq!(probe(&bad), "malformed handshake message");
    }
    for (at, value) in [(0usize, 0u8), (5, 9), (7, 2), (8, 2)] {
        let mut bad = hello.clone();
        bad[at] = value;
        assert_eq!(probe(&bad), "malformed handshake message", "byte {at}");
    }
}

#[test]
fn a_shared_vault_accepts_devices_of_every_member_account_and_no_one_else() {
    let (root_b, root_c) = ([0x08; 32], [0x09; 32]);
    let member = |root: &[u8; 32], client: u8, id: u8| {
        let mut n = node(id);
        n.dev = device(root, client, id, u64::MAX);
        n.accounts = vec![account(&ROOT, 1), account(&root_b, 2)];
        n
    };
    let alice = member(&ROOT, 1, 0xA1);
    let bob = member(&root_b, 2, 0xB2);
    let (mut outbound, mut inbound) = run(&alice, &bob).unwrap();
    assert_eq!(outbound.peer.client_id, [2; 64]);
    assert_eq!(inbound.peer.client_id, [1; 64]);
    let message = outbound.channel.seal(b"shared").unwrap();
    assert_eq!(inbound.channel.open(&message).unwrap().expose(), b"shared");

    let mut carol = node(0xC3);
    carol.dev = device(&root_c, 3, 0xC3, u64::MAX);
    carol.accounts = alice
        .accounts
        .iter()
        .map(|a| account(&ROOT, a.client_id[0]))
        .collect();
    assert_eq!(failure(&carol, &bob), "handshake failed");
    assert_eq!(failure(&alice, &carol), "handshake failed");
}

#[test]
fn a_revoked_device_is_refused_by_both_sides() {
    let (alice, mut bob) = (node(0xA1), node(0xB2));
    let revocation =
        session::issue_revocation(&alice.dev.sign, &alice.dev.cert, &bob.dev.cert, NOW).unwrap();
    let mut listener = node(0xC3);
    listener.revoked.push(revocation.clone());
    assert_eq!(failure(&bob, &listener), "handshake failed");

    let mut dialer = node(0xD4);
    dialer.revoked.push(revocation.clone());
    assert_eq!(failure(&dialer, &bob), "handshake failed");

    bob.revoked.push(revocation);
    assert!(
        run(&alice, &bob).is_ok(),
        "the revoked device's own list does not block others"
    );
    let _ = (gate_key(1), VAULT);
}

#[test]
fn split_halves_keep_every_check_and_work_on_two_tasks_independently() {
    let (alice, bob) = (node(0xA1), node(0xB2));
    let (outbound, inbound) = run(&alice, &bob).unwrap();
    let (mut a_send, mut a_recv) = outbound.channel.into_halves();
    let (mut b_send, mut b_recv) = inbound.channel.into_halves();
    let first = a_send.seal(b"a1").unwrap();
    let second = a_send.seal(b"a2").unwrap();
    let reply = b_send.seal(b"b1").unwrap();
    assert!(b_recv.open(&second).is_err(), "order is still enforced");
    assert_eq!(b_recv.open(&first).unwrap().expose(), b"a1");
    assert_eq!(b_recv.open(&second).unwrap().expose(), b"a2");
    assert_eq!(a_recv.open(&reply).unwrap().expose(), b"b1");
    assert!(a_recv.open(&first).is_err(), "direction is still enforced");
}
