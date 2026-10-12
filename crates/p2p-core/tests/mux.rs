#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use p2p_core::{Dispatcher, Inbound, Message, Outcome, Reassembler, Reply};
use syncwire::limits::PIPELINE_DEPTH;
use syncwire::{Direction, Header, MsgType};

fn wire(ty: MsgType, req_id: u32, payload: &[u8], direction: Direction) -> Vec<u8> {
    let header = Header::new(ty, req_id, payload.len(), direction).unwrap();
    [&header.encode()[..], payload].concat()
}

fn message(ty: MsgType, req_id: u32, payload: &[u8], direction: Direction) -> Message {
    let mut out = Vec::new();
    Reassembler::new(direction)
        .feed(&wire(ty, req_id, payload, direction), &mut out)
        .unwrap();
    out.pop().unwrap()
}

#[test]
fn messages_are_rebuilt_however_the_bytes_are_cut() {
    let bytes = [
        wire(MsgType::Want, 1, &[7; 12], Direction::Request),
        wire(MsgType::Rekey, 2, &[], Direction::Request),
        wire(MsgType::Ping, 3, &[9; 8], Direction::Request),
    ]
    .concat();
    for cut in 1..=bytes.len() {
        let mut reader = Reassembler::new(Direction::Request);
        let mut out = Vec::new();
        for piece in bytes.chunks(cut) {
            reader.feed(piece, &mut out).unwrap();
        }
        assert!(!reader.is_mid_message());
        let ids: Vec<u32> = out.iter().map(|m| m.header.req_id).collect();
        assert_eq!(ids, [1, 2, 3], "cut {cut}");
        assert_eq!(out[0].payload.expose(), &vec![7; 12]);
    }
}

#[test]
fn a_header_with_a_bad_type_direction_or_length_ends_the_stream() {
    let mut out = Vec::new();
    let mut bad = wire(MsgType::Ping, 1, &[0; 8], Direction::Request);
    bad[0] = 99;
    assert!(Reassembler::new(Direction::Request)
        .feed(&bad, &mut out)
        .is_err());
    let pong = wire(MsgType::Pong, 1, &[0; 8], Direction::Response);
    assert!(Reassembler::new(Direction::Request)
        .feed(&pong, &mut out)
        .is_err());
    let mut long = wire(MsgType::Busy, 1, &[], Direction::Response);
    long[8] = 1;
    assert!(Reassembler::new(Direction::Response)
        .feed(&long, &mut out)
        .is_err());
    assert!(out.is_empty());
}

#[test]
fn replies_are_matched_by_request_number_in_any_order() {
    let mut dispatcher = Dispatcher::new(1000);
    let a = dispatcher.request(MsgType::Want, 12, 0).unwrap().unwrap();
    let b = dispatcher
        .request(MsgType::Frontier, 0, 0)
        .unwrap()
        .unwrap();
    assert_ne!(a.req_id, b.req_id);
    let done = dispatcher
        .on_message(message(
            MsgType::Frontier,
            b.req_id,
            &[1],
            Direction::Response,
        ))
        .unwrap();
    assert_eq!(done.request, MsgType::Frontier);
    assert!(matches!(done.reply, Reply::Payload(_)));
    let done = dispatcher
        .on_message(message(MsgType::Bundle, a.req_id, &[], Direction::Response))
        .unwrap();
    assert_eq!(done.request, MsgType::Want);
    assert_eq!(dispatcher.in_flight(), 0);
}

#[test]
fn the_pipeline_holds_four_and_frees_a_place_per_answer() {
    let mut dispatcher = Dispatcher::new(1000);
    let ids: Vec<u32> = (0..PIPELINE_DEPTH)
        .map(|_| {
            dispatcher
                .request(MsgType::Ping, 8, 0)
                .unwrap()
                .unwrap()
                .req_id
        })
        .collect();
    assert!(dispatcher.request(MsgType::Ping, 8, 0).unwrap().is_none());
    dispatcher
        .on_message(message(MsgType::Pong, ids[2], &[0; 8], Direction::Response))
        .unwrap();
    assert!(dispatcher.request(MsgType::Ping, 8, 0).unwrap().is_some());
}

#[test]
fn an_unsolicited_duplicate_or_mismatched_reply_ends_the_connection() {
    let mut dispatcher = Dispatcher::new(1000);
    assert!(dispatcher
        .on_message(message(MsgType::Pong, 5, &[0; 8], Direction::Response))
        .is_err());
    let a = dispatcher
        .request(MsgType::Frontier, 0, 0)
        .unwrap()
        .unwrap();
    assert!(dispatcher
        .on_message(message(
            MsgType::Announce,
            a.req_id,
            &[],
            Direction::Response
        ))
        .is_err());
    let a = dispatcher.request(MsgType::Rekey, 0, 0).unwrap().unwrap();
    dispatcher
        .on_message(message(
            MsgType::Refused,
            a.req_id,
            &[],
            Direction::Response,
        ))
        .unwrap();
    assert!(dispatcher
        .on_message(message(
            MsgType::Refused,
            a.req_id,
            &[],
            Direction::Response
        ))
        .is_err());
}

#[test]
fn status_replies_answer_any_request() {
    for (ty, check) in [
        (MsgType::Busy, 0),
        (MsgType::Refused, 1),
        (MsgType::Stale, 2),
    ] {
        let mut dispatcher = Dispatcher::new(1000);
        let a = dispatcher
            .request(MsgType::SnapReq, 40, 0)
            .unwrap()
            .unwrap();
        let done = dispatcher
            .on_message(message(ty, a.req_id, &[], Direction::Response))
            .unwrap();
        let kind = match done.reply {
            Reply::Busy => 0,
            Reply::Refused => 1,
            Reply::Stale => 2,
            Reply::Payload(_) => 3,
        };
        assert_eq!(kind, check);
    }
}

#[test]
fn a_request_unanswered_for_too_long_is_reported() {
    let mut dispatcher = Dispatcher::new(1000);
    let a = dispatcher
        .request(MsgType::Frontier, 0, 500)
        .unwrap()
        .unwrap();
    assert_eq!(dispatcher.expired(1499), None);
    assert_eq!(dispatcher.expired(1500), Some(a.req_id));
}

#[test]
fn a_dispatcher_cannot_send_what_only_a_responder_sends() {
    let mut dispatcher = Dispatcher::new(1000);
    for ty in [
        MsgType::SnapChunk,
        MsgType::Pong,
        MsgType::Busy,
        MsgType::Refused,
        MsgType::Stale,
    ] {
        assert!(dispatcher.request(ty, 0, 0).is_err());
    }
    assert!(dispatcher.request(MsgType::Want, 13, 0).is_err());
}

fn header(ty: MsgType, req_id: u32) -> Header {
    Header::new(ty, req_id, 0, Direction::Request)
        .or_else(|_| Header::new(ty, req_id, 8, Direction::Request))
        .or_else(|_| Header::new(ty, req_id, 12, Direction::Request))
        .or_else(|_| Header::new(ty, req_id, 40, Direction::Request))
        .unwrap()
}

#[test]
fn the_answering_side_refuses_a_fifth_open_request_and_a_repeated_number() {
    let mut inbound = Inbound::new(100, 100, 10);
    for id in 0..4 {
        inbound.admit(&header(MsgType::Frontier, id)).unwrap();
    }
    assert!(inbound.admit(&header(MsgType::Frontier, 9)).is_err());
    inbound.finish(0, Outcome::Served).unwrap();
    assert!(inbound.admit(&header(MsgType::Frontier, 1)).is_err());
    inbound.admit(&header(MsgType::Frontier, 9)).unwrap();
    assert_eq!(inbound.in_flight(), 4);
}

#[test]
fn only_refusals_count_against_the_failure_budget() {
    let mut inbound = Inbound::new(1000, 1000, 3);
    for id in 0..50 {
        inbound.admit(&header(MsgType::Frontier, id)).unwrap();
        let outcome = if id % 2 == 0 {
            Outcome::Busy
        } else {
            Outcome::Stale
        };
        inbound.finish(id, outcome).unwrap();
    }
    for id in 100..102 {
        inbound.admit(&header(MsgType::Frontier, id)).unwrap();
        inbound.finish(id, Outcome::Refused).unwrap();
    }
    inbound.admit(&header(MsgType::Frontier, 102)).unwrap();
    assert!(inbound.finish(102, Outcome::Refused).is_err());
}

#[test]
fn chunk_requests_have_their_own_budget_and_a_timeout_is_a_failure() {
    let mut inbound = Inbound::new(2, 5, 2);
    for id in 0..5 {
        inbound.admit(&header(MsgType::SnapReq, id)).unwrap();
        inbound.finish(id, Outcome::Served).unwrap();
    }
    assert!(inbound.admit(&header(MsgType::SnapReq, 5)).is_err());
    let mut inbound = Inbound::new(2, 5, 2);
    inbound.admit(&header(MsgType::Frontier, 0)).unwrap();
    inbound.finish(0, Outcome::Served).unwrap();
    inbound.admit(&header(MsgType::Frontier, 1)).unwrap();
    inbound.finish(1, Outcome::Served).unwrap();
    assert!(inbound.admit(&header(MsgType::Frontier, 2)).is_err());
    let mut inbound = Inbound::new(9, 9, 1);
    inbound.admit(&header(MsgType::Frontier, 0)).unwrap();
    assert!(inbound.timed_out(0).is_err());
}
