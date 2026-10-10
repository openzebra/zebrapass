#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::net::SocketAddr;

use syncwire::limits::{CHUNK_LEN, MAX_BUNDLE, MAX_LOG_LEN, MUX_HEADER_LEN};
use syncwire::{
    Chunk, ChunkRequest, Direction, Extent, Header, MsgType, Ping, Want, WhoAmI, ANNOUNCE_WIRE_LEN,
};

const ALL: [MsgType; 16] = [
    MsgType::Announce,
    MsgType::LogHead,
    MsgType::LogChunk,
    MsgType::Frontier,
    MsgType::Want,
    MsgType::Bundle,
    MsgType::SnapReq,
    MsgType::SnapChunk,
    MsgType::Rekey,
    MsgType::Peers,
    MsgType::WhoAmI,
    MsgType::Ping,
    MsgType::Pong,
    MsgType::Busy,
    MsgType::Refused,
    MsgType::Stale,
];

#[test]
fn header_golden_layout() {
    let header = Header::new(MsgType::Want, 0x0102_0304, 12, Direction::Request).unwrap();
    assert_eq!(
        header.encode(),
        [5, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 12],
        "type, request number BE, length BE"
    );
    assert_eq!(
        Header::decode(&header.encode(), Direction::Request).unwrap(),
        header
    );
}

#[test]
fn every_type_code_round_trips_and_nothing_else_parses() {
    for byte in 0..=u8::MAX {
        let known = ALL.iter().find(|ty| **ty as u8 == byte);
        assert_eq!(MsgType::try_from(byte).ok(), known.copied(), "byte {byte}");
    }
}

#[test]
fn unknown_types_are_refused_in_both_directions() {
    for direction in [Direction::Request, Direction::Response] {
        for byte in [0, 17, 255] {
            let mut bytes = [0; MUX_HEADER_LEN];
            bytes[0] = byte;
            assert!(Header::decode(&bytes, direction).is_err());
        }
    }
}

#[test]
fn a_type_in_the_wrong_direction_is_refused() {
    for ty in ALL {
        for (direction, other) in [
            (Direction::Request, Direction::Response),
            (Direction::Response, Direction::Request),
        ] {
            let mut bytes = [0; MUX_HEADER_LEN];
            bytes[0] = ty as u8;
            if ty.max_payload(direction).is_none() {
                assert!(Header::decode(&bytes, direction).is_err(), "{ty:?}");
                assert!(Header::new(ty, 1, 0, direction).is_err());
            }
            assert!(ty.max_payload(direction).is_some() || ty.max_payload(other).is_some());
        }
    }
}

#[test]
fn a_length_over_the_limit_is_refused_before_any_payload() {
    for ty in ALL {
        for direction in [Direction::Request, Direction::Response] {
            let Some(max) = ty.max_payload(direction) else {
                continue;
            };
            let mut bytes = [0; MUX_HEADER_LEN];
            bytes[0] = ty as u8;
            bytes[5..].copy_from_slice(&u32::try_from(max).unwrap().to_be_bytes());
            assert!(Header::decode(&bytes, direction).is_ok());
            bytes[5..].copy_from_slice(&(u32::try_from(max).unwrap() + 1).to_be_bytes());
            assert!(Header::decode(&bytes, direction).is_err());
            bytes[5..].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(Header::decode(&bytes, direction).is_err());
            assert!(Header::new(ty, 1, max + 1, direction).is_err());
        }
    }
}

#[test]
fn status_replies_and_empty_requests_carry_nothing() {
    for ty in [MsgType::Busy, MsgType::Refused, MsgType::Stale] {
        assert_eq!(ty.max_payload(Direction::Response), Some(0));
        assert_eq!(ty.max_payload(Direction::Request), None);
    }
    for ty in [
        MsgType::Announce,
        MsgType::LogHead,
        MsgType::Frontier,
        MsgType::Rekey,
        MsgType::WhoAmI,
    ] {
        assert_eq!(ty.max_payload(Direction::Request), Some(0));
    }
    assert_eq!(
        MsgType::Announce.max_payload(Direction::Response),
        Some(ANNOUNCE_WIRE_LEN)
    );
    assert_eq!(
        MsgType::Bundle.max_payload(Direction::Request),
        Some(MAX_BUNDLE)
    );
}

#[test]
fn want_golden_layout_and_strict_decode() {
    let want = Want {
        revision: 0x0a0b_0c0d_0e0f_1011,
        record_id: 0x0102_0304,
    };
    let bytes = want.encode();
    assert_eq!(
        bytes,
        [1, 2, 3, 4, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]
    );
    assert_eq!(Want::try_from(&bytes[..]).unwrap(), want);
    for len in 0..bytes.len() {
        assert!(Want::try_from(&bytes[..len]).is_err());
    }
    assert!(Want::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
}

#[test]
fn extent_request_and_ping_are_exact() {
    let extent = Extent {
        id: [7; 32],
        total: 99,
    };
    let bytes = extent.encode();
    assert_eq!(bytes.len(), Extent::LEN);
    assert_eq!(Extent::try_from(&bytes[..]).unwrap(), extent);
    assert!(Extent::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
    let mut huge = bytes;
    huge[32..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(Extent::try_from(&huge[..]).is_err());

    let request = ChunkRequest {
        id: [1; 32],
        offset: 65_536,
    };
    let bytes = request.encode();
    assert_eq!(ChunkRequest::try_from(&bytes[..]).unwrap(), request);
    assert!(ChunkRequest::try_from(&bytes[..bytes.len() - 1]).is_err());

    let ping = Ping(0x0102_0304_0506_0708);
    assert_eq!(ping.encode(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Ping::try_from(&ping.encode()[..]).unwrap(), ping);
    assert!(Ping::try_from(&[0u8; 9][..]).is_err());
}

fn chunk(data: &[u8], offset: u64, total: u64) -> Chunk {
    Chunk {
        data: data.into(),
        id: [3; 32],
        offset,
        total,
    }
}

#[test]
fn chunk_golden_layout_and_rejections() {
    let piece = chunk(&[9, 9, 9], 5, 8);
    let bytes = piece.encode().unwrap();
    assert_eq!(&bytes[..32], &[3; 32]);
    assert_eq!(&bytes[32..40], &8u64.to_be_bytes());
    assert_eq!(&bytes[40..48], &5u64.to_be_bytes());
    assert_eq!(&bytes[48..52], &3u32.to_be_bytes());
    assert_eq!(&bytes[52..], &[9, 9, 9]);
    assert_eq!(Chunk::decode_snapshot(&bytes).unwrap(), piece);
    for len in 0..bytes.len() {
        assert!(Chunk::decode_snapshot(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Chunk::decode_snapshot(&trailing).is_err());

    let mut over = bytes.clone();
    over[48..52].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Chunk::decode_snapshot(&over).is_err());
    let mut over = bytes;
    over[48..52].copy_from_slice(&u32::try_from(CHUNK_LEN + 1).unwrap().to_be_bytes());
    assert!(Chunk::decode_snapshot(&over).is_err());

    assert!(chunk(&vec![0; CHUNK_LEN + 1], 0, 1 << 20).encode().is_err());
    assert!(Chunk::decode_snapshot(&chunk(&[1], 8, 8).encode().unwrap()).is_err());
    assert!(Chunk::decode_snapshot(&chunk(&[1], u64::MAX, u64::MAX).encode().unwrap()).is_err());
    assert!(Chunk::decode_snapshot(&chunk(&[], 3, 8).encode().unwrap()).is_err());
    assert!(Chunk::decode_snapshot(&chunk(&[], 8, 8).encode().unwrap()).is_ok());
    let big = chunk(&[1], 0, MAX_LOG_LEN + 1).encode().unwrap();
    assert!(Chunk::decode_log(&big).is_err());
    assert!(Chunk::decode_snapshot(&big).is_ok());
}

#[test]
fn whoami_round_trips_both_families_and_rejects_the_rest() {
    for text in ["203.0.113.9:4040", "[2001:db8::1]:65535"] {
        let addr: SocketAddr = text.parse().unwrap();
        let bytes = WhoAmI(addr).encode();
        assert_eq!(WhoAmI::try_from(&bytes[..]).unwrap(), WhoAmI(addr));
        for len in 0..bytes.len() {
            assert!(WhoAmI::try_from(&bytes[..len]).is_err());
        }
        assert!(WhoAmI::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
    }
    let mut bad = WhoAmI("1.2.3.4:5".parse().unwrap()).encode();
    bad[0] = 5;
    assert!(WhoAmI::try_from(&bad[..]).is_err());
}
