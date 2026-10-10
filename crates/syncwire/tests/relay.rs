#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use syncwire::limits::{
    RELAY_CHALLENGE_LEN, RELAY_CLAIM_LEN, RELAY_HEADER_LEN, RELAY_MAX_DIFFICULTY, RELAY_OPEN_LEN,
    RELAY_RESERVED_LEN,
};
use syncwire::{
    decode_incoming, decode_open, encode_incoming, encode_open, Challenge, Claim, Ping,
    RelayHeader, RelayHint, RelaySide, RelayType, Reserved,
};

const ALL: [RelayType; 11] = [
    RelayType::Reserve,
    RelayType::Connect,
    RelayType::Accept,
    RelayType::Ping,
    RelayType::Challenge,
    RelayType::Reserved,
    RelayType::Incoming,
    RelayType::Splice,
    RelayType::Pong,
    RelayType::Busy,
    RelayType::Refused,
];

#[test]
fn the_opening_is_the_magic_and_a_version() {
    assert_eq!(encode_open(), *b"ZPRY\x00\x01");
    assert_eq!(encode_open().len(), RELAY_OPEN_LEN);
    decode_open(&encode_open()).unwrap();
    for at in 0..RELAY_OPEN_LEN {
        let mut bad = encode_open();
        bad[at] ^= 1;
        assert!(decode_open(&bad).is_err(), "byte {at}");
    }
}

#[test]
fn header_golden_layout() {
    let header = RelayHeader::new(RelayType::Reserve, RELAY_CLAIM_LEN, RelaySide::Client).unwrap();
    assert_eq!(header.encode(), [0x01, 0x00, 0x18], "type, length BE");
    assert_eq!(
        RelayHeader::decode(&header.encode(), RelaySide::Client).unwrap(),
        header
    );
    let splice = RelayHeader::new(RelayType::Splice, 0, RelaySide::Relay).unwrap();
    assert_eq!(splice.encode(), [0x13, 0, 0]);
}

#[test]
fn type_codes_are_the_design_table_and_nothing_else_parses() {
    let table = [
        (0x01, RelayType::Reserve),
        (0x02, RelayType::Connect),
        (0x03, RelayType::Accept),
        (0x04, RelayType::Ping),
        (0x10, RelayType::Challenge),
        (0x11, RelayType::Reserved),
        (0x12, RelayType::Incoming),
        (0x13, RelayType::Splice),
        (0x14, RelayType::Pong),
        (0x1E, RelayType::Busy),
        (0x1F, RelayType::Refused),
    ];
    for byte in 0..=u8::MAX {
        let known = table
            .iter()
            .find(|(code, _)| *code == byte)
            .map(|(_, ty)| *ty);
        assert_eq!(RelayType::try_from(byte).ok(), known, "byte {byte:#x}");
    }
}

#[test]
fn a_type_from_the_wrong_side_and_every_length_over_its_limit_are_refused_at_the_header() {
    for ty in ALL {
        for side in [RelaySide::Client, RelaySide::Relay] {
            let mut bytes = [0u8; RELAY_HEADER_LEN];
            bytes[0] = ty as u8;
            match ty.max_payload(side) {
                None => {
                    assert!(RelayHeader::decode(&bytes, side).is_err(), "{ty:?}");
                    assert!(RelayHeader::new(ty, 0, side).is_err());
                }
                Some(max) => {
                    bytes[1..].copy_from_slice(&u16::try_from(max).unwrap().to_be_bytes());
                    assert!(RelayHeader::decode(&bytes, side).is_ok());
                    bytes[1..].copy_from_slice(&u16::try_from(max + 1).unwrap().to_be_bytes());
                    assert!(RelayHeader::decode(&bytes, side).is_err(), "{ty:?}");
                    bytes[1..].copy_from_slice(&u16::MAX.to_be_bytes());
                    assert!(RelayHeader::decode(&bytes, side).is_err(), "{ty:?}");
                    assert!(RelayHeader::new(ty, max + 1, side).is_err());
                }
            }
        }
    }
}

#[test]
fn the_limits_are_the_design_table() {
    let from = |ty: RelayType, side| ty.max_payload(side);
    assert_eq!(from(RelayType::Reserve, RelaySide::Client), Some(24));
    assert_eq!(from(RelayType::Connect, RelaySide::Client), Some(24));
    assert_eq!(from(RelayType::Accept, RelaySide::Client), Some(24));
    assert_eq!(from(RelayType::Ping, RelaySide::Client), Some(8));
    assert_eq!(from(RelayType::Challenge, RelaySide::Relay), Some(25));
    assert_eq!(from(RelayType::Reserved, RelaySide::Relay), Some(7));
    assert_eq!(from(RelayType::Incoming, RelaySide::Relay), Some(16));
    assert_eq!(from(RelayType::Splice, RelaySide::Relay), Some(0));
    assert_eq!(from(RelayType::Pong, RelaySide::Relay), Some(8));
    assert_eq!(from(RelayType::Busy, RelaySide::Relay), Some(0));
    assert_eq!(from(RelayType::Refused, RelaySide::Relay), Some(0));
    assert_eq!(RELAY_CHALLENGE_LEN, 25);
    assert_eq!(RELAY_RESERVED_LEN, 7);
}

#[test]
fn claim_golden_layout_and_strict_decode() {
    let claim = Claim {
        id: [0xAB; 16],
        nonce: 0x0102_0304_0506_0708,
    };
    let bytes = claim.encode();
    assert_eq!(&bytes[..16], &[0xAB; 16]);
    assert_eq!(&bytes[16..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Claim::try_from(&bytes[..]).unwrap(), claim);
    for len in 0..bytes.len() {
        assert!(Claim::try_from(&bytes[..len]).is_err());
    }
    assert!(Claim::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
}

#[test]
fn challenge_golden_layout_and_strict_decode() {
    let challenge = Challenge {
        salt: [0xCD; 16],
        window: 0x0A0B_0C0D_0E0F_1011,
        difficulty: 12,
    };
    let bytes = challenge.encode();
    assert_eq!(bytes[0], 12, "difficulty first");
    assert_eq!(&bytes[1..17], &[0xCD; 16]);
    assert_eq!(
        &bytes[17..],
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11]
    );
    assert_eq!(Challenge::try_from(&bytes[..]).unwrap(), challenge);
    for len in 0..bytes.len() {
        assert!(Challenge::try_from(&bytes[..len]).is_err());
    }
    assert!(Challenge::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
    let mut hard = bytes;
    hard[0] = RELAY_MAX_DIFFICULTY;
    assert!(Challenge::try_from(&hard[..]).is_ok());
    hard[0] = RELAY_MAX_DIFFICULTY + 1;
    assert!(
        Challenge::try_from(&hard[..]).is_err(),
        "no harder than the bound"
    );
}

#[test]
fn reserved_golden_layout_and_strict_decode() {
    let granted = Reserved {
        ttl_s: 600,
        max_splices: 4,
        splice_mib: 64,
    };
    let bytes = granted.encode();
    assert_eq!(bytes, [0, 0, 2, 0x58, 4, 0, 64]);
    assert_eq!(Reserved::try_from(&bytes[..]).unwrap(), granted);
    for len in 0..bytes.len() {
        assert!(Reserved::try_from(&bytes[..len]).is_err());
    }
    assert!(Reserved::try_from(&[&bytes[..], &[0]].concat()[..]).is_err());
    for zero in [
        [0, 0, 0, 0, 4, 0, 64],
        [0, 0, 2, 0x58, 0, 0, 64],
        [0, 0, 2, 0x58, 4, 0, 0],
    ] {
        assert!(Reserved::try_from(&zero[..]).is_err(), "{zero:?}");
    }
}

#[test]
fn incoming_and_ping_are_exact() {
    let id = [0x77; 16];
    assert_eq!(decode_incoming(&encode_incoming(&id)).unwrap(), id);
    assert!(decode_incoming(&[0; 15]).is_err());
    assert!(decode_incoming(&[0; 17]).is_err());
    assert_eq!(Ping::try_from(&Ping(9).encode()[..]).unwrap(), Ping(9));
    assert!(Ping::try_from(&[0u8; 9][..]).is_err());
}

#[test]
fn a_relay_hint_is_an_address_a_slash_and_32_lowercase_digits() {
    let hint = RelayHint {
        relay: "203.0.113.9:7447".parse().unwrap(),
        slot: [0xAB; 16],
    };
    let text = hint.to_string();
    assert_eq!(text, format!("203.0.113.9:7447/{}", "ab".repeat(16)));
    assert_eq!(text.parse::<RelayHint>().unwrap(), hint);
    let v6 = RelayHint {
        relay: "[2001:4860:4860::8888]:7447".parse().unwrap(),
        slot: [0x01; 16],
    };
    assert!(v6.to_string().len() <= session::MAX_HINT_LEN);
    assert_eq!(v6.to_string().parse::<RelayHint>().unwrap(), v6);
    let slot = "ab".repeat(16);
    for bad in [
        "203.0.113.9:7447".to_owned(),
        "203.0.113.9:7447/".to_owned(),
        format!("203.0.113.9:7447/{slot}0"),
        format!("203.0.113.9:7447/{}", &slot[..30]),
        format!("203.0.113.9:7447/{}", slot.to_uppercase()),
        format!("203.0.113.9:7447/{}g", &slot[..31]),
        format!("203.0.113.9/{slot}"),
        format!("example.com:7447/{slot}"),
        format!("/{slot}"),
        format!("203.0.113.9:7447/{slot}/{slot}"),
    ] {
        assert!(bad.parse::<RelayHint>().is_err(), "{bad}");
    }
}
